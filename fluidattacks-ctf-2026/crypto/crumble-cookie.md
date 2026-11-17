# 🍪 Crumble Cookie

> **Length Extension Attack** sobre firmas `SHA256(SECRET + mensaje)`

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Cryptography | 🟢 Easy | 280 | diriartev |

**Flag:** `flag{f14306cb90f3d844}`

---

## 1. Descripción del reto

SecureVault es una API de archivos que entrega enlaces de descarga "firmados" para que nadie pueda descargar archivos que no debería. El equipo de desarrollo confía mucho en su firma... pero la firma no es un HMAC de verdad, sino un simple `SHA256(SECRET_KEY + mensaje)`. Esto la hace vulnerable a un ataque clásico llamado **Hash Length Extension Attack**.

| | |
|---|---|
| **Instancia** | `0105936d9a03ae6a.chal.ctf.ae` (HTTPS) |
| **Objetivo** | Descargar `private/flag.txt` sin conocer `SECRET_KEY` |

## 2. Análisis del código fuente (`app.py`)

El servidor entrega el código fuente. Los puntos clave son:

- `SECRET_KEY` es un string de **16 caracteres** que nunca se revela (variable de entorno).
- La función `sign()` calcula `hashlib.sha256(SECRET_KEY + mensaje).hexdigest()`.
- El endpoint `/files` entrega un token y su firma válida para archivos públicos:

  ```python
  token = "action=download&file=public/welcome.txt"
  sig   = SHA256(SECRET_KEY + token)
  ```

- El endpoint `/download` verifica la firma y, si es correcta, parsea el token buscando pares `clave=valor` separados por `&`. **Si `file=` aparece varias veces, se queda con la última.**
- Si `file` resuelve a `private/flag.txt`, el servidor devuelve la flag.

## 3. La vulnerabilidad: `SHA256(secreto + mensaje)` no es HMAC

SHA256 (como toda la familia Merkle–Damgård: MD5, SHA1, SHA256, SHA512) procesa el mensaje en bloques y al terminar expone su **estado interno completo** como resultado (el hash). Por lo tanto, si conocemos:

- El hash `H = SHA256(SECRET + mensaje_conocido)`
- La longitud de `mensaje_conocido`
- La longitud de `SECRET_KEY` (el reto indica que son 16 caracteres)

...podemos **continuar** el hash exactamente donde el servidor lo dejó, sin conocer el secreto, y calcular `SHA256(SECRET + mensaje_conocido + padding + EXTRA)` para cualquier `EXTRA`.

> Con HMAC-SHA256 este ataque **no** funcionaría (por eso las notas del reto mencionan "migrar a HMAC").

## 4. Explotación paso a paso

### Paso 1 — Obtener un token y una firma válidos

```bash
curl https://0105936d9a03ae6a.chal.ctf.ae/files
```

Entre otros, devuelve:

```text
token = "action=download&file=public/welcome.txt"
sig   = "eb98dbd9635899e1e02a493d7a1e067b540dc3653c8959099fb62f8e44a439fd"
```

### Paso 2 — Calcular el *glue padding* de SHA256

SHA256 rellena el mensaje original con un byte `0x80`, ceros y 8 bytes con la longitud en bits, hasta completar un múltiplo de 64 bytes. Como `len(SECRET_KEY) = 16` y conocemos la longitud del token, podemos calcular **exactamente** ese padding sin conocer el secreto (solo depende de la longitud total).

### Paso 3 — Reanudar el hash e inyectar el archivo objetivo

Se toma el digest existente (`eb98db...`), se convierte en el estado interno de SHA256 (8 palabras de 32 bits) y se siguen comprimiendo bloques con el dato extra `&file=private/flag.txt`. Esto produce una firma **válida** para `token + padding + &file=private/flag.txt`.

```python
import struct, hashlib, urllib.parse, requests

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def sha256_compress(block, h):
    # implementación manual del compresor SHA256 (ver script completo)
    ...

def sha256_padding(total_len_bytes):
    ml = total_len_bytes * 8
    pad = b'\x80'
    pad += b'\x00' * ((56 - (total_len_bytes + 1) % 64) % 64)
    pad += struct.pack('>Q', ml)
    return pad

def length_extend(orig_digest_hex, secret_len, known_msg, append):
    h = list(struct.unpack('>8L', bytes.fromhex(orig_digest_hex)))
    orig_total_len = secret_len + len(known_msg)
    glue = sha256_padding(orig_total_len)
    new_msg = known_msg + glue + append
    data = append + sha256_padding(orig_total_len + len(glue) + len(append))
    for i in range(0, len(data), 64):
        h = sha256_compress(data[i:i+64], h)
    forged_digest = b''.join(struct.pack('>L', x) for x in h).hex()
    return new_msg, forged_digest
```

### Paso 4 — Armar la URL y pedir el archivo

El token forjado contiene bytes no imprimibles (el padding). El servidor hace `token.encode('latin-1')`, así que se envía el token decodificado como `latin-1` y luego se url-encodea (`quote` usa UTF-8 por defecto, que es lo que Flask/Werkzeug espera para des-escaparlo).

```python
append = b"&file=private/flag.txt"
new_token_bytes, forged_sig = length_extend(orig_sig, 16, known_msg, append)

token_str = new_token_bytes.decode('latin-1')
url_token = urllib.parse.quote(token_str, safe='', encoding='utf-8')

url = f"{BASE}/download?token={url_token}&sig={forged_sig}"
resp = requests.get(url)
print(resp.json())
```

## 5. Resultado

El servidor, convencido de que la firma es legítima, entrega el archivo privado:

```json
{"content": "flag{f14306cb90f3d844}", "filename": "private/flag.txt"}
```

🚩 **FLAG:** `flag{f14306cb90f3d844}`

## 6. Lección / mitigación

- **Nunca** usar `SHA256(secreto + mensaje)` como firma. Usar `HMAC-SHA256(clave, mensaje)`, diseñado específicamente para resistir length extension attacks.
- Alternativamente, usar SHA-3 (Keccak), que no sufre este problema gracias a su construcción de esponja.
