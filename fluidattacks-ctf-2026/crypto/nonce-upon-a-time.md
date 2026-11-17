# ⏳ Nonce Upon a Time

> Recuperando una clave privada ECDSA con un ataque de retículos (**lattice / HNP**)

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Cryptography | 🔴 Hard | 430 | diriartev |

**Flag:** `flag{5213bc34de8ab794}`

---

## 1. Descripción del reto

LicenseForge firma tokens de licencia con **ECDSA sobre la curva NIST P-256**. Hay un endpoint `/api/sign` que firma cualquier mensaje JSON, **excepto** si el campo `"type"` vale `"admin"` (eso lo bloquea explícitamente). Y hay un endpoint `/api/activate` que, si recibe un token con una firma `(r, s)` válida, activa la licencia; si el tipo es `admin`, entrega la flag.

El código fuente "se filtró por accidente". Ahí hay una pista enorme: una función **RFC 6979** (generación determinista y segura de nonces) está comentada, con un `TODO` que dice *"usamos nonces aleatorios, debería ser suficiente"*. Esa es la vulnerabilidad.

| | |
|---|---|
| **Instancia** | `fcd14937c1b4e078.chal.ctf.ae` (HTTPS) |
| **Objetivo** | Firmar un token `{"type": "admin"}` sin que el servidor lo firme por nosotros |

## 2. La vulnerabilidad: nonce ECDSA sesgado (*bit bias*)

En ECDSA, cada firma usa un número aleatorio secreto `k` (el nonce). Si dos firmas reutilizan el mismo `k`, la clave privada se recupera fácilmente. Aquí `k` **no** se reutiliza, pero se genera así:

```python
k = random.getrandbits(256) >> 8
while k == 0 or k >= ORDER:
    k = random.getrandbits(256) >> 8
```

El `>> 8` descarta los 8 bits más altos de un número de 256 bits: `k` **siempre** es menor que `2^248`, mientras que el orden de la curva `n` es de 256 bits. Es decir, sabemos que los 8 bits más altos de `k` son cero en **todas** las firmas.

Es exactamente la vulnerabilidad real conocida como **Minerva (2019)**, que afectó a varias librerías ECDSA. Con muchas firmas que comparten este sesgo se puede plantear el **Hidden Number Problem (HNP)** y resolverlo con reducción de retículos (LLL/BKZ) para recuperar la clave privada completa.

## 3. Fundamento matemático (resumen)

De la ecuación de firma ECDSA, `s = k⁻¹ · (z + r·d) mod n`, se despeja `k`:

```text
k = a·d + b  (mod n)      donde  a = r · s⁻¹ mod n,   b = z · s⁻¹ mod n
```

`z` es el hash del mensaje, `(r, s)` la firma y `d` la clave privada. Como cada `k` es menor que `2^248` (pequeño comparado con `n`), se construye un retículo donde el vector que contiene todos los `k` verdaderos y la clave `d` es, por construcción, uno de los vectores **más cortos**. LLL encuentra ese vector corto y de ahí se despeja `d`.

> No hace falta dominar el álgebra para replicar el ataque: basta con reunir ~40–50 firmas y correr el script de la sección 5.

## 4. Recolección de firmas

`/api/sign` tiene un límite de 10 peticiones por segundo, así que se piden firmas de mensajes no-admin en un bucle espaciado:

```python
import requests, json, time

BASE = "https://fcd14937c1b4e078.chal.ctf.ae"
samples = []
i = 0
while len(samples) < 100:
    msg = json.dumps({"user": "attacker", "type": "standard", "seq": i})
    r = requests.post(BASE + "/api/sign", json={"message": msg})
    if r.status_code == 200:
        d = r.json()
        samples.append({
            "hash": d["hash"],
            "r": d["signature"]["r"],
            "s": d["signature"]["s"],
        })
    i += 1
    time.sleep(0.11)
```

Con 40–100 firmas es suficiente (el mínimo teórico ronda ~32–40 para un sesgo de 8 bits sobre una curva de 256 bits).

## 5. Ataque de retículo (HNP) con `fpylll`

Se usa [`fpylll`](https://github.com/fplll/fpylll) (bindings de Python para fplll). Instalación: `pip install fpylll` (requiere también `cysignals`).

```python
from fpylll import IntegerMatrix, LLL, CVP
from collections import Counter

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551  # orden P-256
delta = 1 << 248  # cota superior de k (sesgo de 8 bits)

def try_attack(samples, M):
    a, b = [], []
    for smp in samples[:M]:
        r = int(smp["r"], 16); s = int(smp["s"], 16); z = int(smp["hash"], 16)
        sinv = pow(s, -1, n)
        a.append((r * sinv) % n)
        b.append((z * sinv) % n)

    dim = M + 1
    B = IntegerMatrix(dim, dim)
    for i in range(M):
        B[i, i] = n * n
    for j in range(M):
        B[M, j] = n * a[j]
    B[M, M] = delta

    target = [-n * b[j] for j in range(M)] + [0]  # OJO: signo negativo en el target

    LLL.reduction(B)
    v = CVP.closest_vector(B, target)

    ks = [(v[j] - target[j]) // n for j in range(M)]
    votes = Counter()
    for i in range(M):
        d_i = ((ks[i] - b[i]) * pow(a[i], -1, n)) % n
        votes[d_i] += 1
    for cand, _ in votes.most_common(5):
        yield cand
```

> ⚠️ **Detalle que se presta a errores:** el vector `target` debe llevar **signo negativo** en `-n*b[j]`, y al reconstruir cada `k` hay que restar el target antes de dividir por `n`: `k_i = (v[i] - target[i]) // n`. Con cualquiera de estos dos errores de signo el ataque "parece" correcto pero nunca converge, sin importar cuántas firmas o cuánta reducción BKZ se use.

Para cada candidato se verifica si `d·G` coincide con la clave pública publicada en `/api/info`, lo que identifica el correcto sin ambigüedad.

## 6. Resultado del ataque

Con 40 firmas reales de la instancia, el ataque recupera la clave privada del servidor en menos de un segundo:

```text
PRIVATE KEY: 0x785eada5050d5a0335712bd0c3cbeae7285e707f06a8c6e04f7069a35b4e5211
```

## 7. Forjar la licencia admin y activarla

Con la clave privada `d` del servidor se puede firmar cualquier mensaje, incluido uno con `type=admin`:

```python
import hashlib, random, json, requests

token = json.dumps({"user": "diriartev", "type": "admin"})
z = int.from_bytes(hashlib.sha256(token.encode()).digest(), "big")

k = random.randrange(1, n)
R = k * G               # multiplicación de punto en la curva
r = R.x() % n
s = (pow(k, -1, n) * (z + r * d)) % n

requests.post(BASE + "/api/activate", json={
    "token": token, "r": hex(r), "s": hex(s)
})
```

El servidor verifica la firma con **su propia** clave pública (que coincide, porque usamos su clave privada real) y la acepta:

```json
{"flag": "flag{5213bc34de8ab794}", "license": "admin",
 "message": "Administrative license activated successfully", "status": "activated"}
```

🚩 **FLAG:** `flag{5213bc34de8ab794}`

## 8. Lección / mitigación

- El nonce `k` de ECDSA debe generarse **siempre** con una fuente criptográficamente segura (`secrets.randbelow`, `os.urandom`) o, mejor aún, de forma **determinista** con RFC 6979, que elimina el riesgo de nonces débiles.
- `random.getrandbits()` usa Mersenne Twister, que **no** es criptográfico; además aquí se recortaba con `>> 8`, introduciendo un sesgo explotable.
- Un sesgo de tan solo unos pocos bits en el nonce (Minerva, 2019 — afectó smartcards y librerías TPM) basta para recuperar la clave privada completa con suficientes firmas y un ataque de retículos.
