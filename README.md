<h1 align="center">🚩 CTF Writeups</h1>

<p align="center">
  Writeups de retos CTF resueltos por <a href="https://github.com/diriartev">diriartev</a> · Explicaciones paso a paso, PoCs y remediación
</p>

---

## 📂 Fluid Attacks CTF 2026

> Plataforma: `ctf.ae` · Fecha: 2026-07-04 · Idioma: Español
>
> **9 retos** · **2 515 pts** · Web · Crypto · Pwn · Mobile

| Reto | Categoría | Dificultad | Pts | Técnica |
|---|---|---|---|---|
| [🧱 The Alignment Trap](fluidattacks-ctf-2026/pwn/the-alignment-trap.md) | Pwn | 🔴 Hard | 480 | Truncación 32-bit → heap overflow → tcache poisoning → House of Apple 2 |
| [⏳ Nonce Upon a Time](fluidattacks-ctf-2026/crypto/nonce-upon-a-time.md) | Crypto | 🔴 Hard | 430 | ECDSA con nonce sesgado → Hidden Number Problem (LLL) |
| [🗡️ The Password is Swordfish](fluidattacks-ctf-2026/pwn/the-password-is-swordfish.md) | Pwn | 🟢 Easy | 360 | Signed/unsigned mismatch → stack overflow → ret2win |
| [📱 Whispers in the Wire](fluidattacks-ctf-2026/mobile/whispers-in-the-wire.md) | Mobile | 🟢 Easy | 310 | Endpoint admin oculto + API key hardcodeada (BAC) |
| [👻 Phantom Decrypt](fluidattacks-ctf-2026/crypto/phantom-decrypt.md) | Crypto | 🟡 Medium | 295 | AES-GCM con `except` *fail-open* → sesión forjada |
| [🍪 Crumble Cookie](fluidattacks-ctf-2026/crypto/crumble-cookie.md) | Crypto | 🟢 Easy | 280 | SHA256 Length Extension Attack |
| [🍳 Mise en Place](fluidattacks-ctf-2026/web/mise-en-place.md) | Web | 🟢 Easy | 190 | Information Disclosure + IDOR |
| [📄 YAML Ain't Safe](fluidattacks-ctf-2026/web/yaml-aint-safe.md) | Web | 🟢 Easy | 170 | PyYAML `yaml.Loader` → RCE (CWE-502) |
| [🛒 ShopEZ](fluidattacks-ctf-2026/web/shopez.md) | Web | 🟢 Easy | — | Business logic: apilar cupones por mayúsculas |

## 🗂️ Estructura

```text
.
└── fluidattacks-ctf-2026/
    ├── crypto/   # Crumble Cookie, Phantom Decrypt, Nonce Upon a Time
    ├── mobile/   # Whispers in the Wire
    ├── pwn/      # The Password is Swordfish, The Alignment Trap
    └── web/      # Mise en Place, YAML Ain't Safe, ShopEZ
```

Cada writeup sigue la misma estructura: **descripción → análisis → explotación paso a paso → PoC → remediación → conclusión**.

## ⚠️ Disclaimer

Contenido con fines educativos. Todas las técnicas se aplicaron sobre infraestructura de CTF diseñada para ello; las instancias ya no están activas.
