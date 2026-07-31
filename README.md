<div align="center">

# ☕ Bambu NFC

**Read &amp; rewrite Bambu Lab spool tags with a PN532**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)

[![English](https://img.shields.io/badge/lang-English-2ea44f?style=for-the-badge)](README.md)
[![Русский](https://img.shields.io/badge/lang-Русский-lightgrey?style=for-the-badge)](README.ru.md)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/disaldr)

</div>

---

A tool for the RFID tags on **Bambu Lab** filament spools (MIFARE Classic 1K)
using a **PN532** reader on macOS. It diagnoses the tag state, shows filament
data, dumps the tag, and rewrites it with your data — a **URL, plain text,
Wi-Fi credentials, or raw bytes** (as a standard NDEF tag).

The tag's encryption keys (KeyA and KeyB) are **derived from the UID** — no cracking required:

- `KeyA[sector] = HKDF-SHA256(UID, salt=master, info="RFID-A\0")`
- `KeyB[sector] = HKDF-SHA256(UID, salt=master, info="RFID-B\0")`

> On newer tags (e.g. PLA Lite) KeyB is **not zero**, contrary to old docs —
> it is also derived from the UID, just with the `RFID-B` context.

---

## Requirements

### Hardware
- A **PN532** module in **UART** mode, connected via a USB-UART adapter
  (usually a **CH340** chip, shows up as `/dev/cu.usbserial-*`).
- A Mac (Apple Silicon; the instructions assume Homebrew at `/opt/homebrew`).

### Software
- [Homebrew](https://brew.sh)
- `libnfc` (reader), a C compiler (Xcode Command Line Tools), Python 3.8+

---

## Installation

### 1. Dependencies

```bash
# Command Line Tools (the cc compiler), if not installed yet
xcode-select --install

# libnfc
brew install libnfc
```

The Python script uses only the standard library — no extra packages needed.

### 2. Find the reader's port

Plug in the PN532 and find its port:

```bash
ls /dev/cu.usbserial-*
```

For example `/dev/cu.usbserial-110`. Remember this value for the next step.

### 3. Configure libnfc for PN532 UART

Homebrew's libnfc looks for its config **inside Cellar**, not in `/opt/homebrew/etc`.
Create the device description (substitute your own port and libnfc version):

```bash
NFC_DIR="/opt/homebrew/Cellar/libnfc/1.8.0/etc/nfc"
mkdir -p "$NFC_DIR/devices.d"

# allow intrusive scan
printf 'allow_intrusive_scan = true\n' > "$NFC_DIR/libnfc.conf"

# PN532 UART description (replace the port with yours)
printf 'name = "PN532 UART"\nconnstring = "pn532_uart:/dev/cu.usbserial-110"\n' \
  > "$NFC_DIR/devices.d/pn532_uart.conf"
```

Check the reader (no tag needed):

```bash
nfc-list
```

You should see `NFC device: PN532 UART opened`. If it says `No NFC device found`,
check the port and that the config sits under `Cellar/.../etc/nfc`.

### 4. Build the C helper

Low-level tag operations are done by `nfc_helper` (libnfc directly — `nfc-mfclassic`
does partial writes on a tag that drifts in the field).
The script **builds it automatically** on first run, but you can do it manually:

```bash
cc nfc_helper.c -I/opt/homebrew/include -L/opt/homebrew/lib -lnfc -o nfc_helper
```

---

## Usage

```bash
python3 bambu_nfc.py
```

### Interface language

Russian / English. Language selection (default: from your system locale, otherwise English):

```bash
python3 bambu_nfc.py --lang en      # argument
BAMBU_LANG=en python3 bambu_nfc.py  # environment variable
```

The script, step by step:

1. Asks you to place the tag, reads the **UID**.
2. **State diagnosis** — determines whether the tag is secured:

   | State | Secured |
   |---|---|
   | Original Bambu (data read-only, access `87878769`) | **YES** |
   | Bambu, already unlocked | NO |
   | Rewritten as NDEF (public keys) | NO |
   | Blank / factory (keys `FFFFFFFFFFFF`) | NO |
   | Unknown | ? |

3. Shows an **actions menu** adapted to the current state:
   - Write data — URL, text, Wi-Fi (SSID + password) or raw bytes; unlocks automatically if needed
   - Clone another Bambu spool — copy filament data from a saved `.mfd` dump
   - Craft a Bambu spool — build filament data from a preset or parameters
   - Show tag content (auto-detects URL / text / Wi-Fi / raw)
   - Show Bambu filament data (type, color, weight, diameter)
   - Save a dump to a file
   - Wipe to factory state

### Supported data types

| Type | What is written |
|---|---|
| URL | NDEF URI record (`https://…`, `tel:`, `mailto:`, …) |
| Text | NDEF Text record (UTF-8) |
| Wi-Fi | NDEF Wi-Fi Simple Config (SSID + password, WPA2/AES) — tap-to-join on supported phones |
| Raw bytes | Arbitrary hex written into the data blocks (no NDEF wrapper) |

Long values automatically span several sectors.

### Cloning or crafting a spool

- *Clone another Bambu spool* writes the filament data from a saved `.mfd` dump
  (made with *Save dump to file*) onto the current tag, re-keyed to this tag's UID
  and re-locked to factory access.
- *Craft a Bambu spool* builds the filament data from parameters — pick a preset
  (including presets auto-read from your own dumps) or enter the Material ID, type,
  color, weight and temperatures manually.

⚠️ A Bambu tag carries an **RSA-2048 signature** made with Bambu's private key,
which cannot be forged. A cloned dump keeps a signature for the *source* UID, and a
crafted spool has none — so a printer that verifies the signature may reject them.
This works on firmware that does **not** verify the signature (historically the
case), and restoring a dump onto **its own** tag works fully. The filament data
itself is always written correctly.

### Debug

Per-block detail while writing:

```bash
BAMBU_DBG=1 python3 bambu_nfc.py
```

---

## Example run

Writing a link to a **secured original** Bambu tag (protection is removed automatically):

```text
$ python3 bambu_nfc.py --lang en
Bambu NFC — spool tag tool
PN532 + libnfc. State diagnosis and available actions.

━━━ Tag detection ━━━
» Place the tag on the reader and press Enter...
  ✓ UID: 02158BEF
  Diagnosing sectors...
  Reading contents...

━━━ Tag state ━━━
  Tag type   : Original Bambu — SECURED (data read-only)
  Secured    : YES
  Access bits: 87878769
  data blocks are write-protected; writing will unlock them automatically.

━━━ Available actions ━━━
  1) Write data (URL / text / Wi-Fi / raw)
  2) Clone another Bambu spool (from a dump)
  3) Craft a Bambu spool (from parameters)
  4) Show Bambu filament data
  5) Save dump to file
  6) Wipe to factory state
  0) Exit
? Choose action [1]: 1

━━━ Data type ━━━
  1) URL / link
  2) Plain text
  3) Wi-Fi network (SSID + password)
  4) Raw bytes (hex)
? Choose action [1]: 1
? Enter URL [https://bambulab.com]:
  ✓ Image built: URL: https://bambulab.com (data sectors: 1)
? Write? This is irreversible (y/n) [y]: y
  Tag secured — unlocking...
  unlock sector  0 OK
    … (sectors 1–15)
  Writing image (hold the tag still)...
  write sector  0 (3 blocks)
  write sector  1 (4 blocks)
    … (sectors 2–15)
  ✓ Written and verified at block level
  Verification read...
  read sector  0 (4/4)
    … (sectors 1–15)

✓ Done! Tag now holds: URL: https://bambulab.com
```

For an **already rewritten** tag the diagnosis shows `Tag type: Rewritten as NDEF tag`,
`Secured: NO`, and a **"Show tag content"** item appears in the menu.

---

## Files

| File | Purpose |
|---|---|
| `bambu_nfc.py` | Main interactive script (menu + progress, RU/EN) |
| `nfc_helper.c` | libnfc C helper: `uid` / `diag` / `unlock` / `write` / `read` |
| `bambu_keys.py` | Derives KeyA/KeyB from UID; generates a keyfile |
| `build_target.py` | Builds an NDEF image (standalone, apart from `bambu_nfc.py`) |

The other `*.c` files (`keytest`, `mapB`, `phase1_unlock`, `robust_write`, …) are
research utilities used while reverse-engineering the format; not needed for normal use.

### Standalone key generation

```bash
python3 bambu_keys.py <UID_hex> [keyfile.mfd]
# example:
python3 bambu_keys.py 02158BEF fullkeys.mfd
```

---

## Good to know

- **Rewriting is irreversible for Bambu's purpose**: after writing a URL the
  printer will no longer recognize the spool. The tag itself stays recoverable
  (public/factory keys are known) — you can wipe or rewrite it again.
- **iPhone cannot read MIFARE Classic** (Core NFC does not support this chip),
  so a URL written to such a tag will not open on an iPhone. It is read by some
  Android phones (with an NXP controller) and, of course, by the PN532 itself.
  For a universal link tag readable by any phone, use an **NTAG213/215** chip,
  not a Bambu tag.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No NFC device found` | Check the port (`ls /dev/cu.usbserial-*`) and the config path under `Cellar/.../etc/nfc` |
| UID jumps / reads wrong | The tag drifts — press it to the center of the antenna and hold still |
| `write-fail` on a sector | A real access denial — press the tag closer and retry |
| Script won't build `nfc_helper` | Build manually (see step 4), check `xcode-select --install` |

---

## Support

If this saved you some time, you can buy me a coffee ☕

<div align="center">

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-buymeacoffee.com%2Fdisaldr-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/disaldr)

</div>

---

## License

Released under the [MIT License](LICENSE).

---

## Disclaimer

This tool is for research and interoperability purposes (using third-party spools,
recovering tags). Use it on your own tags and at your own risk.
