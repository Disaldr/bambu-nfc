#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive tool for Bambu Lab spool tags (MIFARE Classic 1K) over a PN532.

Diagnoses the tag state (secured / unlocked / NDEF / blank / unknown) and offers
the available actions: write data (URL / text / Wi-Fi / raw bytes), show the
current content, show Bambu filament data, dump to a file, wipe to factory state.

Language:  --lang en | --lang ru   (or BAMBU_LANG / system locale; default: en)
Run:       python3 bambu_nfc.py
Needs:     nfc_helper.c (built automatically) and bambu_keys.py next to it.
"""
import os
import struct
import subprocess
import sys
import time

from bambu_keys import derive_keys, CONTEXT_A, CONTEXT_B, ACCESS_BITS

# ============================ i18n ============================
STRINGS = {
    "en": {
        "app_title": "Bambu NFC — spool tag tool",
        "app_sub": "PN532 + libnfc. State diagnosis and available actions.",
        "building_helper": "Building nfc_helper...",
        "helper_build_fail": "Failed to build nfc_helper:",
        "helper_built": "nfc_helper built",
        "wait_tag": "Place the tag on the reader and press Enter...",
        "hdr_detect": "Tag detection",
        "tag_not_found": "No tag found. Check the reader and tag position.",
        "uid_is": "UID: {uid}",
        "diag_sectors": "Diagnosing sectors...",
        "reading_content": "Reading contents...",
        "hdr_state": "Tag state",
        "lbl_kind": "Tag type   : ",
        "lbl_secured": "Secured    : ",
        "lbl_access": "Access bits: ",
        "yes": "YES", "no": "NO", "unknown": "?",
        "secured_hint": "data blocks are write-protected; writing will unlock them automatically.",
        "hdr_actions": "Available actions",
        "menu_exit": "Exit",
        "choose_action": "Choose action",
        "no_such_item": "No such item.",
        "kind_locked": "Original Bambu — SECURED (data read-only)",
        "kind_unlocked": "Bambu, already UNLOCKED (transport access)",
        "kind_ndef": "Rewritten as NDEF tag (public keys)",
        "kind_blank": "Blank / factory tag (default keys)",
        "kind_unknown": "Unknown — no keys matched",
        "kind_mixed": "Mixed state",
        "unlocking": "Tag secured — unlocking...",
        "writing": "Writing image (hold the tag still)...",
        "write_partial_fail": "Some blocks failed to write. Reposition the tag and retry.",
        "write_ok": "Written and verified at block level",
        "verify_read": "Verification read...",
        "hdr_datatype": "Data type",
        "type_url": "URL / link",
        "type_text": "Plain text",
        "type_wifi": "Wi-Fi network (SSID + password)",
        "type_raw": "Raw bytes (hex)",
        "enter_url": "Enter URL",
        "enter_text": "Enter text",
        "enter_ssid": "Wi-Fi SSID",
        "enter_wifi_pass": "Wi-Fi password",
        "enter_raw": "Enter hex bytes (e.g. DEADBEEF)",
        "bad_hex": "Invalid hex.",
        "empty_input": "Empty input.",
        "image_built": "Image built: {desc} (data sectors: {n})",
        "write_confirm": "Write? This is irreversible",
        "cancelled": "Cancelled.",
        "done_write": "Done! Tag now holds: {desc}",
        "read_back_fail": "Written, but read-back didn't confirm — retry holding the tag steady.",
        "hdr_content": "Tag content",
        "no_content": "No readable content on the tag.",
        "sum_uri": "URL: {v}",
        "sum_text": 'Text: "{v}"',
        "sum_wifi": "Wi-Fi: {ssid}  (password: {key})",
        "sum_raw": "Raw {n} bytes: {v}",
        "no_bambu": "No Bambu filament data found (tag rewritten or empty).",
        "bambu_header": "Bambu filament data:",
        "f_type": "Type          : {type}  /  {detailed}",
        "f_tray": "Tray Info     : {tray} / {mat}",
        "f_color": "Color (RGBA)  : #{color}",
        "f_weight": "Weight        : {weight} g",
        "f_diam": "Diameter      : {diam:.2f} mm",
        "dump_name": "Dump file name",
        "dump_saved": "1024-byte dump saved: {path}",
        "format_warn": "The tag will be wiped to zero (factory keys FFFFFFFFFFFF).",
        "format_confirm": "Really wipe?",
        "format_done": "Tag wiped to factory state",
        "menu_write_data": "Write data (URL / text / Wi-Fi / raw)",
        "menu_write_spool": "Clone another Bambu spool (from a dump)",
        "menu_show_content": "Show tag content",
        "menu_show_bambu": "Show Bambu filament data",
        "menu_dump": "Save dump to file",
        "menu_format": "Wipe to factory state",
        "data_too_long": "Data too long for a 1K tag",
        "spool_hdr": "Source dump",
        "spool_pick": "Pick a dump (number) or enter a file path",
        "spool_pick_path": "Enter path to a .mfd dump",
        "spool_no_dumps": "No .mfd dumps found next to the script.",
        "spool_bad_file": "Cannot read a 1024-byte dump: {path}",
        "spool_not_bambu": "This dump has no Bambu filament data — write anyway?",
        "spool_source": "Source spool: {desc}",
        "spool_sig_warn": "The tag keeps its own UID, so the source RSA signature won't match — "
                          "printers that verify it may reject the spool. Restoring a dump onto its own tag works fully.",
        "spool_done": "Bambu spool written: {desc}",
        "menu_craft_spool": "Craft a Bambu spool (from parameters)",
        "craft_pick": "Choose material",
        "craft_custom": "Custom (enter IDs manually)",
        "craft_codes_note": "Preset material codes are typical values — verify against a real spool if unsure.",
        "craft_preview": "Spool to write: {desc}",
        "enter_variant": "Material Variant ID",
        "enter_material": "Material ID",
        "enter_ftype": "Filament type",
        "enter_detailed": "Detailed type",
        "enter_color": "Color RGBA hex",
        "enter_weight": "Weight, grams",
        "enter_diameter": "Diameter, mm",
        "enter_dry_temp": "Drying temperature, C",
        "enter_dry_time": "Drying time, hours",
        "enter_bed_temp": "Bed temperature, C",
        "enter_hot_min": "Hotend min temperature, C",
        "enter_hot_max": "Hotend max temperature, C",
        "bad_color": "Invalid color hex.",
    },
    "ru": {
        "app_title": "Bambu NFC — инструмент метки катушки",
        "app_sub": "PN532 + libnfc. Диагностика состояния и доступные действия.",
        "building_helper": "Собираю nfc_helper...",
        "helper_build_fail": "Не удалось собрать nfc_helper:",
        "helper_built": "nfc_helper собран",
        "wait_tag": "Приложите тег к ридеру и нажмите Enter...",
        "hdr_detect": "Определение метки",
        "tag_not_found": "Метка не обнаружена. Проверьте ридер и позицию тега.",
        "uid_is": "UID: {uid}",
        "diag_sectors": "Диагностика секторов...",
        "reading_content": "Чтение содержимого...",
        "hdr_state": "Состояние метки",
        "lbl_kind": "Тип метки  : ",
        "lbl_secured": "Засекречена: ",
        "lbl_access": "Access-биты: ",
        "yes": "ДА", "no": "НЕТ", "unknown": "?",
        "secured_hint": "data-блоки защищены от записи; для записи нужно снять защиту (сделаю автоматически).",
        "hdr_actions": "Доступные действия",
        "menu_exit": "Выход",
        "choose_action": "Выберите действие",
        "no_such_item": "Нет такого пункта.",
        "kind_locked": "Оригинальный Bambu — ЗАСЕКРЕЧЕНА (data read-only)",
        "kind_unlocked": "Bambu, уже РАЗЛОЧЕНА (транспортный доступ)",
        "kind_ndef": "Перезаписана в NDEF-метку (публичные ключи)",
        "kind_blank": "Чистая / заводская метка (ключи по умолчанию)",
        "kind_unknown": "Неизвестная — ключи не подошли",
        "kind_mixed": "Смешанное состояние",
        "unlocking": "Метка засекречена — снимаю защиту...",
        "writing": "Пишу образ (держите тег неподвижно)...",
        "write_partial_fail": "Часть блоков не записалась. Переположите тег и повторите.",
        "write_ok": "Записано и проверено на уровне блоков",
        "verify_read": "Контрольное чтение...",
        "hdr_datatype": "Тип данных",
        "type_url": "URL / ссылка",
        "type_text": "Текст",
        "type_wifi": "Сеть Wi-Fi (SSID + пароль)",
        "type_raw": "Произвольные байты (hex)",
        "enter_url": "Введите URL",
        "enter_text": "Введите текст",
        "enter_ssid": "Имя сети (SSID)",
        "enter_wifi_pass": "Пароль Wi-Fi",
        "enter_raw": "Введите байты hex (напр. DEADBEEF)",
        "bad_hex": "Некорректный hex.",
        "empty_input": "Пустой ввод.",
        "image_built": "Образ собран: {desc} (секторов под данные: {n})",
        "write_confirm": "Записать? Это необратимо",
        "cancelled": "Отменено.",
        "done_write": "Готово! На метке записано: {desc}",
        "read_back_fail": "Записано, но обратное чтение не подтвердило — повторите, держа тег ровно.",
        "hdr_content": "Содержимое метки",
        "no_content": "Читаемого содержимого на метке нет.",
        "sum_uri": "URL: {v}",
        "sum_text": "Текст: «{v}»",
        "sum_wifi": "Wi-Fi: {ssid}  (пароль: {key})",
        "sum_raw": "Байты ({n}): {v}",
        "no_bambu": "Данных филамента Bambu не найдено (метка перезаписана или пустая).",
        "bambu_header": "Данные филамента Bambu:",
        "f_type": "Тип           : {type}  /  {detailed}",
        "f_tray": "Tray Info     : {tray} / {mat}",
        "f_color": "Цвет (RGBA)   : #{color}",
        "f_weight": "Вес           : {weight} г",
        "f_diam": "Диаметр       : {diam:.2f} мм",
        "dump_name": "Имя файла дампа",
        "dump_saved": "Дамп 1024 Б сохранён: {path}",
        "format_warn": "Метка будет стёрта в ноль (заводские ключи FFFFFFFFFFFF).",
        "format_confirm": "Точно стереть?",
        "format_done": "Метка стёрта в заводское состояние",
        "menu_write_data": "Записать данные (URL / текст / Wi-Fi / raw)",
        "menu_write_spool": "Записать другую катушку (из дампа)",
        "menu_show_content": "Показать содержимое метки",
        "menu_show_bambu": "Показать данные филамента Bambu",
        "menu_dump": "Снять дамп в файл",
        "menu_format": "Стереть в заводское состояние",
        "data_too_long": "Данные не влезают в тег 1K",
        "spool_hdr": "Исходный дамп",
        "spool_pick": "Выберите дамп (номер) или укажите путь к файлу",
        "spool_pick_path": "Укажите путь к дампу .mfd",
        "spool_no_dumps": "Рядом со скриптом нет дампов .mfd.",
        "spool_bad_file": "Не удалось прочитать дамп 1024 Б: {path}",
        "spool_not_bambu": "В дампе нет данных филамента Bambu — записать всё равно?",
        "spool_source": "Исходная катушка: {desc}",
        "spool_sig_warn": "Метка сохраняет свой UID, поэтому RSA-подпись исходной катушки не совпадёт — "
                          "принтеры, проверяющие её, могут отклонить катушку. Восстановление дампа на свою же метку работает полностью.",
        "spool_done": "Катушка Bambu записана: {desc}",
        "menu_craft_spool": "Собрать катушку Bambu (из параметров)",
        "craft_pick": "Выберите материал",
        "craft_custom": "Вручную (ввести ID самому)",
        "craft_codes_note": "Коды материалов в пресетах — типовые; при сомнении сверьтесь с реальной катушкой.",
        "craft_preview": "Катушка для записи: {desc}",
        "enter_variant": "Material Variant ID",
        "enter_material": "Material ID",
        "enter_ftype": "Тип филамента",
        "enter_detailed": "Детальный тип",
        "enter_color": "Цвет RGBA hex",
        "enter_weight": "Вес, граммы",
        "enter_diameter": "Диаметр, мм",
        "enter_dry_temp": "Температура сушки, °C",
        "enter_dry_time": "Время сушки, часы",
        "enter_bed_temp": "Температура стола, °C",
        "enter_hot_min": "Мин. температура сопла, °C",
        "enter_hot_max": "Макс. температура сопла, °C",
        "bad_color": "Некорректный hex цвета.",
    },
}

def resolve_lang(argv):
    for i, a in enumerate(argv):
        if a.startswith("--lang="):
            v = a.split("=", 1)[1].lower()
            return "ru" if v.startswith("ru") else "en"
        if a in ("--lang", "-l") and i + 1 < len(argv):
            v = argv[i + 1].lower()
            return "ru" if v.startswith("ru") else "en"
    env = os.environ.get("BAMBU_LANG", "").lower()
    if env.startswith("ru"):
        return "ru"
    if env.startswith("en"):
        return "en"
    loc = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    return "ru" if loc.startswith("ru") else "en"

LANG = resolve_lang(sys.argv[1:])

def T(_key, **kw):
    s = STRINGS.get(LANG, STRINGS["en"]).get(_key) or STRINGS["en"].get(_key, _key)
    return s.format(**kw) if kw else s

# ============================ пути / константы ============================
HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "nfc_helper")
HELPER_SRC = os.path.join(HERE, "nfc_helper.c")
KEYS_FILE = os.path.join(HERE, "fullkeys.mfd")
WORK_FILE = os.path.join(HERE, "workkeys.mfd")
TARGET_FILE = os.path.join(HERE, "target.mfd")
DUMP_FILE = os.path.join(HERE, "carddump.mfd")
BLANK_KEYS_FILE = os.path.join(HERE, "blankkeys.mfd")

ACC_LOCKED = "87878769"
FFKEY = bytes.fromhex("FFFFFFFFFFFF")
TRANSPORT = bytes([0xFF, 0x07, 0x80, 0x69])

BOLD, DIM, GRN, RED, YEL, CYN, MAG, RST = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[35m", "\033[0m")

def hdr(title):  print(f"\n{BOLD}{CYN}━━━ {title} ━━━{RST}")
def ok(m):       print(f"  {GRN}✓{RST} {m}")
def warn(m):     print(f"  {YEL}!{RST} {m}")
def err(m):      print(f"  {RED}✗{RST} {m}")
def info(m):     print(f"  {DIM}{m}{RST}")

def ask(prompt, default=None):
    suf = f" [{default}]" if default else ""
    try:
        v = input(f"{BOLD}?{RST} {prompt}{suf}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(1)
    return v or (default or "")

def confirm(prompt):
    return ask(f"{prompt} (y/n)", "y").lower().startswith("y")

def wait_tag():
    try:
        input(f"{BOLD}»{RST} {T('wait_tag')}")
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(1)

# ============================ хелпер ============================
def ensure_helper():
    if os.path.exists(HELPER) and os.path.getmtime(HELPER) >= os.path.getmtime(HELPER_SRC):
        return
    info(T("building_helper"))
    r = subprocess.run(["cc", HELPER_SRC, "-I/opt/homebrew/include",
                        "-L/opt/homebrew/lib", "-lnfc", "-o", HELPER],
                       capture_output=True, text=True)
    if r.returncode != 0:
        err(T("helper_build_fail")); print(r.stderr); sys.exit(1)
    ok(T("helper_built"))

def helper(*args, stream=False):
    if not stream:
        return subprocess.run([HELPER, *args], capture_output=True, text=True)
    proc = subprocess.Popen([HELPER, *args], stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        info(line.rstrip())
    proc.wait()
    return proc

# ============================ ключи ============================
def write_keyfile(uid, path=KEYS_FILE):
    ka = derive_keys(uid, CONTEXT_A)
    kb = derive_keys(uid, CONTEXT_B)
    out = bytearray(1024)
    for s in range(16):
        out[s*64+48:s*64+64] = ka[s] + ACCESS_BITS + kb[s]
    with open(path, "wb") as f:
        f.write(out)

KEY_BYTES = {
    "default": FFKEY,
    "mad": bytes.fromhex("A0A1A2A3A4A5"),
    "ndef": bytes.fromhex("D3F7D3F7D3F7"),
}

def build_workkeys(uid, diag):
    ka = derive_keys(uid, CONTEXT_A)
    kb = derive_keys(uid, CONTEXT_B)
    out = bytearray(1024)
    for s in range(16):
        label = diag[s]["label"]
        if label in ("bambuA", "bambuB", "NONE"):
            keyA, keyB = ka[s], kb[s]
        else:
            keyA = KEY_BYTES.get(label, ka[s]); keyB = FFKEY
        out[s*64+48:s*64+64] = keyA + ACCESS_BITS + keyB
    with open(WORK_FILE, "wb") as f:
        f.write(out)

# ============================ NDEF: сборка записей ============================
URI_PREFIXES = [
    (0x01, "http://www."), (0x02, "https://www."), (0x03, "http://"),
    (0x04, "https://"), (0x05, "tel:"), (0x06, "mailto:"),
]

def ndef_record(tnf, rtype, payload, first=True, last=True):
    """Собирает одну NDEF-запись (короткую или длинную)."""
    header = (0x80 if first else 0) | (0x40 if last else 0) | (0x10 if len(payload) < 256 else 0) | (tnf & 0x07)
    out = bytes([header, len(rtype)])
    out += bytes([len(payload)]) if len(payload) < 256 else len(payload).to_bytes(4, "big")
    return out + rtype + payload

def ndef_uri_record(url):
    code, rest = 0x00, url
    for c, pref in URI_PREFIXES:
        if url.startswith(pref):
            code, rest = c, url[len(pref):]; break
    return ndef_record(0x01, b"U", bytes([code]) + rest.encode("utf-8"))

def ndef_text_record(text, lang="en"):
    payload = bytes([len(lang)]) + lang.encode("ascii") + text.encode("utf-8")
    return ndef_record(0x01, b"T", payload)

def ndef_wifi_record(ssid, password, auth=0x0020, enc=0x0008):
    """Wi-Fi Simple Configuration (WPA2-PSK/AES по умолчанию)."""
    def tlv(t, v): return t.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v
    cred = (tlv(0x1026, b"\x01") + tlv(0x1045, ssid.encode("utf-8")) +
            tlv(0x1003, auth.to_bytes(2, "big")) + tlv(0x100F, enc.to_bytes(2, "big")) +
            tlv(0x1027, password.encode("utf-8")) + tlv(0x1020, b"\x00" * 6))
    return ndef_record(0x02, b"application/vnd.wfa.wsc", tlv(0x100E, cred))

def wrap_tlv(message):
    tlv = (bytes([0x03, len(message)]) if len(message) < 255
           else bytes([0x03, 0xFF]) + len(message).to_bytes(2, "big")) + message
    return tlv + bytes([0xFE])

# ============================ NDEF: сборка образа тега ============================
def _place(d, payload, used):
    blocks = [s*4+b for s in range(1, 16) for b in range(3)]
    if len(payload) > len(blocks)*16:
        raise ValueError(T("data_too_long"))
    for i, byte in enumerate(payload):
        blk = blocks[i//16]; d[blk*16 + i % 16] = byte; used.add(blk//4)

def mad_crc8(data):
    crc = 0xC7
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

def build_ndef_target(message):
    d = bytearray(1024)
    used = set()
    _place(d, wrap_tlv(message), used)
    info_byte = 0x01
    aids = [0x03E1 if s in used else 0x0000 for s in range(1, 16)]
    aidb = b"".join(bytes([(a>>8)&0xFF, a&0xFF]) for a in aids)
    crc = mad_crc8(bytes([info_byte]) + aidb)
    d[16:32] = bytes([crc, info_byte]) + aidb[0:14]
    d[32:48] = aidb[14:30]
    d[48:64] = bytes.fromhex("A0A1A2A3A4A5") + bytes([0x78,0x77,0x88,0xC1]) + FFKEY
    for s in range(1, 16):
        t = s*64+48
        if s in used:
            d[t:t+16] = bytes.fromhex("D3F7D3F7D3F7") + bytes([0x7F,0x07,0x88,0x40]) + FFKEY
        else:
            d[t:t+16] = FFKEY + TRANSPORT + FFKEY
    return bytes(d), sorted(used)

def build_raw_target(data):
    """Произвольные байты в data-блоки, без MAD/NDEF, ключи заводские."""
    d = bytearray(1024)
    used = set()
    _place(d, data, used)
    for s in range(16):
        d[s*64+48:s*64+64] = FFKEY + TRANSPORT + FFKEY
    return bytes(d), sorted(used) or [1]

def build_blank_target():
    d = bytearray(1024)
    for s in range(16):
        d[s*64+48:s*64+64] = FFKEY + TRANSPORT + FFKEY
    return bytes(d)

def build_spool_target(uid, source):
    """Данные филамента из чужого дампа + ключи под UID текущей метки, заводской доступ (re-lock)."""
    ka = derive_keys(uid, CONTEXT_A)
    kb = derive_keys(uid, CONTEXT_B)
    d = bytearray(source)                       # копируем все data-блоки (включая RSA-подпись сект. 10-15)
    for s in range(16):                         # block 0 (manufacturer) не пишется хелпером
        d[s*64+48:s*64+64] = ka[s] + ACCESS_BITS + kb[s]   # ACCESS_BITS = 87878769 (как с завода)
    return bytes(d)

def bambu_desc(b):
    if not b:
        return "?"
    return f"{b['type']} / {b['detailed']}, #{b['color']}, {b['weight']}g"

# --- крафт катушки из параметров (по документированным смещениям блоков) ---
BUILTIN_PRESETS = [
    dict(name="PLA Basic", variant="A00-K0", material="GFA00", ftype="PLA", detailed="PLA Basic",
         dry_temp=55, dry_time=8, bed_temp=35, hot_min=190, hot_max=230, diameter=1.75),
    dict(name="PLA Matte", variant="A01-K0", material="GFA01", ftype="PLA", detailed="PLA Matte",
         dry_temp=55, dry_time=8, bed_temp=35, hot_min=190, hot_max=230, diameter=1.75),
    dict(name="PETG HF", variant="G02-K0", material="GFG02", ftype="PETG", detailed="PETG HF",
         dry_temp=65, dry_time=8, bed_temp=70, hot_min=220, hot_max=260, diameter=1.75),
    dict(name="ABS", variant="B00-K0", material="GFB00", ftype="ABS", detailed="ABS",
         dry_temp=80, dry_time=8, bed_temp=90, hot_min=240, hot_max=270, diameter=1.75),
    dict(name="TPU 95A", variant="U01-K0", material="GFU01", ftype="TPU", detailed="TPU 95A",
         dry_temp=70, dry_time=8, bed_temp=35, hot_min=200, hot_max=240, diameter=1.75),
]

def _rdstr(d, o, l): return d[o:o+l].split(b"\x00")[0].decode("ascii", "replace")
def _rdf32(d, o):
    try: return struct.unpack("<f", d[o:o+4])[0]
    except struct.error: return 0.0

def _put_str(d, off, s, ln):
    b = str(s).encode("ascii", "replace")[:ln]
    d[off:off+ln] = b + b"\x00" * (ln - len(b))
def _put_u16(d, off, v): d[off:off+2] = int(v).to_bytes(2, "little", signed=False)
def _put_f32(d, off, v): d[off:off+4] = struct.pack("<f", float(v))

def build_crafted_spool(uid, p):
    """Собирает валидную структуру Bambu-катушки из параметров. Подпись (сект.10-15) = нули."""
    ka = derive_keys(uid, CONTEXT_A); kb = derive_keys(uid, CONTEXT_B)
    d = bytearray(1024)
    _put_str(d, 16, p["variant"], 8); _put_str(d, 24, p["material"], 8)   # блок 1: Tray Info Index
    _put_str(d, 32, p["ftype"], 16)                                       # блок 2: Filament Type
    _put_str(d, 64, p["detailed"], 16)                                    # блок 4: Detailed Type
    d[80:84] = p["color"]                                                 # блок 5: цвет RGBA
    _put_u16(d, 84, p["weight"]); _put_f32(d, 88, p["diameter"])          #         вес, диаметр
    _put_u16(d, 96, p["dry_temp"]); _put_u16(d, 98, p["dry_time"])        # блок 6: сушка
    _put_u16(d, 102, p["bed_temp"])                                       #         температура стола
    _put_u16(d, 104, p["hot_max"]); _put_u16(d, 106, p["hot_min"])        #         сопло max/min
    _put_f32(d, 140, p.get("nozzle", 0.4))                               # блок 8: диаметр сопла
    _put_u16(d, 164, p.get("width", 6625))                               # блок 10: ширина катушки
    _put_str(d, 192, p.get("date", "2024_01_01_00_00"), 16)              # блок 12: дата производства
    _put_u16(d, 228, p.get("length", 330))                              # блок 14: длина, м
    for s in range(16):
        d[s*64+48:s*64+64] = ka[s] + ACCESS_BITS + kb[s]
    return bytes(d)

def _preset_from_dump(fn, data):
    b = parse_bambu(data)
    if not b:
        return None
    return dict(name=f"{b['detailed'] or b['type']}  [{fn}]",
                variant=_rdstr(data, 16, 8), material=b["mat"], ftype=b["type"], detailed=b["detailed"],
                dry_temp=int.from_bytes(data[96:98], "little"), dry_time=int.from_bytes(data[98:100], "little"),
                bed_temp=int.from_bytes(data[102:104], "little"),
                hot_max=int.from_bytes(data[104:106], "little"), hot_min=int.from_bytes(data[106:108], "little"),
                diameter=_rdf32(data, 88), color=data[80:84], weight=int.from_bytes(data[84:86], "little"))

# ============================ NDEF / контент: разбор ============================
def _data_stream(dump):
    out = bytearray()
    for s in range(1, 16):
        for b in range(3):
            blk = s*4+b; out += dump[blk*16:blk*16+16]
    return bytes(out)

def _parse_wifi(payload):
    def walk(buf, acc):
        i = 0
        while i + 4 <= len(buf):
            t = int.from_bytes(buf[i:i+2], "big"); l = int.from_bytes(buf[i+2:i+4], "big")
            v = buf[i+4:i+4+l]; i += 4 + l
            if t == 0x100E:
                walk(v, acc)
            else:
                acc.setdefault(t, v)
    f = {}; walk(payload, f)
    ssid = f.get(0x1045, b"").decode("utf-8", "replace")
    key = f.get(0x1027, b"").decode("utf-8", "replace")
    return ssid, key

def parse_ndef(dump):
    """Возвращает словарь {'kind':..., ...} для первой NDEF-записи, либо None."""
    stream = _data_stream(dump)
    i = 0
    while i < len(stream):
        t = stream[i]
        if t == 0x00: i += 1; continue
        if t == 0xFE or t is None: break
        if t == 0x03:
            if stream[i+1] == 0xFF:
                ln = int.from_bytes(stream[i+2:i+4], "big"); j = i+4
            else:
                ln = stream[i+1]; j = i+2
            msg = stream[j:j+ln]
            if len(msg) < 2:
                return None
            tnf = msg[0] & 0x07; short = bool(msg[0] & 0x10); tlen = msg[1]
            if short:
                plen = msg[2]; k = 3
            else:
                plen = int.from_bytes(msg[3:7], "big"); k = 7
            rtype = msg[k:k+tlen]; k += tlen
            payload = msg[k:k+plen]
            if tnf == 0x01 and rtype == b"U" and payload:
                pref = dict(URI_PREFIXES + [(0x00, "")]).get(payload[0], "")
                return {"kind": "uri", "v": pref + payload[1:].decode("utf-8", "replace")}
            if tnf == 0x01 and rtype == b"T" and payload:
                ll = payload[0] & 0x3F
                return {"kind": "text", "v": payload[1+ll:].decode("utf-8", "replace")}
            if tnf == 0x02 and rtype == b"application/vnd.wfa.wsc":
                ssid, key = _parse_wifi(payload)
                return {"kind": "wifi", "ssid": ssid, "key": key}
            return {"kind": "mime", "v": payload.hex().upper()}
        i += 1
    return None

def describe_content(dump):
    d = parse_ndef(dump)
    if d:
        return d
    raw = _data_stream(dump).rstrip(b"\x00")
    if raw:
        h = raw.hex().upper()
        return {"kind": "raw", "n": len(raw), "v": (h[:48] + "…" if len(h) > 48 else h)}
    return None

def content_summary(c):
    if c["kind"] == "uri":  return T("sum_uri", v=c["v"])
    if c["kind"] == "text": return T("sum_text", v=c["v"])
    if c["kind"] == "wifi": return T("sum_wifi", ssid=c["ssid"], key=c["key"])
    if c["kind"] == "raw":  return T("sum_raw", n=c["n"], v=c["v"])
    return T("sum_raw", n=len(c.get("v", "")) // 2, v=c.get("v", ""))

def parse_bambu(dump):
    def s(b): return b.split(b"\x00")[0].decode("ascii", "replace")
    ftype = s(dump[32:48]); detailed = s(dump[64:80])
    if not ftype and not detailed:
        return None
    try:
        weight = struct.unpack("<H", dump[84:86])[0]
        diam = struct.unpack("<f", dump[88:92])[0]
    except struct.error:
        weight, diam = 0, 0.0
    return dict(tray=s(dump[16:24]), mat=s(dump[24:32]), type=ftype, detailed=detailed,
                color=dump[80:84].hex().upper(), weight=weight, diam=diam)

# ============================ состояние ============================
def read_uid():
    for _ in range(8):
        r = helper("uid")
        line = r.stdout.strip()
        if r.returncode == 0 and line:
            try:
                return bytes.fromhex(line)
            except ValueError:
                pass
        time.sleep(0.3)
    return None

def run_diag(uid):
    write_keyfile(uid)
    r = helper("diag", KEYS_FILE)
    diag = {}
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) >= 4 and p[0] == "sector":
            s = int(p[1]); diag[s] = {"label": p[2], "access": p[3]}
    for s in range(16):
        diag.setdefault(s, {"label": "NONE", "access": "????????"})
    return diag

def classify(diag):
    labels = [diag[s]["label"] for s in range(16)]
    acc = [diag[s]["access"].upper() for s in range(16)]
    has_bambu = any(l in ("bambuA", "bambuB") for l in labels)
    has_pub = any(l in ("mad", "ndef") for l in labels)
    all_default = all(l == "default" for l in labels)
    any_none = any(l == "NONE" for l in labels)
    locked = any(a == ACC_LOCKED for a in acc)

    if has_bambu and locked:
        kind_key, secured = "kind_locked", True
    elif has_bambu and not locked:
        kind_key, secured = "kind_unlocked", False
    elif has_pub:
        kind_key, secured = "kind_ndef", False
    elif all_default:
        kind_key, secured = "kind_blank", False
    elif any_none:
        kind_key, secured = "kind_unknown", None
    else:
        kind_key, secured = "kind_mixed", False
    return kind_key, secured, has_bambu

# ============================ запись ============================
def do_write(target_bytes, locked, verify_keyfile):
    with open(TARGET_FILE, "wb") as f:
        f.write(target_bytes)
    if locked:
        info(T("unlocking"))
        helper("unlock", WORK_FILE, stream=True)
    info(T("writing"))
    w = helper("write", TARGET_FILE, WORK_FILE, stream=True)
    if w.returncode != 0:
        err(T("write_partial_fail"))
        return None
    ok(T("write_ok"))
    info(T("verify_read"))
    helper("read", verify_keyfile, DUMP_FILE, stream=True)
    with open(DUMP_FILE, "rb") as f:
        return f.read()

# ============================ действия ============================
INTERNAL_MFD = {"fullkeys.mfd", "workkeys.mfd", "target.mfd", "carddump.mfd",
                "blankkeys.mfd", "verify.mfd"}

def _list_dumps():
    items = []
    for fn in sorted(os.listdir(HERE)):
        if not fn.endswith(".mfd") or fn in INTERNAL_MFD:
            continue
        try:
            with open(os.path.join(HERE, fn), "rb") as f:
                data = f.read()
        except OSError:
            continue
        if len(data) != 1024:
            continue
        items.append((fn, data, bambu_desc(parse_bambu(data))))
    return items

def _refresh_from_target(ctx, target):
    """После записи: рабочие ключи и флаг locked теперь соответствуют записанному образу."""
    with open(WORK_FILE, "wb") as f:
        f.write(target)
    acc = {target[s*64+54:s*64+58].hex().upper() for s in range(16)}
    ctx["locked"] = (ACC_LOCKED in acc)

def _ask_int(key, default):
    try:
        return int(ask(T(key), str(default)))
    except ValueError:
        return int(default)

def _ask_float(key, default):
    try:
        return float(ask(T(key), str(default)))
    except ValueError:
        return float(default)

def _parse_color(s):
    s = s.strip().lstrip("#")
    if len(s) == 6:
        s += "FF"
    if len(s) != 8:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None

def _pick_datatype():
    opts = [("type_url",), ("type_text",), ("type_wifi",), ("type_raw",)]
    hdr(T("hdr_datatype"))
    for i, (k,) in enumerate(opts, 1):
        print(f"  {BOLD}{i}{RST}) {T(k)}")
    c = ask(T("choose_action"), "1")
    return int(c) if c.isdigit() and 1 <= int(c) <= 4 else 1

def act_write_data(ctx):
    kind = _pick_datatype()
    raw_mode = False
    try:
        if kind == 1:
            url = ask(T("enter_url"), "https://bambulab.com")
            target, used = build_ndef_target(ndef_uri_record(url))
        elif kind == 2:
            text = ask(T("enter_text"))
            if not text: warn(T("empty_input")); return
            target, used = build_ndef_target(ndef_text_record(text))
        elif kind == 3:
            ssid = ask(T("enter_ssid"))
            if not ssid: warn(T("empty_input")); return
            pw = ask(T("enter_wifi_pass"))
            target, used = build_ndef_target(ndef_wifi_record(ssid, pw))
        else:
            hexs = ask(T("enter_raw")).replace(" ", "").replace(":", "")
            try:
                data = bytes.fromhex(hexs)
            except ValueError:
                err(T("bad_hex")); return
            if not data: warn(T("empty_input")); return
            target, used = build_raw_target(data)
            raw_mode = True
    except ValueError as e:
        err(str(e)); return

    # предпросмотр
    preview = describe_content(target)
    desc = content_summary(preview) if preview else "?"
    ok(T("image_built", desc=desc, n=len(used)))
    if not confirm(f"{BOLD}{T('write_confirm')}{RST}"):
        info(T("cancelled")); return

    dump = do_write(target, ctx["locked"], TARGET_FILE)
    if dump is None:
        return
    _refresh_from_target(ctx, target)
    got = describe_content(dump)
    if got:
        print(f"\n{BOLD}{GRN}✓ {T('done_write', desc=content_summary(got))}{RST}")
    else:
        err(T("read_back_fail"))
    ctx["dump"] = dump

def act_write_spool(ctx):
    dumps = _list_dumps()
    print()
    if dumps:
        hdr(T("spool_hdr"))
        for i, (fn, _, desc) in enumerate(dumps, 1):
            print(f"  {BOLD}{i}{RST}) {fn}  {DIM}{desc}{RST}")
        sel = ask(T("spool_pick"))
    else:
        warn(T("spool_no_dumps"))
        sel = ask(T("spool_pick_path"))

    source = None
    if sel.isdigit() and dumps and 1 <= int(sel) <= len(dumps):
        source = dumps[int(sel) - 1][1]
    else:
        p = sel if os.path.isabs(sel) else os.path.join(HERE, sel)
        try:
            with open(p, "rb") as f:
                data = f.read()
            if len(data) == 1024:
                source = data
        except OSError:
            source = None
    if source is None:
        err(T("spool_bad_file", path=sel)); return

    b = parse_bambu(source)
    if not b and not confirm(T("spool_not_bambu")):
        return
    ok(T("spool_source", desc=bambu_desc(b)))
    warn(T("spool_sig_warn"))
    if not confirm(f"{BOLD}{T('write_confirm')}{RST}"):
        info(T("cancelled")); return

    write_keyfile(ctx["uid"])                       # verify-ключи = derived под UID метки
    target = build_spool_target(ctx["uid"], source)
    dump = do_write(target, ctx["locked"], KEYS_FILE)
    if dump is None:
        return
    _refresh_from_target(ctx, target)
    print(f"\n{BOLD}{GRN}✓ {T('spool_done', desc=bambu_desc(parse_bambu(dump)))}{RST}")
    ctx["dump"] = dump

def act_craft_spool(ctx):
    presets = [p for p in (_preset_from_dump(fn, data) for fn, data, _ in _list_dumps()) if p]
    presets += BUILTIN_PRESETS
    hdr(T("craft_pick"))
    for i, p in enumerate(presets, 1):
        print(f"  {BOLD}{i}{RST}) {p['name']}")
    print(f"  {BOLD}{len(presets)+1}{RST}) {T('craft_custom')}")
    info(T("craft_codes_note"))
    sel = ask(T("craft_pick"), "1")
    idx = int(sel) - 1 if sel.isdigit() else -1

    if idx == len(presets):                          # custom
        p = dict(variant=ask(T("enter_variant"), "A00-K0"), material=ask(T("enter_material"), "GFA00"),
                 ftype=ask(T("enter_ftype"), "PLA"), detailed=ask(T("enter_detailed"), "PLA Basic"),
                 dry_temp=_ask_int("enter_dry_temp", 55), dry_time=_ask_int("enter_dry_time", 8),
                 bed_temp=_ask_int("enter_bed_temp", 35), hot_min=_ask_int("enter_hot_min", 190),
                 hot_max=_ask_int("enter_hot_max", 230), diameter=_ask_float("enter_diameter", 1.75))
        default_color, default_weight = "000000FF", 1000
    elif 0 <= idx < len(presets):
        p = dict(presets[idx])
        default_color = p["color"].hex().upper() if p.get("color") else "000000FF"
        default_weight = p.get("weight", 1000)
    else:
        warn(T("no_such_item")); return

    color = _parse_color(ask(T("enter_color"), default_color))
    if not color:
        err(T("bad_color")); return
    p["color"] = color
    p["weight"] = _ask_int("enter_weight", default_weight)
    p.setdefault("diameter", 1.75)

    target = build_crafted_spool(ctx["uid"], p)
    ok(T("craft_preview", desc=bambu_desc(parse_bambu(target))))
    warn(T("spool_sig_warn"))
    if not confirm(f"{BOLD}{T('write_confirm')}{RST}"):
        info(T("cancelled")); return

    write_keyfile(ctx["uid"])
    dump = do_write(target, ctx["locked"], KEYS_FILE)
    if dump is None:
        return
    _refresh_from_target(ctx, target)
    print(f"\n{BOLD}{GRN}✓ {T('spool_done', desc=bambu_desc(parse_bambu(dump)))}{RST}")
    ctx["dump"] = dump

def act_show_content(ctx):
    c = describe_content(ctx["dump"]) if ctx.get("dump") else None
    if c:
        print(f"\n{BOLD}{MAG}{T('hdr_content')}:{RST} {content_summary(c)}")
    else:
        warn(T("no_content"))

def act_show_bambu(ctx):
    b = parse_bambu(ctx["dump"]) if ctx.get("dump") else None
    if not b:
        warn(T("no_bambu")); return
    print(f"\n{BOLD}{T('bambu_header')}{RST}")
    for key in ("f_type", "f_tray", "f_color", "f_weight", "f_diam"):
        print("  " + T(key, **b))

def act_dump(ctx):
    path = ask(T("dump_name"), f"dump_{ctx['uid'].hex().upper()}.mfd")
    with open(os.path.join(HERE, path), "wb") as f:
        f.write(ctx["dump"])
    ok(T("dump_saved", path=path))

def act_format(ctx):
    warn(T("format_warn"))
    if not confirm(T("format_confirm")):
        info(T("cancelled")); return
    blank = bytearray(1024)
    for s in range(16):
        blank[s*64+48:s*64+64] = FFKEY + TRANSPORT + FFKEY
    with open(BLANK_KEYS_FILE, "wb") as f:
        f.write(blank)
    target = build_blank_target()
    dump = do_write(target, ctx["locked"], BLANK_KEYS_FILE)
    if dump is not None:
        _refresh_from_target(ctx, target)
        ok(T("format_done"))
        ctx["dump"] = dump

# ============================ меню ============================
def build_menu(ctx):
    has_content = bool(describe_content(ctx["dump"])) if ctx.get("dump") else False
    has_binfo = bool(parse_bambu(ctx["dump"])) if ctx.get("dump") else False
    menu = [(T("menu_write_data"), act_write_data),
            (T("menu_write_spool"), act_write_spool),
            (T("menu_craft_spool"), act_craft_spool)]
    if has_content:
        menu.append((T("menu_show_content"), act_show_content))
    if has_binfo:
        menu.append((T("menu_show_bambu"), act_show_bambu))
    menu.append((T("menu_dump"), act_dump))
    menu.append((T("menu_format"), act_format))
    return menu

def main():
    print(f"{BOLD}{T('app_title')}{RST}")
    print(f"{DIM}{T('app_sub')}{RST}")
    ensure_helper()

    hdr(T("hdr_detect"))
    wait_tag()
    uid = read_uid()
    if not uid:
        err(T("tag_not_found")); sys.exit(1)
    ok(T("uid_is", uid=uid.hex().upper()))

    info(T("diag_sectors"))
    diag = run_diag(uid)
    kind_key, secured, has_bambu = classify(diag)
    build_workkeys(uid, diag)

    info(T("reading_content"))
    helper("read", WORK_FILE, DUMP_FILE, stream=False)
    try:
        with open(DUMP_FILE, "rb") as f:
            dump = f.read()
    except FileNotFoundError:
        dump = bytes(1024)

    hdr(T("hdr_state"))
    mark = {True: f"{RED}{T('yes')}{RST}", False: f"{GRN}{T('no')}{RST}",
            None: f"{YEL}{T('unknown')}{RST}"}[secured]
    print(f"  {T('lbl_kind')}{BOLD}{T(kind_key)}{RST}")
    print(f"  {T('lbl_secured')}{mark}")
    acc_set = sorted({diag[s]['access'] for s in range(16)})
    print(f"  {T('lbl_access')}{' '.join(acc_set)}")
    if secured:
        info(T("secured_hint"))

    ctx = dict(uid=uid, diag=diag, kind=kind_key, secured=secured, has_bambu=has_bambu,
               locked=(secured is True), dump=dump)

    while True:
        menu = build_menu(ctx)
        hdr(T("hdr_actions"))
        for i, (title, _) in enumerate(menu, 1):
            print(f"  {BOLD}{i}{RST}) {title}")
        print(f"  {BOLD}0{RST}) {T('menu_exit')}")
        choice = ask(T("choose_action"), "1")
        if choice == "0":
            break
        try:
            idx = int(choice) - 1
            assert 0 <= idx < len(menu)
        except (ValueError, AssertionError):
            warn(T("no_such_item")); continue
        menu[idx][1](ctx)

if __name__ == "__main__":
    main()
