#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive tool for Bambu Lab spool tags (MIFARE Classic 1K) over a PN532.

Diagnoses the tag state (secured / unlocked / NDEF / blank / unknown) and offers
the available actions: write a URL, show the current link, show Bambu filament
data, dump to a file, wipe to factory state.

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
        "enter_url": "Enter URL",
        "image_built": 'Image built: "{url}" (data sectors: {n})',
        "write_confirm": "Write? This is irreversible",
        "cancelled": "Cancelled.",
        "done_url": "Done! Tag now holds link: {url}",
        "read_mismatch": 'Read "{got}", expected "{url}" — retry holding the tag steady.',
        "ndef_unrecognized": "NDEF not recognized on read — repeat the write.",
        "link_on_tag": "Link on tag: {url}",
        "no_ndef": "No NDEF link found on the tag.",
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
        "menu_write_url": "Write link (URL)",
        "menu_show_url": "Show link on tag",
        "menu_show_bambu": "Show Bambu filament data",
        "menu_dump": "Save dump to file",
        "menu_format": "Wipe to factory state",
        "url_too_long": "URL too long for a 1K tag",
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
        "enter_url": "Введите URL",
        "image_built": "Образ собран: «{url}» (секторов под данные: {n})",
        "write_confirm": "Записать? Это необратимо",
        "cancelled": "Отменено.",
        "done_url": "Готово! На метке ссылка: {url}",
        "read_mismatch": "Прочитано «{got}», ожидалось «{url}» — повторите, держа тег ровно.",
        "ndef_unrecognized": "NDEF не распознан при чтении — повторите запись.",
        "link_on_tag": "Ссылка на метке: {url}",
        "no_ndef": "NDEF-ссылка на метке не найдена.",
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
        "menu_write_url": "Записать ссылку (URL)",
        "menu_show_url": "Показать ссылку с метки",
        "menu_show_bambu": "Показать данные филамента Bambu",
        "menu_dump": "Снять дамп в файл",
        "menu_format": "Стереть в заводское состояние",
        "url_too_long": "Ссылка слишком длинная для тега 1K",
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

def T(key, **kw):
    s = STRINGS.get(LANG, STRINGS["en"]).get(key) or STRINGS["en"].get(key, key)
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

ACC_LOCKED = "87878769"     # original Bambu: data blocks read-only
ACC_OPEN = "FF078069"       # transport access

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
    "default": bytes.fromhex("FFFFFFFFFFFF"),
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
            keyA = KEY_BYTES.get(label, ka[s]); keyB = bytes.fromhex("FFFFFFFFFFFF")
        out[s*64+48:s*64+64] = keyA + ACCESS_BITS + keyB
    with open(WORK_FILE, "wb") as f:
        f.write(out)

# ============================ NDEF ============================
URI_PREFIXES = [
    (0x01, "http://www."), (0x02, "https://www."), (0x03, "http://"),
    (0x04, "https://"), (0x05, "tel:"), (0x06, "mailto:"),
]

def mad_crc8(data):
    crc = 0xC7
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

def encode_uri(url):
    code, rest = 0x00, url
    for c, pref in URI_PREFIXES:
        if url.startswith(pref):
            code, rest = c, url[len(pref):]; break
    payload = bytes([code]) + rest.encode("utf-8")
    if len(payload) < 256:
        rec = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    else:
        rec = bytes([0xC1, 0x01]) + len(payload).to_bytes(4, "big") + bytes([0x55]) + payload
    tlv = (bytes([0x03, len(rec)]) if len(rec) < 255
           else bytes([0x03, 0xFF]) + len(rec).to_bytes(2, "big")) + rec
    return tlv + bytes([0xFE])

def build_ndef_target(url):
    d = bytearray(1024)
    tlv = encode_uri(url)
    blocks = [s*4+b for s in range(1, 16) for b in range(3)]
    if len(tlv) > len(blocks)*16:
        raise ValueError(T("url_too_long"))
    used = set()
    for i, byte in enumerate(tlv):
        blk = blocks[i//16]; d[blk*16 + i % 16] = byte; used.add(blk//4)
    info_byte = 0x01
    aids = [0x03E1 if s in used else 0x0000 for s in range(1, 16)]
    aidb = b"".join(bytes([(a>>8)&0xFF, a&0xFF]) for a in aids)
    crc = mad_crc8(bytes([info_byte]) + aidb)
    d[16:32] = bytes([crc, info_byte]) + aidb[0:14]
    d[32:48] = aidb[14:30]
    d[48:64] = bytes.fromhex("A0A1A2A3A4A5") + bytes([0x78,0x77,0x88,0xC1]) + bytes.fromhex("FFFFFFFFFFFF")
    for s in range(1, 16):
        t = s*64+48
        if s in used:
            d[t:t+16] = bytes.fromhex("D3F7D3F7D3F7") + bytes([0x7F,0x07,0x88,0x40]) + bytes.fromhex("FFFFFFFFFFFF")
        else:
            d[t:t+16] = bytes.fromhex("FFFFFFFFFFFF") + bytes([0xFF,0x07,0x80,0x69]) + bytes.fromhex("FFFFFFFFFFFF")
    return bytes(d), sorted(used)

def build_blank_target():
    d = bytearray(1024)
    for s in range(16):
        d[s*64+48:s*64+64] = bytes.fromhex("FFFFFFFFFFFF") + bytes([0xFF,0x07,0x80,0x69]) + bytes.fromhex("FFFFFFFFFFFF")
    return bytes(d)

def parse_ndef(dump):
    stream = bytearray()
    for s in range(1, 16):
        for b in range(3):
            blk = s*4+b; stream += dump[blk*16:blk*16+16]
    i = 0
    while i < len(stream):
        t = stream[i]
        if t == 0x00: i += 1; continue
        if t == 0xFE: break
        if t == 0x03:
            if stream[i+1] == 0xFF:
                ln = int.from_bytes(stream[i+2:i+4], "big"); j = i+4
            else:
                ln = stream[i+1]; j = i+2
            msg = stream[j:j+ln]
            if len(msg) >= 4 and (msg[0] & 0x07) == 0x01 and msg[3] == 0x55:
                short = bool(msg[0] & 0x10)
                plen = msg[2] if short else int.from_bytes(msg[3:7], "big")
                off = 4 if short else 7
                payload = msg[off:off+plen]
                pref = dict(URI_PREFIXES + [(0x00, "")]).get(payload[0], "")
                return pref + payload[1:].decode("utf-8", "replace")
            return None
        i += 1
    return None

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
def act_write_url(ctx):
    url = ask(T("enter_url"), "https://bambulab.com")
    try:
        target, used = build_ndef_target(url)
    except ValueError as e:
        err(str(e)); return
    ok(T("image_built", url=url, n=len(used)))
    if not confirm(f"{BOLD}{T('write_confirm')}{RST}"):
        info(T("cancelled")); return
    with open(TARGET_FILE, "wb") as f:
        f.write(target)
    dump = do_write(target, ctx["locked"], TARGET_FILE)
    if dump is None:
        return
    got = parse_ndef(dump)
    if got == url:
        print(f"\n{BOLD}{GRN}✓ {T('done_url', url=got)}{RST}")
    elif got:
        warn(T("read_mismatch", got=got, url=url))
    else:
        err(T("ndef_unrecognized"))
    ctx["dump"] = dump

def act_show_url(ctx):
    url = parse_ndef(ctx["dump"]) if ctx.get("dump") else None
    if url:
        print(f"\n{BOLD}{MAG}{T('link_on_tag', url=url)}{RST}")
    else:
        warn(T("no_ndef"))

def act_show_bambu(ctx):
    b = parse_bambu(ctx["dump"]) if ctx.get("dump") else None
    if not b:
        warn(T("no_bambu")); return
    print(f"\n{BOLD}{T('bambu_header')}{RST}")
    print("  " + T("f_type", **b))
    print("  " + T("f_tray", **b))
    print("  " + T("f_color", **b))
    print("  " + T("f_weight", **b))
    print("  " + T("f_diam", **b))

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
        blank[s*64+48:s*64+64] = bytes.fromhex("FFFFFFFFFFFFFF078069FFFFFFFFFFFF")
    with open(BLANK_KEYS_FILE, "wb") as f:
        f.write(blank)
    dump = do_write(build_blank_target(), ctx["locked"], BLANK_KEYS_FILE)
    if dump is not None:
        with open(WORK_FILE, "wb") as f:
            f.write(blank)
        ok(T("format_done"))
        ctx["dump"] = dump

# ============================ меню ============================
def build_menu(ctx):
    has_url = bool(parse_ndef(ctx["dump"])) if ctx.get("dump") else False
    has_binfo = bool(parse_bambu(ctx["dump"])) if ctx.get("dump") else False
    menu = [(T("menu_write_url"), act_write_url)]
    if has_url:
        menu.append((T("menu_show_url"), act_show_url))
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
