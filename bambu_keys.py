#!/usr/bin/env python3
"""Генерация ключей MIFARE Classic для тегов Bambu Lab из UID.

Алгоритм: HKDF-SHA256(ikm=UID, salt=master, info=b"RFID-A\\0") -> 16 ключей по 6 байт.
Источник: https://github.com/Bambu-Research-Group/RFID-Tag-Guide

Использование:
    python3 bambu_keys.py <UID_hex>              # печать ключей
    python3 bambu_keys.py <UID_hex> keys.mfd     # + keyfile для nfc-mfclassic
"""
import hashlib
import hmac
import sys

MASTER = bytes([0x9A, 0x75, 0x9C, 0xF2, 0xC4, 0xF7, 0xCA, 0xFF,
                0x22, 0x2C, 0xB9, 0x76, 0x9B, 0x41, 0xBC, 0x96])
CONTEXT_A = b"RFID-A\0"
CONTEXT_B = b"RFID-B\0"                    # KeyB на новых тегах тоже выводится из UID
ACCESS_BITS = bytes.fromhex("87878769")   # одинаковые на всех тегах Bambu


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_keys(uid: bytes, context: bytes) -> list[bytes]:
    okm = hkdf_sha256(uid, MASTER, context, 6 * 16)
    return [okm[i * 6:(i + 1) * 6] for i in range(16)]


def build_keyfile(keys_a: list[bytes], keys_b: list[bytes],
                  access: bytes = ACCESS_BITS) -> bytes:
    """Дамп 1024 Б с реальными KeyA/KeyB в трейлерах — формат keyfile для nfc-mfclassic."""
    out = bytearray(1024)
    for sector, (ka, kb) in enumerate(zip(keys_a, keys_b)):
        trailer = sector * 64 + 48
        out[trailer:trailer + 16] = ka + access + kb
    return bytes(out)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    uid = bytes.fromhex(sys.argv[1].replace(":", "").replace(" ", ""))
    keys_a = derive_keys(uid, CONTEXT_A)
    keys_b = derive_keys(uid, CONTEXT_B)
    for sector, (ka, kb) in enumerate(zip(keys_a, keys_b)):
        print(f"Sector {sector:2d}:  KeyA {ka.hex().upper()}   KeyB {kb.hex().upper()}")
    if len(sys.argv) > 2:
        with open(sys.argv[2], "wb") as fh:
            fh.write(build_keyfile(keys_a, keys_b))
        print(f"\nKeyfile записан: {sys.argv[2]}")
