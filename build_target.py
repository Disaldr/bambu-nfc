#!/usr/bin/env python3
"""Собирает target.mfd — стандартный NDEF-тег MIFARE Classic 1K с URI https://bambulab.com."""
import sys
from bambu_keys import derive_keys, CONTEXT_A, CONTEXT_B

UID = bytes.fromhex("02158BEF")
URI = "bambulab.com"        # префикс 0x04 = "https://"

def mad_crc8(data: bytes) -> int:
    crc = 0xC7
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

# --- самопроверка CRC на эталоне: все секторы 1-15 = NDEF(03E1), info=01 -> CRC 0x14 ---
info = 0x01
all_ndef = bytes([info]) + b"\x03\xE1" * 15
assert mad_crc8(all_ndef) == 0x14, f"CRC broken: {mad_crc8(all_ndef):#04x}"
print("MAD-CRC самопроверка: OK (0x14)")

def build() -> bytes:
    src = bytearray(open("dump.mfd", "rb").read())
    d = bytearray(1024)                              # ЧИСТЫЙ образ: всё в нули
    d[0:16] = src[0:16]                              # block0 (manufacturer) — только read-only

    # --- сектор 0: MAD, только сектор 1 помечен как NDEF ---
    aids = [0x0000] * 16
    aids[1] = 0x03E1
    aidbytes = b"".join(bytes([(aids[s] >> 8) & 0xFF, aids[s] & 0xFF]) for s in range(1, 16))
    crc = mad_crc8(bytes([info]) + aidbytes)
    d[16:32] = bytes([crc, info]) + aidbytes[0:14]      # block 1: сектора 1-7
    d[32:48] = aidbytes[14:30]                           # block 2: сектора 8-15
    d[48:64] = bytes.fromhex("A0A1A2A3A4A5") + bytes([0x78,0x77,0x88,0xC1]) + bytes.fromhex("FFFFFFFFFFFF")

    # --- сектор 1: NDEF URI ---
    record = bytes([0xD1, 0x01, 1 + len(URI), 0x55, 0x04]) + URI.encode()
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    assert len(tlv) <= 48, "TLV не влезает в сектор"
    sec = bytearray(48)
    sec[0:len(tlv)] = tlv
    d[64:112] = sec
    d[112:128] = bytes.fromhex("D3F7D3F7D3F7") + bytes([0x7F,0x07,0x88,0x40]) + bytes.fromhex("FFFFFFFFFFFF")

    # --- сектора 2-15: чистые (данные=00), заводские ключи FFFFFFFFFFFF ---
    for s in range(2, 16):
        t = s * 64 + 48
        d[t:t+16] = bytes.fromhex("FFFFFFFFFFFF") + bytes.fromhex("FF078069") + bytes.fromhex("FFFFFFFFFFFF")
    return bytes(d)

if __name__ == "__main__":
    out = build()
    open("target.mfd", "wb").write(out)
    print("target.mfd собран.")
    print("MAD block1:", out[16:32].hex().upper())
    print("Сектор1 blk4:", out[64:80].hex().upper())
    print("Сектор1 blk5:", out[80:96].hex().upper())
