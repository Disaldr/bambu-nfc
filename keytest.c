// Проверка аутентификации трейлеров MIFARE Classic ключом B.
// Для каждого сектора: select -> auth(trailer, KeyB) -> результат. Карта переселектится каждый раз.
#include <nfc/nfc.h>
#include <stdio.h>
#include <string.h>

static nfc_device *pnd;
static nfc_context *ctx;

// KeyB = 000000000000 (по документации Bambu)
static const uint8_t KEYB[6] = {0,0,0,0,0,0};

static int select_card(nfc_target *nt) {
    nfc_modulation mod = { .nmt = NMT_ISO14443A, .nbr = NBR_106 };
    nfc_initiator_select_passive_target(pnd, mod, NULL, 0, nt);
    return nt->nti.nai.szUidLen > 0;
}

int main(void) {
    ctx = NULL;
    nfc_init(&ctx);
    pnd = nfc_open(ctx, NULL);
    if (!pnd) { printf("no device\n"); return 1; }
    nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true);
    nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false);

    int ok = 0;
    for (int sector = 0; sector < 16; sector++) {
        int trailer = sector * 4 + 3;
        nfc_target nt;
        if (!select_card(&nt)) { printf("sector %2d: select FAIL\n", sector); continue; }
        uint8_t uidlen = nt.nti.nai.szUidLen;
        const uint8_t *uid = nt.nti.nai.abtUid;

        // MC_AUTH_B = 0x61
        uint8_t cmd[12];
        cmd[0] = 0x61;
        cmd[1] = trailer;
        memcpy(cmd + 2, KEYB, 6);
        // последние 4 байта — UID (для MIFARE берётся последние 4 байта UID)
        memcpy(cmd + 8, uid + (uidlen - 4), 4);

        uint8_t resp[264];
        int res = nfc_initiator_transceive_bytes(pnd, cmd, 12, resp, sizeof(resp), 0);
        if (res >= 0) { printf("sector %2d: AUTH-B OK\n", sector); ok++; }
        else          { printf("sector %2d: AUTH-B FAIL (%d)\n", sector, res); }
        // сброс поля перед следующей итерацией
        nfc_initiator_deselect_target(pnd);
    }
    printf("\nИтог: KeyB=000000 сработал в %d/16 секторах\n", ok);
    nfc_close(pnd);
    nfc_exit(ctx);
    return 0;
}
