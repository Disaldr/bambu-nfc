// Контроль: для каждого сектора проверяем KeyA (derived, из keys.mfd) и KeyB (000000).
#include <nfc/nfc.h>
#include <stdio.h>
#include <string.h>

static nfc_device *pnd;
static nfc_context *ctx;
static uint8_t keyA[16][6];

static int auth(int block, uint8_t cmdcode, const uint8_t *key) {
    nfc_modulation mod = { .nmt = NMT_ISO14443A, .nbr = NBR_106 };
    nfc_target nt;
    if (nfc_initiator_select_passive_target(pnd, mod, NULL, 0, &nt) <= 0) return -999;
    uint8_t uidlen = nt.nti.nai.szUidLen;
    const uint8_t *uid = nt.nti.nai.abtUid;
    uint8_t cmd[12], resp[264];
    cmd[0] = cmdcode; cmd[1] = block;
    memcpy(cmd + 2, key, 6);
    memcpy(cmd + 8, uid + (uidlen - 4), 4);
    int res = nfc_initiator_transceive_bytes(pnd, cmd, 12, resp, sizeof(resp), 0);
    nfc_initiator_deselect_target(pnd);
    return res;
}

int main(void) {
    FILE *f = fopen("keys.mfd", "rb");
    if (!f) { printf("no keys.mfd\n"); return 1; }
    uint8_t buf[1024]; fread(buf, 1, 1024, f); fclose(f);
    for (int s = 0; s < 16; s++) memcpy(keyA[s], buf + s*64 + 48, 6);

    nfc_init(&ctx);
    pnd = nfc_open(ctx, NULL);
    if (!pnd) { printf("no device\n"); return 1; }
    nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true);
    nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false);

    static const uint8_t KEYB[6] = {0,0,0,0,0,0};
    int okA = 0, okB = 0;
    for (int s = 0; s < 16; s++) {
        int trailer = s*4 + 3;
        int ra = auth(trailer, 0x60, keyA[s]);  // 0x60 = auth A
        int rb = auth(trailer, 0x61, KEYB);      // 0x61 = auth B
        printf("sector %2d:  KeyA(derived) %s   KeyB(000000) %s\n",
               s, ra >= 0 ? "OK  " : "FAIL", rb >= 0 ? "OK" : "FAIL");
        if (ra >= 0) okA++;
        if (rb >= 0) okB++;
    }
    printf("\nKeyA OK: %d/16   KeyB OK: %d/16\n", okA, okB);
    nfc_close(pnd); nfc_exit(ctx);
    return 0;
}
