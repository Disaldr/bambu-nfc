// Фаза 1: сменить access-биты всех трейлеров на транспортные (FF078069) через KeyB.
// Пишем ТОЛЬКО трейлер (config 101 разрешает менять access-биты ключом B).
#include <nfc/nfc.h>
#include <stdio.h>
#include <string.h>
static nfc_device *pnd; static nfc_context *ctx;
static uint8_t keyA[16][6], keyB[16][6];

// select+auth+write трейлера за одну активацию карты
static int unlock_sector(int s){
    int trailer = s*4 + 3;
    nfc_modulation mod={.nmt=NMT_ISO14443A,.nbr=NBR_106}; nfc_target nt;
    if(nfc_initiator_select_passive_target(pnd,mod,NULL,0,&nt)<=0) return -1;
    const uint8_t *uid=nt.nti.nai.abtUid; uint8_t ul=nt.nti.nai.szUidLen;

    uint8_t cmd[18], resp[264];
    // auth B
    cmd[0]=0x61; cmd[1]=trailer; memcpy(cmd+2,keyB[s],6); memcpy(cmd+8,uid+(ul-4),4);
    if(nfc_initiator_transceive_bytes(pnd,cmd,12,resp,sizeof(resp),0)<0){ nfc_initiator_deselect_target(pnd); return -2; }
    // write трейлера: KeyA + FF078069 + KeyB
    cmd[0]=0xA0; cmd[1]=trailer;
    memcpy(cmd+2, keyA[s], 6);
    cmd[8]=0xFF; cmd[9]=0x07; cmd[10]=0x80; cmd[11]=0x69;
    memcpy(cmd+12, keyB[s], 6);
    int w=nfc_initiator_transceive_bytes(pnd,cmd,18,resp,sizeof(resp),0);
    nfc_initiator_deselect_target(pnd);
    return w<0 ? -3 : 0;
}

int main(void){
    FILE*f=fopen("fullkeys.mfd","rb"); uint8_t buf[1024]; fread(buf,1,1024,f); fclose(f);
    for(int s=0;s<16;s++){ memcpy(keyA[s],buf+s*64+48,6); memcpy(keyB[s],buf+s*64+58,6); }
    nfc_init(&ctx); pnd=nfc_open(ctx,NULL); nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd,NP_EASY_FRAMING,true);
    nfc_device_set_property_bool(pnd,NP_AUTO_ISO14443_4,false);
    int ok=0;
    for(int s=0;s<16;s++){
        int r=-99;
        for(int try=0; try<5 && r!=0; try++) r=unlock_sector(s);   // до 5 попыток на сектор
        printf("sector %2d: %s\n", s, r==0?"access -> FF078069 OK":"FAIL");
        if(r==0) ok++;
    }
    printf("\nРазблокировано %d/16 секторов\n", ok);
    nfc_close(pnd); nfc_exit(ctx); return 0;
}
