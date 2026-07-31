// Для каждого сектора перебирает все 16 кандидатов KeyB из 96-байтного файла.
#include <nfc/nfc.h>
#include <stdio.h>
#include <string.h>
static nfc_device *pnd; static nfc_context *ctx;
static int authB(int block, const uint8_t *key){
    nfc_modulation mod={.nmt=NMT_ISO14443A,.nbr=NBR_106}; nfc_target nt;
    if(nfc_initiator_select_passive_target(pnd,mod,NULL,0,&nt)<=0) return -999;
    const uint8_t *uid=nt.nti.nai.abtUid; uint8_t ul=nt.nti.nai.szUidLen;
    uint8_t cmd[12],resp[264]; cmd[0]=0x61; cmd[1]=block;
    memcpy(cmd+2,key,6); memcpy(cmd+8,uid+(ul-4),4);
    int r=nfc_initiator_transceive_bytes(pnd,cmd,12,resp,sizeof(resp),0);
    nfc_initiator_deselect_target(pnd); return r;
}
int main(int argc,char**argv){
    FILE*f=fopen(argv[1],"rb"); uint8_t k[96]; fread(k,1,96,f); fclose(f);
    nfc_init(&ctx); pnd=nfc_open(ctx,NULL); nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd,NP_EASY_FRAMING,true);
    nfc_device_set_property_bool(pnd,NP_AUTO_ISO14443_4,false);
    for(int s=0;s<16;s++){
        int found=-1;
        for(int c=0;c<16;c++){ if(authB(s*4+3,k+c*6)>=0){found=c;break;} }
        if(found>=0) printf("sector %2d  <- candidate %2d  %02X%02X%02X%02X%02X%02X\n",
            s,found,k[found*6],k[found*6+1],k[found*6+2],k[found*6+3],k[found*6+4],k[found*6+5]);
        else printf("sector %2d  <- НЕ НАЙДЕН среди 16 кандидатов\n",s);
    }
    nfc_close(pnd); nfc_exit(ctx); return 0;
}
