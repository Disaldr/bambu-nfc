// Тест auth B: читает файл из 96 байт (16 ключей по 6) и пробует auth B на каждом трейлере.
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
    if(argc<2){printf("usage: authB_file <keyfile96>\n");return 1;}
    FILE*f=fopen(argv[1],"rb"); if(!f){printf("no file\n");return 1;}
    uint8_t k[96]; if(fread(k,1,96,f)!=96){printf("need 96 bytes\n");return 1;} fclose(f);
    nfc_init(&ctx); pnd=nfc_open(ctx,NULL); if(!pnd){printf("no dev\n");return 1;}
    nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd,NP_EASY_FRAMING,true);
    nfc_device_set_property_bool(pnd,NP_AUTO_ISO14443_4,false);
    int ok=0;
    for(int s=0;s<16;s++){ int r=authB(s*4+3,k+s*6); if(r>=0){ok++; printf("sector %2d: KeyB OK  %02X%02X%02X%02X%02X%02X\n",s,k[s*6],k[s*6+1],k[s*6+2],k[s*6+3],k[s*6+4],k[s*6+5]);} }
    printf("KeyB совпал в %d/16 секторах (%s)\n",ok,argv[1]);
    nfc_close(pnd); nfc_exit(ctx); return 0;
}
