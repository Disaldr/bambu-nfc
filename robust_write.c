// Надёжная запись target.mfd на тег: мультиключевая авторизация + retry + verify.
#include <nfc/nfc.h>
#include <stdio.h>
#include <string.h>

static nfc_device *pnd; static nfc_context *ctx;
static uint8_t target[1024], dA[16][6], dB[16][6], tA[16][6];
static const uint8_t FF[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

static int do_select(uint8_t *uid,uint8_t *ul){
    nfc_modulation mod={.nmt=NMT_ISO14443A,.nbr=NBR_106}; nfc_target nt;
    if(nfc_initiator_select_passive_target(pnd,mod,NULL,0,&nt)<=0) return 0;
    *ul=nt.nti.nai.szUidLen; memcpy(uid,nt.nti.nai.abtUid,*ul); return 1;
}
static int try_auth(int block,uint8_t code,const uint8_t*key,const uint8_t*uid,uint8_t ul){
    uint8_t cmd[12],resp[264];
    cmd[0]=code; cmd[1]=block; memcpy(cmd+2,key,6); memcpy(cmd+8,uid+(ul-4),4);
    return nfc_initiator_transceive_bytes(pnd,cmd,12,resp,sizeof(resp),0)>=0;
}
// перебор ключей-кандидатов для сектора s; при успехе карта остаётся авторизованной
static int auth_any(int s,int block,uint8_t*uid,uint8_t*ul){
    struct{uint8_t code;const uint8_t*k;} cand[]={
        {0x60,dA[s]},{0x60,FF},{0x60,tA[s]},{0x61,dB[s]},{0x61,FF}};
    for(int i=0;i<5;i++){
        if(!do_select(uid,ul)) continue;                 // свежий select перед каждым ключом
        if(try_auth(block,cand[i].code,cand[i].k,uid,*ul)) return 1;
        nfc_initiator_deselect_target(pnd);              // неудачный auth -> карта halt, сброс
    }
    return 0;
}
static int write_block(int block,const uint8_t*data){
    uint8_t cmd[18],resp[264]; cmd[0]=0xA0; cmd[1]=block; memcpy(cmd+2,data,16);
    return nfc_initiator_transceive_bytes(pnd,cmd,18,resp,sizeof(resp),0)>=0;
}
static int read_block(int block,uint8_t*out){
    uint8_t cmd[2]={0x30,(uint8_t)block},resp[264];
    int r=nfc_initiator_transceive_bytes(pnd,cmd,2,resp,sizeof(resp),0);
    if(r<16) return 0; memcpy(out,resp,16); return 1;
}

int main(void){
    FILE*f=fopen("target.mfd","rb"); fread(target,1,1024,f); fclose(f);
    f=fopen("fullkeys.mfd","rb"); uint8_t kb[1024]; fread(kb,1,1024,f); fclose(f);
    for(int s=0;s<16;s++){ memcpy(dA[s],kb+s*64+48,6); memcpy(dB[s],kb+s*64+58,6);
                           memcpy(tA[s],target+s*64+48,6); }
    nfc_init(&ctx); pnd=nfc_open(ctx,NULL); nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd,NP_EASY_FRAMING,true);
    nfc_device_set_property_bool(pnd,NP_AUTO_ISO14443_4,false);

    int okD=0,okT=0,fail=0;
    for(int s=0;s<16;s++){
        // порядок: сначала data-блоки, трейлер последним
        int order[4]={0,1,2,3}, start=(s==0)?1:0;        // сектор0 блок0 (manufacturer) не трогаем
        for(int oi=start;oi<4;oi++){
            int blk=s*4+order[oi]; int trailer=(order[oi]==3);
            const uint8_t*want=target+blk*16;
            int done=0;
            for(int att=0;att<8 && !done;att++){
                uint8_t uid[10],ul;
                if(!auth_any(s,blk,uid,&ul)) continue;
                if(!write_block(blk,want)){ nfc_initiator_deselect_target(pnd); continue; }
                if(trailer){ done=1; nfc_initiator_deselect_target(pnd); break; } // трейлер: verify пропускаем (ключи нечитаемы)
                // verify data-блока
                uint8_t rb[16];
                if(auth_any(s,blk,uid,&ul) && read_block(blk,rb) && memcmp(rb,want,16)==0) done=1;
                nfc_initiator_deselect_target(pnd);
            }
            if(done){ if(trailer) okT++; else okD++; }
            else { fail++; printf("  !! блок %2d (сектор %d) НЕ записан\n",blk,s); }
        }
    }
    printf("\nData-блоков записано+проверено: %d, трейлеров: %d, провалов: %d\n",okD,okT,fail);
    nfc_close(pnd); nfc_exit(ctx); return 0;
}
