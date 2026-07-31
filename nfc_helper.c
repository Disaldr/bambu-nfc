// Низкоуровневый хелпер для тегов Bambu (MIFARE Classic 1K) через libnfc.
// Подкоманды:
//   uid                          -> печатает UID (антиколлизия), hex
//   probe   <keys1024>           -> UID + GENUINE/NOKEY (проверка KeyA сектора 0)
//   unlock  <keys1024>           -> сменить access-биты всех трейлеров на FF078069 (auth KeyB)
//   write   <target1024> <keys1024> -> надёжная запись образа (мультиключ + retry + verify)
//   read    <keys1024> <out1024> -> прочитать весь тег в файл (auth KeyA, fallback KeyB)
// Прогресс печатается в stdout построчно.
#include <nfc/nfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nfc_device *pnd; static nfc_context *ctx;
static const uint8_t FF[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const uint8_t MADK[6]={0xA0,0xA1,0xA2,0xA3,0xA4,0xA5};
static const uint8_t NDEFK[6]={0xD3,0xF7,0xD3,0xF7,0xD3,0xF7};

static int open_dev(void){
    nfc_init(&ctx); pnd=nfc_open(ctx,NULL);
    if(!pnd){ fprintf(stderr,"NFC-устройство не найдено\n"); return 0; }
    nfc_initiator_init(pnd);
    nfc_device_set_property_bool(pnd,NP_EASY_FRAMING,true);
    nfc_device_set_property_bool(pnd,NP_AUTO_ISO14443_4,false);
    return 1;
}
static void close_dev(void){ nfc_close(pnd); nfc_exit(ctx); }

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
static int write_block(int block,const uint8_t*data){
    uint8_t cmd[18],resp[264]; cmd[0]=0xA0; cmd[1]=block; memcpy(cmd+2,data,16);
    return nfc_initiator_transceive_bytes(pnd,cmd,18,resp,sizeof(resp),0)>=0;
}
static int read_block(int block,uint8_t*out){
    uint8_t cmd[2]={0x30,(uint8_t)block},resp[264];
    int r=nfc_initiator_transceive_bytes(pnd,cmd,2,resp,sizeof(resp),0);
    if(r<16) return 0; memcpy(out,resp,16); return 1;
}
static int load(const char*path,uint8_t*buf){
    FILE*f=fopen(path,"rb"); if(!f) return 0;
    size_t n=fread(buf,1,1024,f); fclose(f); return n==1024;
}

// ---- команды ----
static int cmd_uid(void){
    uint8_t uid[10],ul;
    for(int i=0;i<10;i++){ if(do_select(uid,&ul)){
        for(int j=0;j<ul;j++) printf("%02X",uid[j]); printf("\n");
        nfc_initiator_deselect_target(pnd); return 0; } }
    return 1;
}
static int cmd_probe(uint8_t*K){
    uint8_t uid[10],ul; if(!do_select(uid,&ul)){ printf("NOTAG\n"); return 1; }
    int ok=try_auth(3,0x60,K+48,uid,ul);
    for(int j=0;j<ul;j++) printf("%02X",uid[j]);
    printf(" %s\n", ok?"GENUINE":"NOKEY");
    nfc_initiator_deselect_target(pnd); return ok?0:2;
}
// diag: определить, каким ключом открывается каждый сектор и его access-биты
static int cmd_diag(uint8_t*K){
    for(int s=0;s<16;s++){
        int trailer=s*4+3;
        struct{uint8_t code;const uint8_t*k;const char*lbl;} c[]={
            {0x60,K+s*64+48,"bambuA"},{0x61,K+s*64+58,"bambuB"},
            {0x60,FF,"default"},{0x60,MADK,"mad"},{0x60,NDEFK,"ndef"}};
        int found=-1,haveacc=0; uint8_t acc[4]={0};
        for(int i=0;i<5;i++){
            uint8_t uid[10],ul; if(!do_select(uid,&ul)) continue;
            if(try_auth(trailer,c[i].code,c[i].k,uid,ul)){
                uint8_t rb[16];
                if(read_block(trailer,rb)){ memcpy(acc,rb+6,4); haveacc=1; }
                nfc_initiator_deselect_target(pnd); found=i; break;
            }
            nfc_initiator_deselect_target(pnd);
        }
        if(found<0) printf("sector %2d NONE ????????\n",s);
        else if(haveacc) printf("sector %2d %s %02X%02X%02X%02X\n",s,c[found].lbl,acc[0],acc[1],acc[2],acc[3]);
        else            printf("sector %2d %s ????????\n",s,c[found].lbl);
        fflush(stdout);
    }
    return 0;
}
static int cmd_unlock(uint8_t*K){
    int ok=0;
    for(int s=0;s<16;s++){
        int trailer=s*4+3, done=0;
        for(int att=0;att<6 && !done;att++){
            uint8_t uid[10],ul; if(!do_select(uid,&ul)) continue;
            if(!try_auth(trailer,0x61,K+s*64+58,uid,ul)){ nfc_initiator_deselect_target(pnd); continue; }
            uint8_t t[16]; memcpy(t,K+s*64+48,6);
            t[6]=0xFF;t[7]=0x07;t[8]=0x80;t[9]=0x69; memcpy(t+10,K+s*64+58,6);
            if(write_block(trailer,t)) done=1;
            nfc_initiator_deselect_target(pnd);
        }
        printf("unlock sector %2d %s\n", s, done?"OK":"FAIL"); fflush(stdout);
        if(done) ok++;
    }
    return ok==16?0:1;
}
// мультиключевая авторизация (перебор кандидатов с переселектом); при успехе карта авторизована
static int auth_any(uint8_t*K,uint8_t*T,int s,int block,uint8_t*uid,uint8_t*ul){
    struct{uint8_t code;const uint8_t*k;} c[]={
        {0x60,K+s*64+48},{0x60,FF},{0x60,T+s*64+48},{0x61,K+s*64+58},{0x61,FF}};
    for(int i=0;i<5;i++){
        if(!do_select(uid,ul)) continue;
        if(try_auth(block,c[i].code,c[i].k,uid,*ul)) return 1;
        nfc_initiator_deselect_target(pnd);
    }
    return 0;
}
// пишет один блок, перебирая ключи, пока не пройдёт именно ЗАПИСЬ (не только auth)
// stage (для отладки): 0=нет select, 1=auth не прошёл, 2=write не прошёл, 3=verify не прошёл, 4=OK
static int write_one(uint8_t*K,uint8_t*T,int s,int blk,const uint8_t*want,int trailer,int*stage){
    struct{uint8_t code;const uint8_t*k;} c[]={
        {0x60,K+s*64+48},{0x61,K+s*64+58},{0x61,FF},{0x60,FF},
        {0x60,T+s*64+48},{0x61,MADK},{0x61,NDEFK},{0x60,MADK},{0x60,NDEFK}};
    int NC=sizeof(c)/sizeof(c[0]); int best=0;
    for(int att=0;att<3;att++){
        for(int i=0;i<NC;i++){
            uint8_t uid[10],ul; if(!do_select(uid,&ul)) continue;
            if(!try_auth(blk,c[i].code,c[i].k,uid,ul)){ nfc_initiator_deselect_target(pnd); if(best<1)best=1; continue; }
            if(best<2)best=2;
            if(!write_block(blk,want)){ nfc_initiator_deselect_target(pnd); continue; }
            if(best<3)best=3;
            if(trailer){ nfc_initiator_deselect_target(pnd); *stage=4; return 1; } // трейлер: verify пропускаем
            uint8_t rb[16]; int good=0;                 // verify в ТОЙ ЖЕ сессии (без reselect)
            if(read_block(blk,rb) && memcmp(rb,want,16)==0) good=1;
            nfc_initiator_deselect_target(pnd);
            if(good){ *stage=4; return 1; }
        }
    }
    *stage=best; return 0;
}
static int cmd_write(uint8_t*T,uint8_t*K){
    int fail=0, dbg=getenv("BAMBU_DBG")!=NULL;
    const char*SN[]={"no-select","auth-fail","write-fail","verify-fail","OK"};
    for(int s=0;s<16;s++){
        int start=(s==0)?1:0, wrote=0;              // сектор0 блок0 не трогаем
        for(int oi=start;oi<4;oi++){                // data-блоки раньше трейлера
            int blk=s*4+oi, stage=0;
            if(write_one(K,T,s,blk,T+blk*16,(oi==3),&stage)) wrote++; else fail++;
            if(dbg) printf("  blk %2d (%s): %s\n", blk, (oi==3)?"trailer":"data", SN[stage]);
        }
        printf("write sector %2d (%d блоков)\n", s, wrote); fflush(stdout);
    }
    return fail?1:0;
}
static int cmd_read(uint8_t*K,const char*out){
    uint8_t dump[1024]; memset(dump,0,sizeof(dump)); int fail=0;
    for(int s=0;s<16;s++){
        int oks=0;
        for(int b=0;b<4;b++){
            int blk=s*4+b, done=0;
            for(int att=0;att<6 && !done;att++){
                uint8_t uid[10],ul;
                if(!auth_any(K,K,s,blk,uid,&ul)) continue;
                uint8_t rb[16];
                if(read_block(blk,rb)){ memcpy(dump+blk*16,rb,16); done=1; }
                nfc_initiator_deselect_target(pnd);
            }
            if(done) oks++; else fail++;
        }
        printf("read sector %2d (%d/4)\n", s, oks); fflush(stdout);
    }
    FILE*f=fopen(out,"wb"); fwrite(dump,1,1024,f); fclose(f);
    return fail?1:0;
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: nfc_helper uid|diag|probe|unlock|write|read ...\n"); return 2; }
    if(!open_dev()) return 3;
    int rc=2; uint8_t K[1024],T[1024];
    if(!strcmp(argv[1],"uid"))                    rc=cmd_uid();
    else if(!strcmp(argv[1],"diag")   && argc>=3 && load(argv[2],K)) rc=cmd_diag(K);
    else if(!strcmp(argv[1],"probe")  && argc>=3 && load(argv[2],K)) rc=cmd_probe(K);
    else if(!strcmp(argv[1],"unlock") && argc>=3 && load(argv[2],K)) rc=cmd_unlock(K);
    else if(!strcmp(argv[1],"write")  && argc>=4 && load(argv[2],T)&&load(argv[3],K)) rc=cmd_write(T,K);
    else if(!strcmp(argv[1],"read")   && argc>=4 && load(argv[2],K)) rc=cmd_read(K,argv[3]);
    else fprintf(stderr,"неверные аргументы\n");
    close_dev(); return rc;
}
