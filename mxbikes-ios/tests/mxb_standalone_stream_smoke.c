#include "mxb_standalone_files.h"
#define B UINT64_C(0x140000000)
#define TRACK_SIZE UINT64_C(1751015009)
static uint8_t guest[65536];
static unsigned calls,writes;static uint64_t bad=UINT64_MAX;
static int valid(void *c,uint64_t a,size_t n){(void)c;return a>=B&&n<=sizeof(guest)&&a-B<=sizeof(guest)-n;}
static int rd(void *c,uint64_t a,uint8_t *p,size_t n){if(!valid(c,a,n))return 0;for(size_t i=0;i<n;i++)p[i]=guest[a-B+i];return 1;}
static void wr(void *c,uint64_t a,const uint8_t *p,size_t n){(void)c;writes++;for(size_t i=0;i<n;i++)guest[a-B+i]=p[i];}
static int backing(void *c,uint64_t offset,uint8_t *p,size_t n){(void)c;calls++;if(n>MXB_FILE_CHUNK||offset>TRACK_SIZE||n>TRACK_SIZE-offset||offset>=bad)return 0;for(size_t i=0;i<n;i++)p[i]=(uint8_t)(offset+i);return 1;}
static void str(uint8_t *p,const char *s){while((*p++=(uint8_t)*s++));}
#define F(name) mxb_files_dispatch(&f,&m,name,&r)
int smoke(void){
    mxb_files f={0};mxb_crt_memory m={0,rd,valid,wr,0};mxb_crt_regs r={.rsp=B+8,.rcx=B+16,.rdx=B+150};
    static const uint8_t ini[]="hello\nworld";
    if(!mxb_files_mount_source(&f,"tracks.pkz",TRACK_SIZE,backing,0)||!mxb_files_mount(&f,"core.ini",ini,sizeof(ini)-1))return 1;
    if(mxb_files_mount_source(&f,"TRACKS.PKZ",1,backing,0)||mxb_files_mount_source(&f,"../x",1,backing,0)||mxb_files_mount_source(&f,"too-large",MXB_FILE_MAX+1,backing,0))return 2;
    str(guest+16,"TRACKS.PKZ");str(guest+150,"rb");if(F("fopen")!=1||!r.rax||calls)return 3;
    uint64_t h=r.rax;
    if(F("fopen")!=1||r.rax==h)return 4;
    uint64_t h2=r.rax;
    r.rcx=h;r.rdx=(uint32_t)-8;r.r8=2;if(F("fseek")!=1||r.rax||F("ftell")!=1||r.rax!=TRACK_SIZE-8)return 5;
    r.rcx=B+512;r.rdx=4;r.r8=3;r.r9=h;if(F("fread")!=1||r.rax!=2||calls!=1||guest[512]!=(uint8_t)(TRACK_SIZE-8)||guest[519]!=(uint8_t)(TRACK_SIZE-1))return 6;
    r.rcx=h;if(F("feof")!=1||!r.rax||F("ferror")!=1||r.rax)return 7;
    r.rcx=h2;if(F("ftell")!=1||r.rax)return 8;
    r.rcx=h;if(F("clearerr")!=1||F("feof")!=1||r.rax)return 9;
    if(F("fgetc")!=1||r.rax!=UINT32_MAX||F("feof")!=1||!r.rax)return 10;
    if(F("rewind")!=1||F("ftell")!=1||r.rax||F("feof")!=1||r.rax)return 11;
    r.rcx=B+512;r.rdx=1;r.r8=MXB_FILE_CHUNK*2+5;r.r9=h;unsigned before=calls;
    if(F("fread")!=1||r.rax!=MXB_FILE_CHUNK*2+5||calls-before!=3||guest[512+MXB_FILE_CHUNK*2+4]!=4)return 12;
    r.rcx=h;if(F("rewind")!=1)return 13;bad=MXB_FILE_CHUNK;
    r.rcx=B+512;r.rdx=3;r.r8=MXB_FILE_CHUNK;r.r9=h;
    if(F("fread")!=1||r.rax!=MXB_FILE_CHUNK/3)return 14;
    r.rcx=h;if(F("ftell")!=1||r.rax!=MXB_FILE_CHUNK||F("ferror")!=1||!r.rax||F("feof")!=1||r.rax)return 15;
    r.rdx=0;r.r8=0;if(F("fseek")!=1||F("ferror")!=1||!r.rax)return 16;
    if(F("rewind")!=1||F("ferror")!=1||r.rax)return 17;
    bad=UINT64_MAX;r.rcx=B+65530;r.rdx=1;r.r8=7;r.r9=h;before=calls;unsigned w=writes;
    if(F("fread")!=-1||calls!=before||writes!=w)return 18;
    r.rcx=h;if(F("ftell")!=1||r.rax)return 19;
    r.rcx=B+512;r.rdx=UINT64_MAX;r.r8=2;r.r9=h;if(F("fread")!=-1)return 20;
    r.rcx=h;r.rdx=INT32_MAX;r.r8=0;if(F("fseek")!=1||r.rax||F("ftell")!=1||r.rax!=INT32_MAX)return 21;
    r.rdx=1;r.r8=1;if(F("fseek")!=1||r.rax!=UINT32_MAX||F("ftell")!=1||r.rax!=INT32_MAX)return 22;
    if(F("fclose")!=1||F("ferror")!=-1)return 23;
    str(guest+16,"core.ini");r.rcx=B+16;r.rdx=B+150;if(F("fopen")!=1||r.rax==h)return 24;
    h=r.rax;
    r.rcx=B+512;r.rdx=32;r.r8=h;if(F("fgets")!=1||guest[517]!='\n'||guest[518])return 25;
    r.rcx=h;if(F("fgetc")!=1||r.rax!='w')return 26;
    r.rcx=B+512;r.rdx=32;r.r8=h;if(F("fgets")!=1||guest[512]!='o'||guest[515]!='d'||guest[516])return 27;
    r.rcx=h;if(F("feof")!=1||!r.rax||F("rewind")!=1||F("ferror")!=1||r.rax)return 28;
    r.rcx=h2;if(F("fclose")!=1)return 29;
    r.rcx=h;if(F("fclose")!=1)return 30;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
