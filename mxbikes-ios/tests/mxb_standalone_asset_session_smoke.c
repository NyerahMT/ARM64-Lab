#define _POSIX_C_SOURCE 200809L
#include "mxb_standalone_asset_session.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#define B UINT64_C(0x140000000)
#define SIZE UINT64_C(1751015009)
static uint8_t guest[65536];
static int valid(void *c,uint64_t a,size_t n){(void)c;return a>=B&&n<=sizeof(guest)&&a-B<=sizeof(guest)-n;}
static int rd(void *c,uint64_t a,uint8_t *p,size_t n){if(!valid(c,a,n))return 0;memcpy(p,guest+(a-B),n);return 1;}
static void wr(void *c,uint64_t a,const uint8_t *p,size_t n){(void)c;memcpy(guest+(a-B),p,n);}
#define F(name) mxb_files_dispatch(&f,&m,name,&r)
static int smoke(const char *path,const char *link){
    mxb_files f={0};mxb_asset_session s={0};mxb_crt_memory m={0,rd,valid,wr,0};mxb_crt_regs r={.rsp=B+8,.rcx=B,.rdx=B+128};
    if(!mxb_asset_session_init(&s,&f)||mxb_asset_session_init(&s,&f))return 1;
    if(mxb_asset_session_mount(&s,"tracks.pkz",path,SIZE-1)||s.count)return 2;
    if(mxb_asset_session_mount(&s,"tracks.pkz",link,SIZE)||s.count)return 3;
    if(mxb_asset_session_mount(&s,"tracks.pkz","/dev/null",UINT64_MAX)||s.count)return 4;
    if(!mxb_asset_session_mount(&s,"tracks.pkz",path,SIZE)||s.count!=1)return 5;
    if(mxb_asset_session_mount(&s,"TRACKS.PKZ",path,SIZE)||s.count!=1)return 6;
    if(mxb_asset_session_mount(&s,"../escape",path,SIZE)||s.count!=1)return 7;
    memcpy(guest,"tracks.pkz",11);memcpy(guest+128,"rb",3);
    if(F("fopen")!=1||!r.rax)return 8;
    uint64_t token=r.rax;
    r.rcx=token;r.rdx=(uint32_t)-8;r.r8=2;
    if(F("fseek")!=1||r.rax||F("ftell")!=1||r.rax!=SIZE-8)return 9;
    r.rcx=B+512;r.rdx=1;r.r8=16;r.r9=token;
    if(F("fread")!=1||r.rax!=8||memcmp(guest+512,"abcdefgh",8))return 10;
    r.rcx=token;if(F("feof")!=1||!r.rax)return 11;
    if(F("rewind")!=1||F("ferror")!=1||r.rax)return 12;
    r.rcx=B+512;r.rdx=1;r.r8=50000;r.r9=token;
    if(F("fread")!=1||r.rax!=50000)return 13;
    for(size_t i=0;i<50000;i++)if(guest[512+i])return 14;
    int savedfd=s.sources[0].fd;
    mxb_asset_session_close(&s);mxb_asset_session_close(&s);
    if(s.count||s.files||fcntl(savedfd,F_GETFD)!=-1)return 15;
    r.rcx=token;if(F("ftell")!=-1)return 16;
    if(!mxb_asset_session_init(&s,&f)||!mxb_asset_session_mount(&s,"tracks.pkz",path,SIZE))return 17;
    r.rcx=B;r.rdx=B+128;if(F("fopen")!=1||!r.rax||r.rax==token)return 18;
    token=r.rax;
    if(truncate(path,1))return 19;
    r.rcx=B+512;r.rdx=1;r.r8=8;r.r9=token;if(F("fread")!=1||r.rax)return 20;
    r.rcx=token;if(F("ferror")!=1||!r.rax||F("feof")!=1||r.rax)return 21;
    mxb_asset_session_close(&s);
    return 0;
}
int main(void){
    char path[]="/tmp/mxb-stream-XXXXXX",link[]="/tmp/mxb-link-XXXXXX";
    int fd=mkstemp(path);if(fd<0)return 100;
    int lfd=mkstemp(link);if(lfd<0){close(fd);unlink(path);return 101;}
    close(lfd);unlink(link);
    int result=102;
    if(!ftruncate(fd,(off_t)SIZE)&&pwrite(fd,"abcdefgh",8,(off_t)(SIZE-8))==8&&!symlink(path,link))result=smoke(path,link);
    close(fd);unlink(link);unlink(path);
    if(result)fprintf(stderr,"asset session checkpoint %d failed\n",result);
    return result;
}
