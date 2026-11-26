/* Native C case conversion contract, without game bytes. */
#include "mxb_standalone_memory.h"
#define BASE UINT64_C(0x140000000)
static uint8_t memory[8192];
static size_t write_limit=sizeof(memory);
static unsigned writes;
static int valid(uint64_t a,size_t n,size_t cap){
    return a>=BASE&&n<=cap&&a-BASE<=cap-n;
}
static int read(void *ctx,uint64_t a,uint8_t *out,size_t n){
    (void)ctx;if(!valid(a,n,sizeof(memory)))return 0;
    for(size_t i=0;i<n;i++)out[i]=memory[a-BASE+i];
    return 1;
}
static int writable(void *ctx,uint64_t a,size_t n){
    (void)ctx;return valid(a,n,write_limit);
}
static void write(void *ctx,uint64_t a,const uint8_t *src,size_t n){
    (void)ctx;writes++;for(size_t i=0;i<n;i++)memory[a-BASE+i]=src[i];
}
static int equal(const char *s){
    for(size_t i=0;;i++){
        if(memory[i]!=(uint8_t)s[i])return 0;
        if(!s[i])return 1;
    }
}
static void set(const char*s){
    for(size_t i=0;;i++){memory[i]=(uint8_t)s[i];if(!s[i])break;}
}
int main(void){
    mxb_crt_memory m={0,read,writable,write,0};
    mxb_crt_regs r={BASE,0,0,0,BASE+8,99};
#define CALL(s) mxb_memory_dispatch(&m,s,&r)
    set("aBc-Z 123 _");
    if(CALL("_strupr")!=1||r.rax!=BASE||!equal("ABC-Z 123 _")||writes!=1)return 1;
    if(CALL("_strlwr")!=1||r.rax!=BASE||!equal("abc-z 123 _")||writes!=2)return 2;
    memory[0]=0;if(CALL("_strupr")!=1||memory[0]||writes!=3)return 3;
    for(size_t i=0;i<4095;i++)memory[i]='a';
    memory[4095]=0;
    if(CALL("_strupr")!=1||writes!=4)return 4;
    for(size_t i=0;i<4095;i++)if(memory[i]!='A')return 5;
    memory[4095]='a';r.rax=99;
    if(CALL("_strlwr")!=-1||writes!=4||r.rax!=99||memory[0]!='A')return 6;
    set("abc");memory[2]=128;
    if(CALL("_strupr")!=-1||writes!=4||memory[0]!='a'||r.rax!=99)return 7;
    set("abc");write_limit=3;
    if(CALL("_strupr")!=-1||writes!=4||!equal("abc")||r.rax!=99)return 8;
    write_limit=sizeof(memory);
    r.rcx=BASE+sizeof(memory)-1;memory[sizeof(memory)-1]='z';
    if(CALL("_strupr")!=-1||writes!=4||r.rax!=99)return 9;
    r.rcx=BASE;r.rsp=BASE+16;
    if(CALL("_strupr")!=-1||writes!=4||r.rax!=99)return 10;
    r.rsp=BASE+8;r.rcx=0;
    if(CALL("_strupr")!=-1||writes!=4||r.rax!=99)return 11;
    return 0;
}
