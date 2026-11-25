#include "mxb_standalone_winmain.h"
#define S UINT64_C(0x700000108)
#define C UINT64_C(0x112233445566)
#define G UINT64_C(0x760000800)
#define A UINT64_C(0x14034302c)
static int same(const uint8_t *a,const uint8_t *b,size_t n){for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
int smoke(void){
    mxb_winmain_prefix r;
    uint8_t cmd[]="  \"one two\" three";
    if(!mxb_winmain_prepare(&r,S,C,7,9,10,G,A,cmd,sizeof(cmd)))return 1;
    if(r.frame_rsp!=S-0x288||r.saved_cookie!=(C^r.frame_rsp)||r.instance!=7||r.previous_instance!=9||r.show!=10)return 2;
    if(r.argc!=3||r.argv[0]!=A||r.argv[1]!=G+3||r.argv[2]!=G+12)return 3;
    if(!same(cmd,(const uint8_t*)"  \"one two\0\0three",sizeof(cmd)))return 4;
    uint8_t unmatched[]="\"one two";
    if(!mxb_winmain_prepare(&r,S,C,0,0,0,G,A,unmatched,sizeof(unmatched))||r.argc!=3||r.argv[1]!=G||r.argv[2]!=G+5)return 5;
    uint8_t adjacent[]="\"a\"bc d";
    if(!mxb_winmain_prepare(&r,S,C,0,0,0,G,A,adjacent,sizeof(adjacent))||r.argc!=4||r.argv[1]!=G+1||r.argv[2]!=G+4||r.argv[3]!=G+6||adjacent[3])return 6;
    uint8_t high[]={0x80,'a',0xff,'b',0};
    if(!mxb_winmain_prepare(&r,S,C,0,0,0,G,A,high,sizeof(high))||r.argc!=3||r.argv[1]!=G+1||r.argv[2]!=G+3||high[2])return 7;
    uint8_t many[261];for(size_t i=0;i<260;i++)many[i]=(i&1)?' ':'a';many[260]=0;
    if(!mxb_winmain_prepare(&r,S,C,0,0,0,G,A,many,sizeof(many))||r.argc!=128||r.argv[127]!=G+252||many[255]!=' ')return 8;
    uint8_t invalid[]={'a','b'};
    if(mxb_winmain_prepare(&r,S,C,0,0,0,G,A,invalid,sizeof(invalid))||r.argc!=128||invalid[1]!='b')return 9;
    uint8_t empty[]={0};
    if(!mxb_winmain_prepare(&r,S,C,0,0,0,G,A,empty,sizeof(empty))||r.argc!=1)return 10;
    if(mxb_winmain_prepare(&r,S+1,C,0,0,0,G,A,empty,sizeof(empty)))return 11;
    uint8_t path[260]={0};
    if(!mxb_winmain_module_directory(path,sizeof(path),(const uint8_t*)"C:/foo\\game.exe",16)||!same(path,(const uint8_t*)"C:/foo\\\0ame.exe",16))return 12;
    if(!mxb_winmain_module_directory(path,sizeof(path),(const uint8_t*)"a:b:c",6)||!same(path,(const uint8_t*)"a:b:\\",6))return 13;
    if(!mxb_winmain_module_directory(path,sizeof(path),(const uint8_t*)"game.exe",9)||path[0]||path[1]!='a')return 14;
    if(mxb_winmain_module_directory(path,259,(const uint8_t*)"C:",3)||path[1]!='a')return 15;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
