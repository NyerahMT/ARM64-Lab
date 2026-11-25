#include "mxb_standalone_platform.h"
#define P(s) (const uint8_t *)(s),sizeof(s)
static int same(const uint8_t *a,const char *b){size_t i=0;for(;b[i];i++)if(a[i]!=(uint8_t)b[i])return 0;return !a[i];}
int smoke(void){
    mxb_platform p={0};uint8_t out[260]={0};
    if(!mxb_platform_init(&p,P("C:\\MXBReference\\"),0xfffffffeu))return 1;
    if(!same(p.cwd,"C:\\MXBReference"))return 2;
    if(mxb_platform_get_directory(&p,out,260)!=15||!same(out,"C:\\MXBReference"))return 3;
    out[0]=99;if(mxb_platform_get_directory(&p,out,15)!=16||out[0]!=99)return 4;
    if(!mxb_platform_set_directory(&p,P("c:/mxbREFERENCE//"))||!same(p.cwd,"C:\\MXBReference"))return 5;
    if(!mxb_platform_set_directory(&p,P("c:/"))||!same(p.cwd,"C:\\"))return 6;
    if(mxb_platform_set_directory(&p,P("C:\\missing"))||p.last_error!=3||!same(p.cwd,"C:\\"))return 7;
    if(mxb_platform_set_directory(&p,P("C:\\..\\MXBReference"))||p.last_error!=123)return 8;
    if(mxb_platform_set_directory(&p,P("C:MXBReference"))||p.last_error!=123)return 9;
    if(mxb_platform_set_directory(&p,P("\\\\server\\share")))return 10;
    if(mxb_platform_set_directory(&p,P("C:\\MXBReference\\.")))return 11;
    if(mxb_platform_set_directory(&p,P("C:\\x*y")))return 12;
    if(!mxb_platform_set_directory(&p,P("C:\\MXBReference"))||p.last_error!=123)return 13;
    if(mxb_platform_get_directory(&p,0,0)!=16)return 14;
    if(mxb_platform_get_directory(&p,0,260)||p.last_error!=87)return 15;
    if(!mxb_platform_advance(&p,3)||mxb_platform_ticks(&p)!=1)return 16;
    if(mxb_platform_advance(&p,UINT64_MAX)||mxb_platform_ticks(&p)!=1)return 17;
    if(mxb_platform_timer_begin(&p,2)!=97||p.timer_refs)return 18;
    if(mxb_platform_timer_begin(&p,1)||mxb_platform_timer_begin(&p,1)||p.timer_refs!=2)return 19;
    if(mxb_platform_timer_end(&p,1)||p.timer_refs!=1)return 20;
    if(mxb_platform_timer_end(&p,2)!=97||p.timer_refs!=1)return 21;
    if(mxb_platform_timer_end(&p,1)||mxb_platform_timer_end(&p,1)!=97)return 22;
    p.timer_refs=UINT32_MAX;if(mxb_platform_timer_begin(&p,1)!=97||p.timer_refs!=UINT32_MAX)return 23;
    if(mxb_platform_init(&p,P("bad"),0)||!same(p.root,"C:\\MXBReference"))return 24;
    const uint8_t embedded[]={'C',':','\\','x',0,'y',0};
    if(mxb_platform_set_directory(&p,embedded,sizeof embedded))return 25;
    return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
