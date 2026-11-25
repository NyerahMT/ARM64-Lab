#include "mxb_standalone_platform.h"
static uint8_t upper(uint8_t c){return c>='a'&&c<='z'?(uint8_t)(c-32):c;}
static int sep(uint8_t c){return c=='/'||c=='\\';}
static void copy(uint8_t *d,const uint8_t *s,size_t n){for(size_t i=0;i<n;i++)d[i]=s[i];}
static size_t len(const uint8_t *s){size_t n=0;while(n<MXB_PATH_CAP&&s[n])n++;return n;}
/* Canonicalize absolute, ASCII DOS paths only. No dot segments,
 * UNC, drive-relative paths, host paths, or unsupported NT namespaces. */
static int normalize(uint8_t *out,const uint8_t *in,size_t n){
    if(!in||n<4||n>MXB_PATH_CAP||in[n-1]||upper(in[0])<'A'||upper(in[0])>'Z'||in[1]!=':'||!sep(in[2]))return 0;
    size_t w=3;out[0]=upper(in[0]);out[1]=':';out[2]='\\';
    for(size_t i=3;i<n-1;){
        while(i<n-1&&sep(in[i]))i++;
        if(i==n-1)break;
        size_t start=i;
        while(i<n-1&&!sep(in[i])){
            uint8_t c=in[i];
            if(c<33||c>126||c==':'||c=='*'||c=='?'||c=='"'||c=='<'||c=='>'||c=='|')return 0;
            i++;
        }
        if(in[i-1]=='.')return 0;
        if(w>3)out[w++]='\\';
        for(size_t j=start;j<i;j++)out[w++]=in[j];
    }
    out[w]=0;return 1;
}
static int eq(const uint8_t *a,const uint8_t *b){for(size_t i=0;i<MXB_PATH_CAP;i++){if(upper(a[i])!=upper(b[i]))return 0;if(!a[i])return 1;}return 0;}
int mxb_platform_init(mxb_platform *p,const uint8_t *root,size_t n,uint64_t ticks){
    if(!p)return 0;
    mxb_platform v={0};if(!normalize(v.root,root,n))return 0;
    /* The root's drive is also a known directory. */
    copy(v.cwd,v.root,len(v.root)+1);v.elapsed_ms=ticks;*p=v;return 1;
}
uint32_t mxb_platform_set_directory(mxb_platform *p,const uint8_t *path,size_t n){
    if(!p)return 0;
    uint8_t v[MXB_PATH_CAP]={0};if(!normalize(v,path,n)){p->last_error=123;return 0;}
    if(eq(v,p->root)){copy(p->cwd,p->root,len(p->root)+1);return 1;}
    if(v[0]==p->root[0]&&v[1]==':'&&v[2]=='\\'&&!v[3]){copy(p->cwd,v,4);return 1;}
    p->last_error=3;return 0;
}
uint32_t mxb_platform_get_directory(mxb_platform *p,uint8_t *out,size_t cap){
    if(!p)return 0;
    size_t n=len(p->cwd);if(!n||n==MXB_PATH_CAP)return 0;
    if(cap<=n)return (uint32_t)(n+1);
    if(!out){p->last_error=87;return 0;}
    copy(out,p->cwd,n+1);return (uint32_t)n;
}
int mxb_platform_advance(mxb_platform *p,uint64_t delta){if(!p||delta>UINT64_MAX-p->elapsed_ms)return 0;p->elapsed_ms+=delta;return 1;}
uint32_t mxb_platform_ticks(const mxb_platform *p){return p?(uint32_t)p->elapsed_ms:0;}
uint32_t mxb_platform_timer_begin(mxb_platform *p,uint32_t ms){if(!p||ms!=1||p->timer_refs==UINT32_MAX)return MXB_TIMER_NOCANDO;p->timer_refs++;return 0;}
uint32_t mxb_platform_timer_end(mxb_platform *p,uint32_t ms){if(!p||ms!=1||!p->timer_refs)return MXB_TIMER_NOCANDO;p->timer_refs--;return 0;}
