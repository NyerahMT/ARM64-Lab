#include "mxb_standalone_format.h"
#define CAP 1024u
static int eq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int readstr(const mxb_crt_memory *m,uint64_t p,uint8_t *s,size_t cap){
    if(!p||p>UINT64_MAX-cap)return 0;
    for(size_t i=0;i<cap;i++){if(!m->read(m->ctx,p+i,s+i,1))return 0;if(!s[i])return 1;}return 0;
}
static int arg(const mxb_crt_memory *m,const mxb_crt_regs *r,unsigned i,uint64_t *v){
    if(i==0){*v=r->r8;return 1;}if(i==1){*v=r->r9;return 1;}
    if(i>=16||r->rsp>UINT64_MAX-160u)return 0;
    uint8_t b[8];if(!m->read(m->ctx,r->rsp+40u+8u*(i-2u),b,8))return 0;
    *v=0;for(unsigned j=8;j;j--)*v=(*v<<8)|b[j-1];return 1;
}
static int append(uint8_t *b,size_t *n,uint8_t ch){if(*n>=CAP-1u)return 0;b[(*n)++]=ch;return 1;}
int mxb_format_dispatch(const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    if(!eq(name,"sprintf"))return 0;
    if(!m||!m->read||!m->writable||!m->write||!r||(r->rsp&15u)!=8u)return -1;
    uint8_t fmt[256],buf[CAP],str[CAP];size_t n=0;unsigned index=0;
    if(!readstr(m,r->rdx,fmt,sizeof(fmt)))return -1;
    for(size_t i=0;fmt[i];i++){
        uint8_t c=fmt[i];if(c!='%'){if(!append(buf,&n,c))return -1;continue;}
        c=fmt[++i];if(c=='%'){if(!append(buf,&n,c))return -1;continue;}
        /* Windows long is 32-bit. No flags, width, precision, or ll modifier. */
        int islong=c=='l';if(islong)c=fmt[++i];
        if(c!='u'&&c!='d'&&c!='i'&&c!='x'&&c!='X'&&c!='s'&&c!='c')return 0;
        if(islong&&(c=='s'||c=='c'))return 0;
        uint64_t value;if(!arg(m,r,index++,&value))return -1;
        if(c=='s'){
            if(!readstr(m,value,str,sizeof(str)))return -1;
            for(size_t j=0;str[j];j++)if(!append(buf,&n,str[j]))return -1;
        }else if(c=='c'){
            if(!append(buf,&n,(uint8_t)value))return -1;
        }else{
            uint32_t v=(uint32_t)value,radix=(c=='x'||c=='X')?16u:10u;uint8_t digits[16];size_t k=0;
            if((c=='d'||c=='i')&&(v&0x80000000u)){if(!append(buf,&n,'-'))return -1;v=0u-v;}
            do{unsigned d=v%radix;digits[k++]=(uint8_t)(d<10?'0'+d:(c=='X'?'A':'a')+d-10);v/=radix;}while(v);
            while(k)if(!append(buf,&n,digits[--k]))return -1;
        }
    }
    buf[n]=0;
    if(!r->rcx||r->rcx>UINT64_MAX-(n+1u)||!m->writable(m->ctx,r->rcx,n+1u))return -1;
    m->write(m->ctx,r->rcx,buf,n+1u);r->rax=n;return 1;
}
