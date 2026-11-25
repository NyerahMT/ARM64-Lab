#include "mxb_standalone_winsock.h"
static int eq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int named(const char *n,const char *a,const char *b){return eq(n,a)||eq(n,b);}
static size_t format4(uint8_t *text,const uint8_t *addr){
    size_t n=0;
    for(unsigned i=0;i<4;i++){
        unsigned v=addr[i];if(i)text[n++]='.';
        if(v>=100)text[n++]=(uint8_t)('0'+v/100);
        if(v>=10)text[n++]=(uint8_t)('0'+(v/10)%10);
        text[n++]=(uint8_t)('0'+v%10);
    }text[n++]=0;return n;
}
static void put(uint8_t *p,uint64_t v,size_t n){for(size_t i=0;i<n;i++){p[i]=(uint8_t)v;v>>=8;}}
int mxb_winsock_dispatch(mxb_winsock *s,mxb_heap *heap,const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    if(!s||!r)return -1;
    if(named(name,"WSAStartup","#115")){
        uint16_t v=(uint16_t)r->rcx;
        if((v&255u)!=2u){r->rax=10092u;return 1;}
        if(v>0x202u)v=0x202u;
        if(s->refs==UINT32_MAX){r->rax=10091u;return 1;}
        /* Win64 WSADATA: four WORDs, pointer, 257+129 chars, padding. */
        uint8_t data[408]={0};
        if(!m||!m->writable||!m->write||!r->rdx||r->rdx>UINT64_MAX-sizeof(data)||
           !m->writable(m->ctx,r->rdx,sizeof(data))){r->rax=10014u;return 1;}
        data[0]=(uint8_t)v;data[1]=(uint8_t)(v>>8);data[2]=2;data[3]=2;
        const char description[]="MXB offline Winsock compatibility";
        const char status[]="No network transport";
        for(size_t i=0;i<sizeof(description);i++)data[16+i]=(uint8_t)description[i];
        for(size_t i=0;i<sizeof(status);i++)data[273+i]=(uint8_t)status[i];
        m->write(m->ctx,r->rdx,data,sizeof(data));s->refs++;r->rax=0;return 1;
    }
    if(named(name,"WSACleanup","#116")){
        if(!s->refs){s->last_error=10093u;r->rax=UINT32_MAX;return 1;}
        s->refs--;r->rax=0;return 1;
    }
    if(named(name,"WSAGetLastError","#111")){r->rax=s->last_error;return 1;}
    if(named(name,"WSASetLastError","#112")){s->last_error=(uint32_t)r->rcx;return 1;}
    uint32_t v=(uint32_t)r->rcx;
    if(named(name,"htonl","#8")||named(name,"ntohl","#14")){
        r->rax=((v&255u)<<24)|((v&0xff00u)<<8)|((v>>8)&0xff00u)|(v>>24);return 1;}
    if(named(name,"htons","#9")||named(name,"ntohs","#15")){
        r->rax=((v&255u)<<8)|((v>>8)&255u);return 1;}
    if(eq(name,"inet_pton")){
        if((uint32_t)r->rcx!=2u)return 0; /* AF_INET only */
        uint8_t text[16],addr[4];size_t n=0;
        if(!m||!m->read||!r->rdx||r->rdx>UINT64_MAX-16u)return -1;
        for(;n<sizeof(text);n++){if(!m->read(m->ctx,r->rdx+n,text+n,1))return -1;if(!text[n])break;}
        if(n==sizeof(text)){r->rax=0;return 1;}
        size_t i=0;
        for(unsigned part=0;part<4;part++){
            unsigned x=0,k=0;
            while(i<n&&text[i]>='0'&&text[i]<='9'){
                if(++k>3||(k>1&&text[i-k+1]=='0')){r->rax=0;return 1;}
                x=x*10u+text[i++]-'0';
            }
            if(!k||x>255u||(part<3?(i==n||text[i]!='.'):i!=n)){r->rax=0;return 1;}
            addr[part]=(uint8_t)x;if(part<3)i++;
        }
        if(!m->writable||!m->write||!r->r8||r->r8>UINT64_MAX-4u||!m->writable(m->ctx,r->r8,4))return -1;
        m->write(m->ctx,r->r8,addr,4);r->rax=1;return 1;
    }
    if(eq(name,"inet_ntop")){
        if((uint32_t)r->rcx!=2u)return 0;
        uint8_t addr[4],text[16];
        if(!m||!m->read||!r->rdx||r->rdx>UINT64_MAX-4u||!m->read(m->ctx,r->rdx,addr,4))return -1;
        size_t n=format4(text,addr);
        if(r->r9<n){s->last_error=10014u;r->rax=0;return 1;}
        if(!m->writable||!m->write||!r->r8||r->r8>UINT64_MAX-n||!m->writable(m->ctx,r->r8,n))return -1;
        m->write(m->ctx,r->r8,text,n);r->rax=r->r8;return 1;
    }
    if(eq(name,"getnameinfo")){
        /* Local-only name resolution: the loopback host, no DNS or service lookup. */
        uint8_t sa[16],stack[24];
        if(!m||!m->read||r->rdx<16u||r->rdx>128u||!r->rcx||r->rcx>UINT64_MAX-16u||
           r->rsp>UINT64_MAX-64u||!m->read(m->ctx,r->rcx,sa,16)||!m->read(m->ctx,r->rsp+40u,stack,24))return -1;
        for(size_t i=0;i<12;i++)if(stack[i])return 0;
        if(stack[17]||stack[18]||stack[19]||(stack[16]!=0&&stack[16]!=2)||sa[0]!=2||sa[1])return 0;
        uint8_t text[16];const uint8_t host[]="localhost";size_t n;
        if(stack[16]==2)n=format4(text,sa+4);
        else{
            if(sa[4]!=127||sa[5]||sa[6]||sa[7]!=1)return 0;
            n=sizeof(host);for(size_t i=0;i<n;i++)text[i]=host[i];
        }
        if((uint32_t)r->r9<n){r->rax=10014u;return 1;}
        if(!m->writable||!m->write||!r->r8||r->r8>UINT64_MAX-n||!m->writable(m->ctx,r->r8,n))return -1;
        m->write(m->ctx,r->r8,text,n);r->rax=0;return 1;
    }
    if(eq(name,"getaddrinfo")){
        /* The only configured local name is localhost, with one IPv4 record.
         * No service names, hints, DNS, or remote lookup. */
        const uint8_t local[]="localhost";uint8_t input[sizeof(local)];
        if(r->rdx||r->r8)return 0;
        if(!m||!m->read||!m->write||!m->writable||!heap||!r->rcx||r->rcx>UINT64_MAX-sizeof(local)||
           !r->r9||r->r9>UINT64_MAX-8u||!m->writable(m->ctx,r->r9,8))return -1;
        if(!m->read(m->ctx,r->rcx,input,sizeof(input)))return -1;
        for(size_t i=0;i<sizeof(local);i++)if(input[i]!=local[i])return 0;
        unsigned i=0;while(i<16&&s->results[i])i++;
        if(i==16){r->rax=8;return 1;}
        mxb_crt_regs alloc=*r;alloc.rcx=64;
        if(mxb_heap_dispatch(heap,m,"malloc",&alloc)!=1)return -1;
        if(!alloc.rax){r->rax=8;return 1;}
        uint64_t a=alloc.rax;
        if((r->r9<a+64&&a<r->r9+8)||!m->writable(m->ctx,a,64)){
            alloc.rcx=a;(void)mxb_heap_dispatch(heap,m,"free",&alloc);return -1;
        }
        uint8_t data[64]={0},out[8];put(data+4,2,4);put(data+16,16,8);put(data+32,a+48,8);
        data[48]=2;data[52]=127;data[55]=1;put(out,a,8);
        m->write(m->ctx,a,data,sizeof(data));m->write(m->ctx,r->r9,out,8);
        s->results[i]=a;r->rax=0;return 1;
    }
    if(eq(name,"freeaddrinfo")){
        if(!r->rcx)return 1;
        unsigned i=0;while(i<16&&s->results[i]!=r->rcx)i++;
        if(i==16||!heap||mxb_heap_dispatch(heap,m,"free",r)!=1)return -1;
        s->results[i]=0;return 1;
    }
    /* No fake socket handle or remote response. Stop at transport calls. */
    return 0;
}
