#include "mxb_standalone_files.h"
#define TOKEN_BASE UINT64_C(0x780000000)
static int eq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int readstr(const mxb_crt_memory *m,uint64_t a,char *s,size_t n){
    if(!m||!m->read||!a||a>UINT64_MAX-n)return 0;
    for(size_t i=0;i<n;i++){if(!m->read(m->ctx,a+i,(uint8_t *)s+i,1))return 0;if(!s[i])return 1;}return 0;
}
static int canonical(const char *s,char *out){
    if(!s)return 0;
    for(size_t i=0;i<MXB_FILE_NAME;i++){
        unsigned c=(unsigned char)s[i];
        if(!c){out[i]=0;return i&&out[0]!='.'&&out[i-1]!='.';}
        /* Flat ASCII asset namespace only: no directory separators or traversal. */
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;
        out[i]=(char)(c>='A'&&c<='Z'?c+32:c);
    }return 0;
}
int mxb_files_mount(mxb_files *f,const char *name,const uint8_t *data,uint64_t size){
    char normalized[MXB_FILE_NAME]={0};if(!f||!data||size>MXB_FILE_MAX||!canonical(name,normalized))return 0;
    unsigned free_slot=MXB_FILE_MOUNTS;
    for(unsigned i=0;i<MXB_FILE_MOUNTS;i++){
        if(!f->mounts[i].data){if(free_slot==MXB_FILE_MOUNTS)free_slot=i;}
        else if(eq(f->mounts[i].name,normalized))return 0;
    }
    if(free_slot==MXB_FILE_MOUNTS)return 0;
    mxb_file_mount *m=&f->mounts[free_slot];for(size_t i=0;i<MXB_FILE_NAME;i++)m->name[i]=normalized[i];m->data=data;m->size=size;return 1;
}
static mxb_file_handle *handle(mxb_files *f,uint64_t token){
    if(!token)return 0;
    for(unsigned i=0;i<MXB_FILE_HANDLES;i++)if(f->handles[i].token==token)return &f->handles[i];
    return 0;
}
int mxb_files_dispatch(mxb_files *f,const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    int open=eq(name,"fopen"),read=eq(name,"fread"),seek=eq(name,"fseek"),tell=eq(name,"ftell"),close=eq(name,"fclose"),eof=eq(name,"feof"),err=eq(name,"ferror"),gets=eq(name,"fgets");
    if(!open&&!read&&!seek&&!tell&&!close&&!eof&&!err&&!gets)return 0;
    if(!f||!r||(r->rsp&15u)!=8u)return -1;
    if(open){
        char path[MXB_FILE_NAME],mode[8],normalized[MXB_FILE_NAME];
        if(!readstr(m,r->rcx,path,sizeof(path))||!readstr(m,r->rdx,mode,sizeof(mode)))return -1;
        if(!eq(mode,"rb")||!canonical(path,normalized))return 0;
        unsigned i=0;while(i<MXB_FILE_MOUNTS&&(!f->mounts[i].data||!eq(f->mounts[i].name,normalized)))i++;
        if(i==MXB_FILE_MOUNTS)return 0; /* unknown asset: stop, do not invent absence */
        unsigned h=0;while(h<MXB_FILE_HANDLES&&f->handles[h].token)h++;
        if(h==MXB_FILE_HANDLES||f->generation>=UINT32_MAX){r->rax=0;return 1;}
        uint64_t token=TOKEN_BASE+(++f->generation)*16u;
        f->handles[h]=(mxb_file_handle){token,0,i,0};r->rax=token;return 1;
    }
    mxb_file_handle *h=handle(f,read?r->r9:gets?r->r8:r->rcx);
    if(!h||h->mount>=MXB_FILE_MOUNTS||!f->mounts[h->mount].data)return -1;
    mxb_file_mount *a=&f->mounts[h->mount];
    if(close){*h=(mxb_file_handle){0};r->rax=0;return 1;}
    if(tell){r->rax=h->pos;return 1;}
    if(eof){r->rax=h->eof;return 1;}
    if(err){r->rax=0;return 1;}
    if(seek){
        uint32_t origin=(uint32_t)r->r8;if(origin>2)return 0;
        int64_t pos=(int64_t)(origin==0?0:origin==1?h->pos:a->size)+(int32_t)(uint32_t)r->rdx;
        if(pos<0||pos>INT32_MAX){r->rax=UINT32_MAX;return 1;}
        h->pos=(uint64_t)pos;h->eof=0;r->rax=0;return 1;
    }
    uint64_t available=h->pos<a->size?a->size-h->pos:0;
    if(read){
        if(!r->rdx||!r->r8){r->rax=0;return 1;}
        if(r->r8>UINT64_MAX/r->rdx||r->rdx*r->r8>MXB_FILE_MAX)return -1;
        uint64_t want=r->rdx*r->r8,n=want<available?want:available;
        if(n&&(!m||!m->writable||!m->write||!r->rcx||r->rcx>UINT64_MAX-n||!m->writable(m->ctx,r->rcx,(size_t)n)))return -1;
        if(n)m->write(m->ctx,r->rcx,a->data+h->pos,(size_t)n);
        h->pos+=n;if(n<want)h->eof=1;r->rax=n/r->rdx;return 1;
    }
    /* fgets: binary stream, newline retained, NUL terminator; count>=2 only. */
    int32_t cap=(int32_t)(uint32_t)r->rdx;if(cap<2||cap>4096)return 0;
    if(!available){h->eof=1;r->rax=0;return 1;}
    uint8_t buf[4096];size_t n=0;
    while(n<(size_t)cap-1&&n<available){uint8_t c=a->data[h->pos+n];buf[n++]=c;if(c=='\n')break;}
    buf[n]=0;
    if(!m||!m->writable||!m->write||!r->rcx||r->rcx>UINT64_MAX-(n+1)||!m->writable(m->ctx,r->rcx,n+1))return -1;
    m->write(m->ctx,r->rcx,buf,n+1);h->pos+=n;if(n==available&&buf[n-1]!='\n'&&n<(size_t)cap-1)h->eof=1;r->rax=r->rcx;return 1;
}
