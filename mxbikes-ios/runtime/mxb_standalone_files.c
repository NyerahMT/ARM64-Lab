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
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;
        out[i]=(char)(c>='A'&&c<='Z'?c+32:c);
    }return 0;
}
static int active(const mxb_file_mount *m){return m->data||m->read_at;}
/* A missing loose directory is proven independently of its similarly named
 * archive. Accept only safe relative descendant paths; never query the host. */
static int absent_root(const mxb_files *f,const char *s){
    for(unsigned i=0;i<MXB_FILE_ABSENT_DIRS;i++)
        if(f->absent_dirs[i][0]&&eq(f->absent_dirs[i],s))return 1;
    return 0;
}
int mxb_files_mark_absent_directory(mxb_files *f,const char *s){
    char key[MXB_FILE_NAME]={0};
    if(!f||!canonical(s,key))return 0;
    for(size_t i=0;key[i];i++)
        if(!((key[i]>='a'&&key[i]<='z')||(key[i]>='0'&&key[i]<='9')))return 0;
    for(unsigned i=0;i<MXB_FILE_MOUNTS;i++)
        if(active(&f->mounts[i])&&eq(f->mounts[i].name,key))return 0;
    if(absent_root(f,key))return 1;
    for(unsigned i=0;i<MXB_FILE_ABSENT_DIRS;i++)if(!f->absent_dirs[i][0]){
        for(size_t j=0;j<MXB_FILE_NAME;j++)f->absent_dirs[i][j]=key[j];
        return 1;
    }
    return 0;
}
static int absent_descendant(const mxb_files *f,const char *path,int wildcard){
    char root[MXB_FILE_NAME]={0};size_t start=0,seg=0;int depth=0,has_wild=0;
    for(size_t i=0;i<MXB_FILE_NAME;i++){
        unsigned c=(unsigned char)path[i];
        if(!c||c=='/'||c=='\\'){
            if(!seg||path[start]==' '||path[i-1]==' '||path[i-1]=='.')return 0;
            if(seg==1&&path[start]=='.')return 0;
            if(seg==2&&path[start]=='.'&&path[start+1]=='.')return 0;
            if(!depth){
                if(!c||has_wild||!absent_root(f,root))return 0;
            }else if(has_wild&&c)return 0;
            if(!c)return depth>0;
            depth++;start=i+1;seg=0;has_wild=0;
            continue;
        }
        if(c=='*'||c=='?'){if(!wildcard||!depth)return 0;has_wild=1;}
        else if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
                  c=='_'||c=='-'||c=='.'||c==' '))return 0;
        if(!depth)root[seg]=(char)(c>='A'&&c<='Z'?c+32:c);
        seg++;
    }
    return 0;
}

static int mount(mxb_files *f,const char *name,const uint8_t *data,uint64_t size,mxb_file_read_at read_at,void *ctx){
    char normalized[MXB_FILE_NAME]={0};if(!f||(!data&&!read_at)||size>MXB_FILE_MAX||!canonical(name,normalized)||absent_root(f,normalized))return 0;
    unsigned free_slot=MXB_FILE_MOUNTS;
    for(unsigned i=0;i<MXB_FILE_MOUNTS;i++){
        if(!active(&f->mounts[i])){if(free_slot==MXB_FILE_MOUNTS)free_slot=i;}
        else if(eq(f->mounts[i].name,normalized))return 0;
    }
    if(free_slot==MXB_FILE_MOUNTS)return 0;
    mxb_file_mount *m=&f->mounts[free_slot];for(size_t i=0;i<MXB_FILE_NAME;i++)m->name[i]=normalized[i];
    m->data=data;m->size=size;m->read_at=read_at;m->ctx=ctx;return 1;
}
int mxb_files_mount(mxb_files *f,const char *name,const uint8_t *data,uint64_t size){return mount(f,name,data,size,0,0);}
int mxb_files_mount_source(mxb_files *f,const char *name,uint64_t size,mxb_file_read_at read_at,void *ctx){return mount(f,name,0,size,read_at,ctx);}
static int source(const mxb_file_mount *a,uint64_t offset,uint8_t *out,size_t n){
    if(offset>a->size||n>a->size-offset)return 0;
    if(a->read_at)return a->read_at(a->ctx,offset,out,n)==1;
    for(size_t i=0;i<n;i++)out[i]=a->data[offset+i];
    return 1;
}
static mxb_file_handle *handle(mxb_files *f,uint64_t token){
    if(!token)return 0;
    for(unsigned i=0;i<MXB_FILE_HANDLES;i++)if(f->handles[i].token==token)return &f->handles[i];
    return 0;
}
static int output(const mxb_crt_memory *m,uint64_t a,size_t n){return m&&m->writable&&m->write&&a&&a<=UINT64_MAX-n&&m->writable(m->ctx,a,n);}
int mxb_files_dispatch(mxb_files *f,const mxb_crt_memory *m,const char *name,mxb_crt_regs *r){
    int open=eq(name,"fopen"),read=eq(name,"fread"),seek=eq(name,"fseek"),tell=eq(name,"ftell"),close=eq(name,"fclose"),eof=eq(name,"feof"),err=eq(name,"ferror"),gets=eq(name,"fgets"),getc=eq(name,"fgetc"),clear=eq(name,"clearerr"),rewind=eq(name,"rewind");
    int find=eq(name,"_findfirst64i32");
    if(!open&&!read&&!seek&&!tell&&!close&&!eof&&!err&&!gets&&!getc&&!clear&&!rewind&&!find)return 0;
    if(!f||!r||(r->rsp&15u)!=8u)return -1;
    if(find){
        char pattern[MXB_FILE_NAME];
        if(!readstr(m,r->rcx,pattern,sizeof(pattern)))return -1;
        if(!absent_descendant(f,pattern,1))return 0;
        r->rax=UINT64_MAX;return 1;
    }
    if(open){
        char path[MXB_FILE_NAME],mode[8],normalized[MXB_FILE_NAME];
        if(!readstr(m,r->rcx,path,sizeof(path))||!readstr(m,r->rdx,mode,sizeof(mode)))return -1;
        if(!eq(mode,"rb"))return 0;
        if(absent_descendant(f,path,0)){r->rax=0;return 1;}
        if(!canonical(path,normalized))return 0;
        unsigned i=0;while(i<MXB_FILE_MOUNTS&&(!active(&f->mounts[i])||!eq(f->mounts[i].name,normalized)))i++;
        if(i==MXB_FILE_MOUNTS)return 0;
        unsigned h=0;while(h<MXB_FILE_HANDLES&&f->handles[h].token)h++;
        if(h==MXB_FILE_HANDLES||f->generation>=UINT32_MAX){r->rax=0;return 1;}
        uint64_t token=TOKEN_BASE+(++f->generation)*16u;
        f->handles[h]=(mxb_file_handle){token,0,i,0,0};r->rax=token;return 1;
    }
    mxb_file_handle *h=handle(f,read?r->r9:gets?r->r8:r->rcx);
    if(!h||h->mount>=MXB_FILE_MOUNTS||!active(&f->mounts[h->mount]))return -1;
    mxb_file_mount *a=&f->mounts[h->mount];
    if(close){*h=(mxb_file_handle){0};r->rax=0;return 1;}
    if(tell){r->rax=h->pos;return 1;}
    if(eof){r->rax=h->eof;return 1;}
    if(err){r->rax=h->error;return 1;}
    if(clear){h->eof=h->error=0;return 1;}
    if(rewind){h->pos=0;h->eof=h->error=0;return 1;}
    if(seek){
        uint32_t origin=(uint32_t)r->r8;if(origin>2)return 0;
        int64_t pos=(int64_t)(origin==0?0:origin==1?h->pos:a->size)+(int32_t)(uint32_t)r->rdx;
        if(pos<0||pos>INT32_MAX){r->rax=UINT32_MAX;return 1;}
        h->pos=(uint64_t)pos;h->eof=0;r->rax=0;return 1;
    }
    uint64_t available=h->pos<a->size?a->size-h->pos:0;
    if(read){
        if(!r->rdx||!r->r8){r->rax=0;return 1;}
        if(r->r8>UINT64_MAX/r->rdx||r->rdx*r->r8>MXB_FILE_READ_MAX)return -1;
        uint64_t want=r->rdx*r->r8,n=want<available?want:available;
        if(n&&!output(m,r->rcx,(size_t)n))return -1;
        uint64_t done=0;uint8_t buf[MXB_FILE_CHUNK];
        while(done<n){size_t chunk=(size_t)(n-done);if(chunk>sizeof(buf))chunk=sizeof(buf);
            if(!source(a,h->pos+done,buf,chunk)){h->error=1;break;}
            m->write(m->ctx,r->rcx+done,buf,chunk);done+=chunk;
        }
        h->pos+=done;if(done==n&&n<want)h->eof=1;r->rax=done/r->rdx;return 1;
    }
    if(getc){uint8_t b;if(!available){h->eof=1;r->rax=UINT32_MAX;return 1;}
        if(!source(a,h->pos,&b,1)){h->error=1;r->rax=UINT32_MAX;return 1;}
        h->pos++;r->rax=b;return 1;
    }
    int32_t cap=(int32_t)(uint32_t)r->rdx;if(cap<2||cap>4096)return 0;
    if(!available){h->eof=1;r->rax=0;return 1;}
    uint8_t buf[4096];size_t limit=(size_t)cap-1;if(available<limit)limit=(size_t)available;
    /* Read one byte at a time so a source failure after a newline does not
     * turn an otherwise successful line read into an error. */
    size_t n=0;while(n<limit){if(!source(a,h->pos+n,buf+n,1)){h->error=1;r->rax=0;return 1;}if(buf[n++]=='\n')break;}
    buf[n]=0;if(!output(m,r->rcx,n+1))return -1;
    m->write(m->ctx,r->rcx,buf,n+1);h->pos+=n;
    if(n==available&&buf[n-1]!='\n'&&n<(size_t)cap-1)h->eof=1;
    r->rax=r->rcx;return 1;
}
