#include "mxb_observed_memory.h"
static const mxb_observed_region *find(const mxb_observed_memory *m,uint64_t p){
    if(!m||m->count>MXB_OBSERVED_REGION_CAP)return 0;
    for(unsigned i=0;i<m->count;i++){
        const mxb_observed_region *r=&m->region[i];
        if(p>=r->base&&p-r->base<r->size)return r;
    }
    return 0;
}
int mxb_observed_map(mxb_observed_memory *m,uint64_t base,size_t size,uint8_t *bytes,unsigned perms){
    if(!m||m->count>=MXB_OBSERVED_REGION_CAP||!base||!size||!bytes||
       base>UINT64_MAX-size||!perms||(perms&~7u)||
       ((perms&MXB_MEM_W)&&(perms&MXB_MEM_X)))return 0;
    for(unsigned i=0;i<m->count;i++){
        const mxb_observed_region *r=&m->region[i];
        if(base<r->base+r->size&&r->base<base+size)return 0;
    }
    m->region[m->count++]=(mxb_observed_region){base,size,bytes,perms};
    return 1;
}
int mxb_observed_permitted(const mxb_observed_memory *m,uint64_t p,size_t size,unsigned perms){
    if(!m||!size||p>UINT64_MAX-size||!perms||(perms&~7u))return 0;
    while(size){
        const mxb_observed_region *r=find(m,p);
        if(!r||(r->permissions&perms)!=perms)return 0;
        uint64_t n=r->size-(p-r->base);
        if(n>size)n=size;
        size-=(size_t)n;p+=n;
    }
    return 1;
}
static int width(unsigned n){return n==1||n==2||n==4||n==8;}
int mxb_observed_read(void *ctx,uint64_t p,unsigned n,uint64_t *out){
    const mxb_observed_memory *m=ctx;
    if(!out||!width(n)||!mxb_observed_permitted(m,p,n,MXB_MEM_R))return 0;
    uint64_t value=0;
    for(unsigned i=0;i<n;i++){
        const mxb_observed_region *r=find(m,p+i);
        value|=(uint64_t)r->bytes[p+i-r->base]<<(8*i);
    }
    *out=value;return 1;
}
static void commit(mxb_observed_memory *m,uint64_t p,unsigned n,uint64_t v){
    for(unsigned i=0;i<n;i++){
        const mxb_observed_region *r=find(m,p+i);
        r->bytes[p+i-r->base]=(uint8_t)(v>>(8*i));
    }
}
int mxb_observed_write(void *ctx,uint64_t p,unsigned n,uint64_t v){
    mxb_observed_memory *m=ctx;
    if(!width(n)||!mxb_observed_permitted(m,p,n,MXB_MEM_W))return 0;
    commit(m,p,n,v);return 1;
}
int mxb_observed_write128(void *ctx,uint64_t p,uint64_t lo,uint64_t hi){
    mxb_observed_memory *m=ctx;
    if(!mxb_observed_permitted(m,p,16,MXB_MEM_W))return 0;
    commit(m,p,8,lo);commit(m,p+8,8,hi);return 1;
}
