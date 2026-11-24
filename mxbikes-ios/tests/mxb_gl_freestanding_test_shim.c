/* Test-only freestanding allocation and memory functions.
 * Never include this file in the iOS app or production renderer. */
#include <stddef.h>
#include <stdint.h>

static _Alignas(16) unsigned char arena[512u*1024u];
/* First-fit blocks: enough for the renderer or small texture fixtures. */
static struct {size_t offset,size;int live;} blocks[32];
typedef uint64_t alias_u64 __attribute__((may_alias));

void *memset(void *dst,int value,size_t n){
 unsigned char *p=dst;
 const unsigned char byte=(unsigned char)value;
 while(n&&((uintptr_t)p&7u)){*p++=byte;--n;}
 const uint64_t word=(uint64_t)byte*UINT64_C(0x0101010101010101);
 while(n>=8u){
  *(volatile alias_u64 *)p=word;
  p+=8u;n-=8u;
 }
 while(n){*(volatile unsigned char *)p++=byte;--n;}
 return dst;
}
void *memcpy(void *dst,const void *src,size_t n){
 volatile unsigned char *d=dst;
 const volatile unsigned char *s=src;
 for(size_t i=0;i<n;i++)d[i]=s[i];
 return dst;
}
int memcmp(const void *lhs,const void *rhs,size_t n){
 const unsigned char *a=lhs,*b=rhs;
 for(size_t i=0;i<n;i++)if(a[i]!=b[i])return a[i]<b[i]?-1:1;
 return 0;
}
void *calloc(size_t count,size_t size){
 if(!count||!size||count>sizeof(arena)/size)return 0;
 size_t bytes=count*size;
 size_t rounded=(bytes+15u)&~(size_t)15u;
 if(rounded>sizeof(arena))return 0;
 unsigned slot=32;
 for(unsigned i=0;i<32;i++)if(!blocks[i].live){slot=i;break;}
 if(slot==32)return 0;
 size_t offset=0;
 for(;;){
  if(offset>sizeof(arena)-rounded)return 0;
  size_t next=offset;
  for(unsigned i=0;i<32;i++)
   if(blocks[i].live&&offset<blocks[i].offset+blocks[i].size&&
      blocks[i].offset<offset+rounded&&blocks[i].offset+blocks[i].size>next)
    next=blocks[i].offset+blocks[i].size;
  if(next==offset)break;
  offset=next;
 }
 blocks[slot].offset=offset;blocks[slot].size=rounded;blocks[slot].live=1;
 return memset(arena+offset,0,bytes);
}
void free(void *ptr){
 if(!ptr)return;
 for(unsigned i=0;i<32;i++)
  if(blocks[i].live&&ptr==arena+blocks[i].offset){blocks[i].live=0;return;}
}
extern int main(void);
int smoke(void){return main();}
