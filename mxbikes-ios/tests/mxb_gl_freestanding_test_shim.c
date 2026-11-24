/* Test-only freestanding allocation and memory functions.
 * Never include this file in the iOS app or production renderer. */
#include <stddef.h>
#include <stdint.h>

static _Alignas(16) unsigned char arena[512u*1024u];
static int allocated;
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
void *calloc(size_t count,size_t size){
 if(allocated||!count||!size||count>sizeof(arena)/size)return 0;
 allocated=1;
 return memset(arena,0,count*size);
}
void free(void *ptr){
 if(ptr==arena)allocated=0;
}
extern int main(void);
int smoke(void){return main();}
