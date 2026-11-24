#include "mxb_guest_memory.h"

void mxb_guest_memory_init(MXBGuestMemory *m){if(m)m->count=0u;}
static const MXBGuestRegion *find(const MXBGuestMemory *m,uint64_t a){
 if(!m||m->count>MXB_MEM_MAX_REGIONS)return 0;
 for(unsigned i=0;i<m->count;i++){
  const MXBGuestRegion *r=&m->regions[i];
  if(a>=r->base&&a-r->base<r->length)return r;
 }
 return 0;
}
int mxb_guest_map(MXBGuestMemory*m,uint64_t base,uint8_t*bytes,size_t length,unsigned p){
 if(!m||!bytes||!length||m->count>=MXB_MEM_MAX_REGIONS||
    !p||(p&~7u)||((p&MXB_MEM_WRITE)&&(p&MXB_MEM_EXEC))||
    (uint64_t)length>UINT64_MAX-base)return 0;
 uintptr_t backing=(uintptr_t)bytes;
 if(length>UINTPTR_MAX-backing)return 0;
 uint64_t end=base+(uint64_t)length;
 for(unsigned i=0;i<m->count;i++){
  const MXBGuestRegion*r=&m->regions[i];
  uintptr_t host=(uintptr_t)r->bytes;
  /* No virtual or host aliasing: overlap-safe memmove relies on this. */
  if((base<r->base+r->length&&r->base<end)||
     (backing<host+r->length&&host<backing+length))return 0;
 }
 unsigned at=m->count;
 while(at&&m->regions[at-1u].base>base){m->regions[at]=m->regions[at-1u];at--;}
 m->regions[at]=(MXBGuestRegion){base,(uint64_t)length,bytes,p};m->count++;
 return 1;
}
int mxb_guest_map_gaps(MXBGuestMemory*m,uint64_t base,uint8_t*bytes,size_t length,unsigned p){
 if(!m||!bytes||!length||m->count>MXB_MEM_MAX_REGIONS||
    (p!=MXB_MEM_READ&&p!=(MXB_MEM_READ|MXB_MEM_WRITE))||
    (uint64_t)length>UINT64_MAX-base||length>UINTPTR_MAX-(uintptr_t)bytes)return 0;
 MXBGuestMemory staged=*m;
 uint64_t at=base,end=base+(uint64_t)length;
 for(unsigned i=0;i<m->count;i++){
  const MXBGuestRegion*r=&m->regions[i];
  uint64_t limit=r->base+r->length;
  if(limit<=base||r->base>=end)continue;
  /* A preexisting region must be wholly inside this image segment and no
   * more permissive than it; a cross-section alias is not an overlay. */
  if(r->base<at||limit>end||(r->permissions&~p))return 0;
  if(r->base>at&&!mxb_guest_map(&staged,at,bytes+(size_t)(at-base),(size_t)(r->base-at),p))return 0;
  at=limit;
 }
 if(at<end&&!mxb_guest_map(&staged,at,bytes+(size_t)(at-base),(size_t)(end-at),p))return 0;
 *m=staged;return 1;
}
int mxb_guest_unmap(MXBGuestMemory*m,uint64_t base){
 if(!m||m->count>MXB_MEM_MAX_REGIONS)return 0;
 for(unsigned i=0;i<m->count;i++)if(m->regions[i].base==base){
  for(unsigned j=i+1u;j<m->count;j++)m->regions[j-1u]=m->regions[j];
  m->count--;return 1;
 }
 return 0;
}
int mxb_guest_check(const MXBGuestMemory*m,uint64_t a,size_t n,unsigned p){
 if(!m||m->count>MXB_MEM_MAX_REGIONS||!p||(p&~7u)||
    n>MXB_MEM_MAX_TRANSFER||(uint64_t)n>UINT64_MAX-a)return 0;
 while(n){
  const MXBGuestRegion*r=find(m,a);
  if(!r||(r->permissions&p)!=p)return 0;
  uint64_t remaining=r->length-(a-r->base);
  size_t chunk=remaining<n?(size_t)remaining:n;
  a+=chunk;n-=chunk;
 }
 return 1;
}
static void transfer(const MXBGuestMemory*m,uint64_t a,void*out,const void*in,size_t n,int write){
 uint8_t*d=out;const uint8_t*s=in;
 while(n){
  const MXBGuestRegion*r=find(m,a);
  uint64_t off=a-r->base,remaining=r->length-off;
  size_t chunk=remaining<n?(size_t)remaining:n;
  volatile uint8_t*p=r->bytes+(size_t)off;
  for(size_t i=0;i<chunk;i++){
   if(write)p[i]=s[i];else d[i]=p[i];
  }
  if(write)s+=chunk;else d+=chunk;
  a+=chunk;n-=chunk;
 }
}
int mxb_guest_read(const MXBGuestMemory*m,uint64_t a,void*out,size_t n){
 if((n&&!out)||!mxb_guest_check(m,a,n,MXB_MEM_READ))return 0;
 transfer(m,a,out,0,n,0);return 1;
}
int mxb_guest_write(MXBGuestMemory*m,uint64_t a,const void*in,size_t n){
 if((n&&!in)||!mxb_guest_check(m,a,n,MXB_MEM_WRITE))return 0;
 transfer(m,a,0,in,n,1);return 1;
}
int mxb_guest_fill(MXBGuestMemory*m,uint64_t a,uint8_t value,size_t n){
 if(!mxb_guest_check(m,a,n,MXB_MEM_WRITE))return 0;
 while(n){
  const MXBGuestRegion*r=find(m,a);
  uint64_t off=a-r->base,remaining=r->length-off;
  size_t chunk=remaining<n?(size_t)remaining:n;
  volatile uint8_t*p=r->bytes+(size_t)off;
  for(size_t i=0;i<chunk;i++)p[i]=value;
  a+=chunk;n-=chunk;
 }
 return 1;
}
int mxb_guest_move(MXBGuestMemory*m,uint64_t dst,uint64_t src,size_t n){
 if(!mxb_guest_check(m,src,n,MXB_MEM_READ)||
    !mxb_guest_check(m,dst,n,MXB_MEM_WRITE))return 0;
 uint8_t tmp[256];
 if(dst>src&&dst-src<n){
  while(n){
   size_t k=n<sizeof(tmp)?n:sizeof(tmp);n-=k;
   transfer(m,src+n,tmp,0,k,0);transfer(m,dst+n,0,tmp,k,1);
  }
 }else{
  for(size_t offset=0;offset<n;){
   size_t k=n-offset<sizeof(tmp)?n-offset:sizeof(tmp);
   transfer(m,src+offset,tmp,0,k,0);transfer(m,dst+offset,0,tmp,k,1);offset+=k;
  }
 }
 return 1;
}
int mxb_guest_read_callback(void*ctx,uint64_t a,void*out,size_t n){
 return mxb_guest_read((const MXBGuestMemory*)ctx,a,out,n);
}
int mxb_guest_write_callback(void*ctx,uint64_t a,const void*in,size_t n){
 return mxb_guest_write((MXBGuestMemory*)ctx,a,in,n);
}
int mxb_guest_memory_smoke(void){
 MXBGuestMemory m;uint8_t a[32],b[32],ro[8],out[64];
 mxb_guest_memory_init(&m);
 for(unsigned i=0;i<32;i++){a[i]=(uint8_t)i;b[i]=(uint8_t)(i+32u);}
 for(unsigned i=0;i<8;i++)ro[i]=0xa5u;
 const uint64_t base=UINT64_C(0x700000000);
 if(!mxb_guest_map(&m,base+32,b,32,3)||!mxb_guest_map(&m,base,a,32,3)||
    !mxb_guest_map(&m,base+64,ro,8,1)||m.count!=3u)return 0;
 if(mxb_guest_map(&m,base+31,out,2,3)||mxb_guest_map(&m,base+128,a,32,3)||
    mxb_guest_map(&m,base+128,out,8,6)||mxb_guest_map(&m,UINT64_MAX-1,out,8,3))return 0;
 if(!mxb_guest_read(&m,base,out,64))return 0;
 for(unsigned i=0;i<64;i++)if(out[i]!=i)return 0;
 if(mxb_guest_fill(&m,base+60,0,8)||b[28]!=60||ro[0]!=0xa5u)return 0;
 if(!mxb_guest_move(&m,base+4,base,60)||!mxb_guest_read(&m,base,out,64))return 0;
 for(unsigned i=4;i<64;i++)if(out[i]!=i-4u)return 0;
 if(!mxb_guest_move(&m,base,base+4,60)||!mxb_guest_read(&m,base,out,60))return 0;
 for(unsigned i=0;i<60;i++)if(out[i]!=i)return 0;
 if(mxb_guest_move(&m,base+60,base,8)||b[28]!=out[56])return 0;
 if(!mxb_guest_unmap(&m,base+32)||mxb_guest_read(&m,base+31,out,2))return 0;
 if(!mxb_guest_read(&m,UINT64_MAX,0,0)||mxb_guest_read(&m,UINT64_MAX, out,1))return 0;
 /* Map a whole data section around a persistent writable and a read-only
  * overlay. Preserve their original backing and stricter permissions. */
 MXBGuestMemory gaps={0};uint8_t section[64],overlay[8],strict[4];
 for(unsigned i=0;i<64;i++)section[i]=(uint8_t)i;
 for(unsigned i=0;i<8;i++)overlay[i]=0x91;
 for(unsigned i=0;i<4;i++)strict[i]=0x72;
 if(!mxb_guest_map(&gaps,base+8,overlay,8,3)||
    !mxb_guest_map(&gaps,base+24,strict,4,1)||
    !mxb_guest_map_gaps(&gaps,base,section,sizeof(section),3)||gaps.count!=5||
    !mxb_guest_read(&gaps,base,out,64))return 0;
 for(unsigned i=0;i<64;i++)if(out[i]!=(i>=8&&i<16?0x91:i>=24&&i<28?0x72:i))return 0;
 if(mxb_guest_fill(&gaps,base+22,0,8)||strict[0]!=0x72||section[22]!=22)return 0;
 if(!mxb_guest_fill(&gaps,base+6,0x23,12)||overlay[0]!=0x23||section[6]!=0x23)return 0;
 unsigned old_count=gaps.count;
 if(mxb_guest_map_gaps(&gaps,base+2,section+2,32,3)||gaps.count!=old_count||
    mxb_guest_map_gaps(&gaps,base,section,64,5)||gaps.count!=old_count||
    mxb_guest_map_gaps(&gaps,base,section,64,1)||gaps.count!=old_count)return 0;
 return 1;
}
