#include "mxb_pe_guest_image.h"

static uint16_t u16(const uint8_t*p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t u32(const uint8_t*p){
 return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t u64(const uint8_t*p){return u32(p)|((uint64_t)u32(p+4)<<32);}
static int within(size_t offset,size_t count,size_t length){return offset<=length&&count<=length-offset;}
static int power2(uint32_t a){return a&&!(a&(a-1u));}
static uint32_t align_up(uint32_t n,uint32_t a){
 uint64_t v=((uint64_t)n+a-1u)&~((uint64_t)a-1u);
 return v<=UINT32_MAX?(uint32_t)v:0;
}
int mxb_pe_plan(const uint8_t*f,size_t size,MXBPEImage*out){
 if(!f||!out||size<64u||size>MXB_PE_MAX_IMAGE||u16(f)!=0x5a4du)return 0;
 uint32_t pe=u32(f+0x3c);
 if(!within(pe,24,size)||u32(f+pe)!=0x4550u||u16(f+pe+4)!=0x8664u)return 0;
 unsigned count=u16(f+pe+6),opt_size=u16(f+pe+20);
 size_t opt=(size_t)pe+24u;
 if(!count||count>MXB_PE_MAX_SECTIONS||opt_size<112u||
    !within(opt,opt_size,size)||u16(f+opt)!=0x20bu)return 0;
 size_t section_table=opt+opt_size;
 if(!within(section_table,count*40u,size))return 0;
 uint32_t sa=u32(f+opt+32),fa=u32(f+opt+36);
 MXBPEImage p={0};p.image_base=u64(f+opt+24);
 p.image_size=u32(f+opt+56);p.header_size=u32(f+opt+60);
 p.entry_rva=u32(f+opt+16);p.section_count=count;
 if(!power2(sa)||sa<4096u||sa>65536u||!power2(fa)||fa<512u||fa>sa||
    !p.image_base||(p.image_base&0xffffu)||!p.image_size||
    p.image_size>MXB_PE_MAX_IMAGE||p.image_size%sa||
    p.image_base>UINT64_MAX-p.image_size||!p.header_size||p.header_size%fa||
    !within(0,p.header_size,size)||section_table+count*40u>p.header_size)return 0;
 p.header_mapped_size=align_up(p.header_size,sa);
 if(!p.header_mapped_size||p.header_mapped_size>p.image_size)return 0;
 int entry_ok=0;
 for(unsigned i=0;i<count;i++){
  const uint8_t*s=f+section_table+i*40u;MXBPESection*r=&p.sections[i];
  r->virtual_size=u32(s+8);r->rva=u32(s+12);r->raw_size=u32(s+16);r->raw_offset=u32(s+20);
  uint32_t flags=u32(s+36),span=r->virtual_size>r->raw_size?r->virtual_size:r->raw_size;
  r->permissions=((flags&0x40000000u)?MXB_MEM_READ:0u)|
                 ((flags&0x80000000u)?MXB_MEM_WRITE:0u)|
                 ((flags&0x20000000u)?MXB_MEM_EXEC:0u);
  r->mapped_size=align_up(span,sa);
  if(!r->mapped_size||r->rva%sa||r->rva<p.header_mapped_size||
     r->rva>=p.image_size||r->mapped_size>p.image_size-r->rva||
     !r->permissions||((r->permissions&6u)==6u))return 0;
  if(r->raw_size&&(r->raw_offset%fa||r->raw_offset<p.header_size||
     !within(r->raw_offset,r->raw_size,size)))return 0;
  /* Some vendor-added terminal sections have an unaligned raw length.
   * Accept only a bounded final raw tail with at most file-alignment
   * padding; never round its payload up or copy bytes outside the range. */
  if(r->raw_size%fa){
   uint32_t end=r->raw_offset+r->raw_size;
   if(end!=size&&align_up(end,fa)!=size)return 0;
  }
  for(unsigned j=0;j<i;j++){
   const MXBPESection*q=&p.sections[j];
   if(r->rva<q->rva+q->mapped_size&&q->rva<r->rva+r->mapped_size)return 0;
   if(r->raw_size&&q->raw_size&&r->raw_offset<(uint64_t)q->raw_offset+q->raw_size&&
      q->raw_offset<(uint64_t)r->raw_offset+r->raw_size)return 0;
  }
  if((r->permissions&MXB_MEM_EXEC)&&p.entry_rva>=r->rva&&p.entry_rva-r->rva<span)entry_ok=1;
 }
 if(!entry_ok)return 0;
 *out=p;return 1;
}
int mxb_pe_map(MXBGuestMemory*m,const uint8_t*f,size_t size,
               uint8_t*backing,size_t capacity,MXBPEImage*out){
 MXBPEImage p;
 if(!m||m->count>MXB_MEM_MAX_REGIONS||!backing||!mxb_pe_plan(f,size,&p)||
    capacity<p.image_size)return 0;
 uintptr_t src=(uintptr_t)f,dst=(uintptr_t)backing;
 if(size>UINTPTR_MAX-src||p.image_size>UINTPTR_MAX-dst||
    (src<dst+p.image_size&&dst<src+size))return 0;
 MXBGuestMemory staged=*m;
 /* The zero-fill touches the entire image, including its unmapped holes.
  * Reject any host alias with an already registered region up front. */
 for(unsigned i=0;i<m->count;i++){
  uintptr_t old=(uintptr_t)m->regions[i].bytes;
  if(old<dst+p.image_size&&dst<old+m->regions[i].length)return 0;
 }
 if(!mxb_guest_map(&staged,p.image_base,backing,p.header_mapped_size,MXB_MEM_READ))return 0;
 for(unsigned i=0;i<p.section_count;i++){
  const MXBPESection*r=&p.sections[i];
  if(!mxb_guest_map(&staged,p.image_base+r->rva,backing+r->rva,
                    r->mapped_size,r->permissions))return 0;
 }
 volatile uint8_t*d=backing;
 for(uint32_t i=0;i<p.image_size;i++)d[i]=0;
 for(uint32_t i=0;i<p.header_size;i++)d[i]=f[i];
 for(unsigned k=0;k<p.section_count;k++){
  const MXBPESection*r=&p.sections[k];
  for(uint32_t i=0;i<r->raw_size;i++)d[r->rva+i]=f[r->raw_offset+i];
 }
 *m=staged;if(out)*out=p;return 1;
}
static void put(uint8_t*p,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8u*i));}
int mxb_pe_guest_smoke(void){
 uint8_t file[1536]={0},backing[12288],byte=0;MXBGuestMemory m={0};MXBPEImage plan;
 uint8_t*pe=file+0x80,*opt=pe+24,*sections=opt+240;
 put(file,0x5a4d,2);put(file+0x3c,0x80,4);
 put(pe,0x4550,4);put(pe+4,0x8664,2);put(pe+6,2,2);put(pe+20,240,2);
 put(opt,0x20b,2);put(opt+16,0x1000,4);put(opt+24,UINT64_C(0x140000000),8);
 put(opt+32,0x1000,4);put(opt+36,0x200,4);put(opt+56,0x3000,4);put(opt+60,0x200,4);
 for(unsigned i=0;i<2;i++){
  uint8_t*s=sections+i*40u;
  put(s+8,0x400,4);put(s+12,0x1000u*(i+1u),4);put(s+16,0x200,4);
  put(s+20,0x200u*(i+1u),4);put(s+36,i?0xc0000040u:0x60000020u,4);
 }
 file[512]=0xcc;file[1024]=0xa5;file[1535]=0x33;
 const uint64_t base=UINT64_C(0x140000000);
 for(unsigned i=0;i<sizeof(backing);i++)backing[i]=0x77;
 /* Invalid or overlapping sections never mutate caller's memory/backing. */
 put(sections+40+12,0x1000,4);
 if(mxb_pe_map(&m,file,sizeof(file),backing,sizeof(backing),&plan)||m.count||backing[0]!=0x77)return 0;
 put(sections+40+12,0x2000,4);
 put(sections+36,0xe0000020,4);
 if(mxb_pe_plan(file,sizeof(file),&plan))return 0;
 put(sections+36,0x60000020,4);
 /* A non-aligned nonterminal raw segment is invalid. A final vendor
  * section can have a bounded unaligned payload; padding stays zero. */
 put(sections+16,0x1ff,4);
 if(mxb_pe_plan(file,sizeof(file),&plan))return 0;
 put(sections+16,0x200,4);
 put(sections+40+16,0x1ff,4);
 if(!mxb_pe_plan(file,sizeof(file),&plan))return 0;
 put(sections+40+16,0x200,4);
 if(mxb_pe_map(&m,file,sizeof(file),backing,sizeof(backing)-1,&plan)||m.count)return 0;
 if(!mxb_pe_map(&m,file,sizeof(file),backing,sizeof(backing),&plan)||
    plan.image_base!=base||plan.entry_rva!=0x1000||plan.section_count!=2||m.count!=3)return 0;
 if(!mxb_guest_read(&m,base+0x1000,&byte,1)||byte!=0xcc||
    !mxb_guest_check(&m,base+0x1000,1,MXB_MEM_EXEC)||
    mxb_guest_write(&m,base+0x1000,&byte,1))return 0;
 if(!mxb_guest_read(&m,base+0x2000,&byte,1)||byte!=0xa5||
    !mxb_guest_read(&m,base+0x21ff,&byte,1)||byte!=0x33||
    !mxb_guest_read(&m,base+0x2200,&byte,1)||byte||
    mxb_guest_check(&m,base+0x2000,1,MXB_MEM_EXEC))return 0;
 byte=0x5a;
 if(!mxb_guest_write(&m,base+0x2200,&byte,1)||backing[0x2200]!=0x5a)return 0;
 if(mxb_pe_map(&m,file,sizeof(file),backing,sizeof(backing),&plan)||backing[0x2200]!=0x5a)return 0;
 return 1;
}
