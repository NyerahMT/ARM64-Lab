#include "mxb_native_exec.h"
#include "mxb_guest_crt.h"
#include "mxb_pe_guest_image.h"

static uint8_t initial_byte(unsigned i){return (uint8_t)(i*13u+7u);}
int mxb_native_probe_smoke(void){
 MXBGuestState s={0};MXBNativeCursor cursor=mxb_native_probe_begin();
 uint8_t stack[4096]={0},heap[2][4096],arena[4096]={0},out[8];
 const uint64_t stack_base=UINT64_C(0x720000000),heap_base=UINT64_C(0x730000000);
 for(unsigned p=0;p<2;p++)for(unsigned i=0;i<4096;i++)heap[p][i]=initial_byte(i+p*4096u);
 if(!mxb_guest_heap_init(&s,UINT64_C(0x740000000),arena,sizeof(arena))||
    !mxb_guest_map(&s.memory,stack_base,stack,sizeof(stack),3)||
    !mxb_guest_map(&s.memory,heap_base,heap[0],4096,3)||
    !mxb_guest_map(&s.memory,heap_base+4096,heap[1],4096,3))return 0;
 s.r[MXB_RSP]=stack_base+0xc00u;s.flags=0x202;
 if(mxb_native_probe_resume(&s,&cursor,0)!=MXB_NATIVE_YIELD||cursor.steps)return 0;
 int rc;unsigned slices=0;
 do{
  rc=mxb_native_probe_resume(&s,&cursor,3u);
  if(++slices>16u)return 0;
 }while(rc==MXB_NATIVE_YIELD);
 if(rc!=MXB_NATIVE_DONE||cursor.steps!=32u||slices!=11u||
    s.r[MXB_RSP]!=stack_base+0xc00u||s.r[MXB_RAX]!=heap_base+132u)return 0;
 if(s.r[MXB_RBX]!=s.heap.base || s.heap.count!=1u || s.heap.live[0].length!=16u)return 0;
 for(unsigned i=0;i<32;i++)if(arena[i]!=0x5a)return 0;
 if(arena[32])return 0;
 for(unsigned i=0;i<4;i++)if(heap[0][128u+i]!=initial_byte(16u+i))return 0;
 for(unsigned i=0;i<32;i++)if(heap[0][132u+i]!=initial_byte(16u+i))return 0;
 for(unsigned i=0;i<4;i++)if(heap[0][164u+i]!=initial_byte(52u+i))return 0;
 if(!mxb_guest_read(&s.memory,heap_base+4092u,out,8))return 0;
 for(unsigned i=0;i<8;i++)if(out[i]!=0xa7u)return 0;
 if(mxb_native_probe_resume(&s,&cursor,3)!=MXB_NATIVE_DONE||cursor.steps!=32u)return 0;
 MXBNativeCursor bad=mxb_native_probe_begin();bad.pc=0x1234u;
 if(mxb_native_probe_resume(&s,&bad,1)!=MXB_NATIVE_UNKNOWN_PC)return 0;
 return mxb_guest_memory_smoke()&&mxb_guest_crt_smoke()&&mxb_pe_guest_smoke();
}
