#ifndef MXBIKES_NATIVE_FILE_CRC_CHAIN_H
#define MXBIKES_NATIVE_FILE_CRC_CHAIN_H
/*
 * End-to-end read-only Win64 CRT service / original CRC guest-state chain.
 * Uses the same mx_cfg_memory and mx_crt_cluster_state as native startup.
 * CRC execution is an exact verified translation of 0x140130670;
 * fread/fseek/ftell/fclose are read-only guest service adapters, NOT full
 * translations of surrounding original game instructions. The wrapper is a
 * reusable native service chain, not original renderer or Steam execution.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#include "mxbikes_crc_cluster_bridge.h"

#define MXB_FILE_CHUNK 1000U
#define MXB_FILE_SEEK_SET 0
#define MXB_FILE_SEEK_CUR 1
#define MXB_FILE_SEEK_END 2

typedef struct {
 const uint8_t *owned_bytes;
 uint64_t length,position;
 uint32_t seek_calls,tell_calls,read_calls,close_calls;
 uint64_t total_bytes_read;
 uint8_t is_open;
} mxb_readonly_file;

static inline int mxb_file_init(mxb_readonly_file *f,
            const uint8_t *source,uint64_t length,uint64_t initial_position) {
 if(!f||!source||!length||initial_position>length)return 0;
 f->owned_bytes=source;f->length=length;f->position=initial_position;
 f->seek_calls=0U;f->tell_calls=0U;f->read_calls=0U;f->close_calls=0U;
 f->total_bytes_read=0U;f->is_open=1U;
 return 1;
}
static inline int mxb_file_seek(mxb_readonly_file *f,
                               int64_t offset,int origin) {
 if(!f||!f->is_open)return 0;
 uint64_t base;
 if(origin==MXB_FILE_SEEK_SET)base=0U;
 else if(origin==MXB_FILE_SEEK_CUR)base=f->position;
 else if(origin==MXB_FILE_SEEK_END)base=f->length;
 else return 0;
 uint64_t target;
 if(offset<0){
  /* Avoid signed overflow for INT64_MIN. */
  uint64_t subtract=(uint64_t)(-(offset+1))+1U;
  if(subtract>base)return 0;
  target=base-subtract;
 }else{
  uint64_t plus=(uint64_t)offset;
  if(base>f->length||plus>f->length-base)return 0;
  target=base+plus;
 }
 if(target>f->length)return 0;
 f->position=target;f->seek_calls++;
 return 1;
}
static inline int mxb_file_tell(mxb_readonly_file *f,uint64_t *result) {
 if(!f||!f->is_open||!result||f->length>UINT32_MAX)return 0;
 *result=f->position;
 f->tell_calls++;
 return 1;
}
/* Emulate fread(guest_buffer,1,request,file) with checked guest memory.
 * Preflight every destination before a single write; no host IO, no code
 * execution from file contents, and guest pointer cannot escape mappings.
 */
static inline int mxb_file_read(mxb_readonly_file *f,mx_cfg_memory *memory,
                               uint64_t guest_buffer,uint32_t request,
                               uint32_t *bytes_read) {
 if(!f||!memory||!bytes_read||!f->is_open||
    request==0U||request>MXB_FILE_CHUNK||
    guest_buffer>UINT64_MAX-(uint64_t)request)return 0;
 uint64_t remaining=f->length-f->position;
 uint32_t amount=(uint32_t)(remaining<(uint64_t)request?remaining:request);
 /* Validate one contiguous registered guest writable range before copying.
  * This is the same bounded region contract as mx_cfg_transfer, with an
  * atomic preflight rather than partial writes on an invalid destination.
  */
 if(!memory->regions||memory->count==0U||memory->count>16U)return 0;
 volatile uint8_t *destination=0;
 for(uint32_t k=0U;k<memory->count;k++){
  const mx_cfg_region *region=&memory->regions[k];
  if(!region->data||guest_buffer<region->base||
     (uint64_t)amount>region->length)continue;
  uint64_t offset=guest_buffer-region->base;
  if(offset>region->length-(uint64_t)amount)continue;
  destination=(volatile uint8_t*)region->data+offset;
  break;
 }
 if(!destination)return 0;
 for(uint32_t i=0U;i<amount;i++)
    destination[i]=f->owned_bytes[f->position+(uint64_t)i];
 f->position+=(uint64_t)amount;
 f->total_bytes_read+=(uint64_t)amount;
 f->read_calls++;
 *bytes_read=amount;
 return 1;
}
static inline int mxb_file_close(mxb_readonly_file *f) {
 if(!f||!f->is_open)return 0;
 f->is_open=0U;f->close_calls++;
 return 1;
}
/* Callable unit used by the batch startup runtime; actual buffer is created
 * by a real read service into guest memory, then the original CRC executes
 * in the SAME guest register/memory state as the rest of startup.
 */
static inline int mxb_file_read_and_crc(mxb_readonly_file *file,
         mx_crt_cluster_state *guest,mx_cfg_memory *memory,
         uint64_t guest_buffer,uint32_t size,uint64_t original_r14) {
 if(!file||!guest||!memory||guest->fault||size==0U||size>1000U)
    return 0;
 uint32_t copied=0U;
 if(!mxb_file_read(file,memory,guest_buffer,size,&copied)||
    copied!=size)return 0;
 guest->rip=MXB_CRC_LOOP_VA;
 guest->rcx=guest_buffer;
 guest->rdx=(uint64_t)copied;
 if(!mxb_crc_cluster_run(guest,memory,original_r14))
    return 0;
 if(guest->rip!=MXB_CRC_EXIT_VA||guest->rdx!=0U||
    guest->rcx!=guest_buffer+(uint64_t)size)return 0;
 return 1;
}
#endif
