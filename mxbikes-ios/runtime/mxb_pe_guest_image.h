#ifndef MXB_PE_GUEST_IMAGE_H
#define MXB_PE_GUEST_IMAGE_H
#include "mxb_guest_memory.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MXB_PE_MAX_SECTIONS 48u
#define MXB_PE_MAX_IMAGE (128u*1024u*1024u)
typedef struct {
 uint32_t rva,virtual_size,raw_offset,raw_size,mapped_size,permissions;
} MXBPESection;
typedef struct {
 uint64_t image_base;
 uint32_t image_size,header_size,header_mapped_size,entry_rva,section_count;
 MXBPESection sections[MXB_PE_MAX_SECTIONS];
} MXBPEImage;
/* Parse only 64-bit x86 PE images with normal page-aligned sections.
 * No native execution, relocations, imported DLL resolution or entitlement. */
int mxb_pe_plan(const uint8_t*file,size_t file_size,MXBPEImage*out);
/* Maps at the original preferred guest VA. Backing is caller-owned, zero
 * filled, and must remain valid while memory is mapped. On rejection neither
 * memory mappings nor backing bytes nor the output plan are changed. */
int mxb_pe_map(MXBGuestMemory*m,const uint8_t*file,size_t file_size,
               uint8_t*backing,size_t backing_size,MXBPEImage*out);
int mxb_pe_guest_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
