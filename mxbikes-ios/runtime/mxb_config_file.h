#ifndef MXB_CONFIG_FILE_H
#define MXB_CONFIG_FILE_H
#include "mxb_guest_memory.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Isolated read-only Win64 file metadata service. No licensing or Steam state.
 * This context belongs to the configuration test, not the startup process. */
typedef struct {
 uint64_t last_write;
 unsigned open, opens, queries, closes;
} MXBConfigFile;
#define MXB_CONFIG_HANDLE UINT64_C(0x730070000)
int mxb_config_file_call(MXBGuestState *s,MXBConfigFile *f,const char *symbol,uint64_t return_pc);
int mxb_config_file_smoke(void);
#ifdef __cplusplus
}
#endif
#endif
