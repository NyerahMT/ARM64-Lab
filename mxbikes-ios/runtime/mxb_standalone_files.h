#ifndef MXB_STANDALONE_FILES_H
#define MXB_STANDALONE_FILES_H
#include "mxb_standalone_crt.h"
#define MXB_FILE_MOUNTS 16u
#define MXB_FILE_HANDLES 32u
#define MXB_FILE_NAME 128u
#define MXB_FILE_MAX (64u*1024u*1024u)
/* Caller-owned immutable data stays alive until the session ends. Guest
 * names resolve only against explicit mounts; no host paths or writes. */
typedef struct {char name[MXB_FILE_NAME];const uint8_t *data;uint64_t size;} mxb_file_mount;
typedef struct {uint64_t token,pos;uint32_t mount,eof;} mxb_file_handle;
typedef struct {mxb_file_mount mounts[MXB_FILE_MOUNTS];mxb_file_handle handles[MXB_FILE_HANDLES];uint64_t generation;} mxb_files;
int mxb_files_mount(mxb_files *,const char *,const uint8_t *,uint64_t);
int mxb_files_dispatch(mxb_files *,const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
