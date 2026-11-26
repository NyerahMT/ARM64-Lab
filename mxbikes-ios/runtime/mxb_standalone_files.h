#ifndef MXB_STANDALONE_FILES_H
#define MXB_STANDALONE_FILES_H
#include "mxb_standalone_crt.h"
#define MXB_FILE_MOUNTS 16u
#define MXB_FILE_HANDLES 32u
#define MXB_FILE_NAME 128u
#define MXB_FILE_MAX UINT64_C(2147483647)
#define MXB_FILE_READ_MAX (64u*1024u*1024u)
#define MXB_FILE_CHUNK 16384u
#define MXB_FILE_ABSENT_DIRS 8u
/* A source must return exactly n bytes on success, with no guest pointers.
 * Its context and immutable backing storage must outlive the session. */
typedef int (*mxb_file_read_at)(void *,uint64_t,uint8_t *,size_t);
typedef struct {
    char name[MXB_FILE_NAME];const uint8_t *data;uint64_t size;
    mxb_file_read_at read_at;void *ctx;
} mxb_file_mount;
typedef struct {uint64_t token,pos;uint32_t mount,eof,error;} mxb_file_handle;
typedef struct {mxb_file_mount mounts[MXB_FILE_MOUNTS];mxb_file_handle handles[MXB_FILE_HANDLES];uint64_t generation;char absent_dirs[MXB_FILE_ABSENT_DIRS][MXB_FILE_NAME];} mxb_files;
int mxb_files_mount(mxb_files *,const char *,const uint8_t *,uint64_t);
int mxb_files_mount_source(mxb_files *,const char *,uint64_t,mxb_file_read_at,void *);
/* Register only directories established absent by the trusted publisher inventory. */
int mxb_files_mark_absent_directory(mxb_files *,const char *);
int mxb_files_dispatch(mxb_files *,const mxb_crt_memory *,const char *,mxb_crt_regs *);
#endif
