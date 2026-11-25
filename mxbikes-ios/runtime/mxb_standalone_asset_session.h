#ifndef MXB_STANDALONE_ASSET_SESSION_H
#define MXB_STANDALONE_ASSET_SESSION_H
#include "mxb_standalone_files.h"
/* Caller-owned, zero-initialized session. All mounted file descriptors and
 * their guest handles are owned by this session. Do not copy or move it
 * while active; it and its file table must outlive all dispatches.
 * Paths are supplied by trusted platform code, never by the guest. */
typedef struct {int fd;uint64_t size;} mxb_asset_source;
typedef struct {mxb_files *files;mxb_asset_source sources[MXB_FILE_MOUNTS];unsigned count;} mxb_asset_session;
int mxb_asset_session_init(mxb_asset_session *,mxb_files *);
/* expected_size==UINT64_MAX means no exact size check. */
int mxb_asset_session_mount(mxb_asset_session *,const char *name,const char *path,uint64_t expected_size);
void mxb_asset_session_close(mxb_asset_session *);
#endif
