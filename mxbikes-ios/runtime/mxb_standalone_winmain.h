#ifndef MXB_STANDALONE_WINMAIN_H
#define MXB_STANDALONE_WINMAIN_H
#include <stdint.h>
#include <stddef.h>
/* Semantic lift of beta21e WinMain's initial frame and argument parser.
 * The caller verifies executable identity and maps these effects to guest
 * storage. No original instruction bytes are embedded. */
#define MXB_WINMAIN_MAX_ARGS 128u
#define MXB_WINMAIN_MAX_COMMAND 4096u
typedef struct {
    uint64_t frame_rsp, saved_cookie, instance, previous_instance;
    uint32_t show, argc;
    uint64_t argv[MXB_WINMAIN_MAX_ARGS];
} mxb_winmain_prefix;
/* command must be a writable, NUL-terminated guest buffer, with no overlap
 * with out. On rejected input neither command nor out is modified. The
 * result models observable startup fields, not all volatile registers/flags. */
int mxb_winmain_prepare(mxb_winmain_prefix *out,uint64_t entry_rsp,uint64_t cookie,
                         uint64_t instance,uint64_t previous,uint32_t show,
                         uint64_t guest_command,uint64_t argv0,
                         uint8_t *command,size_t size);
/* Copy a bounded Windows module path and retain the directory prefix,
 * including the last slash; drive-only paths become drive-root paths.
 * Preserves the original helper's bytes after its inserted terminator.
 * Input and output must not overlap; on rejection output is unchanged. */
#define MXB_WINMAIN_PATH_CAP 260u
int mxb_winmain_module_directory(uint8_t *out,size_t capacity,
                                 const uint8_t *path,size_t size);
#endif
