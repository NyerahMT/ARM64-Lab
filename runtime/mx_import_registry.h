#ifndef MX_IMPORT_REGISTRY_H
#define MX_IMPORT_REGISTRY_H
#include "mx_guest_imports.h"

/* Import policy for a future native ARM64 host:
 * Do not confuse known data imports with callable code.
 * Only tested portable APIs are executable here; diagnostic mocks are NOT
 * registered, and SteamAPI_Init is deliberately NOT emulated as success.
 */
typedef enum {
    MX_IMPORT_UNRESOLVED = 0,
    MX_IMPORT_PORTABLE_TIMING = 1,
    MX_IMPORT_DATA_SYMBOL = 2,
    MX_IMPORT_STEAM_SERVICE_REQUIRED = 3,
    MX_IMPORT_HOST_IDENTITY = 4
} mx_import_kind;

mx_import_kind mx_classify_win64_import(const char *dll, const char *symbol);

/* 1 = executed; 0 = not implemented (never claims success); -1 = failure. */
int mx_dispatch_supported_win64_import(const mx_import_runtime *runtime,
                                       const char *dll, const char *symbol,
                                       mx_win64_call *guest_call);
#endif
