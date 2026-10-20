#include "mx_import_registry.h"

/* ASCII-only import names, case-insensitive as Win32 module naming requires. */
static int equal_ascii(const char *a, const char *b) {
    if (!a || !b) return 0;
    for (; *a && *b; a++, b++) {
        unsigned char x=(unsigned char)*a, y=(unsigned char)*b;
        if (x>='A'&&x<='Z') x=(unsigned char)(x-'A'+'a');
        if (y>='A'&&y<='Z') y=(unsigned char)(y-'A'+'a');
        if (x!=y) return 0;
    }
    return *a=='\0'&&*b=='\0';
}

mx_import_kind mx_classify_win64_import(const char *dll, const char *symbol) {
    if (!dll || !symbol) return MX_IMPORT_UNRESOLVED;
    if (equal_ascii(dll,"msvcr90.dll") && equal_ascii(symbol,"_acmdln"))
        return MX_IMPORT_DATA_SYMBOL;
    if (equal_ascii(dll,"kernel32.dll")) {
        if (equal_ascii(symbol,"GetCurrentProcessId") ||
            equal_ascii(symbol,"GetCurrentThreadId"))
            return MX_IMPORT_HOST_IDENTITY;
        if (equal_ascii(symbol,"GetTickCount") ||
            equal_ascii(symbol,"QueryPerformanceCounter") ||
            equal_ascii(symbol,"QueryPerformanceFrequency") ||
            equal_ascii(symbol,"GetSystemTimeAsFileTime") ||
            equal_ascii(symbol,"Sleep"))
            return MX_IMPORT_PORTABLE_TIMING;
    }
    if (equal_ascii(dll,"winmm.dll") && equal_ascii(symbol,"timeGetTime"))
        return MX_IMPORT_PORTABLE_TIMING;
    if (equal_ascii(dll,"steam_api64.dll") &&
        (equal_ascii(symbol,"SteamAPI_Init") ||
         equal_ascii(symbol,"SteamAPI_RestartAppIfNecessary") ||
         equal_ascii(symbol,"SteamInternal_ContextInit")))
        return MX_IMPORT_STEAM_SERVICE_REQUIRED;
    return MX_IMPORT_UNRESOLVED;
}

int mx_dispatch_supported_win64_import(const mx_import_runtime *rt,
                                       const char *dll, const char *symbol,
                                       mx_win64_call *call) {
    mx_import_kind kind=mx_classify_win64_import(dll,symbol);
    if (kind==MX_IMPORT_HOST_IDENTITY) {
        if (!rt || !call) return -1;
        uint32_t id=0;
        if (equal_ascii(symbol,"GetCurrentProcessId")) {
            if (!rt->current_process_id) return -1;
            id=rt->current_process_id(rt->identity_userdata);
        } else if (equal_ascii(symbol,"GetCurrentThreadId")) {
            if (!rt->current_thread_id) return -1;
            id=rt->current_thread_id(rt->identity_userdata);
        }
        if (id==0) return -1;
        call->rax=id; /* Win32 DWORD return zero-extends to guest RAX. */
        return 1;
    }
    if (kind!=MX_IMPORT_PORTABLE_TIMING)
        return 0;
    return mx_dispatch_timing_import(rt,dll,symbol,call);
}
