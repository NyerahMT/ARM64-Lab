#include <stdint.h>
#include <stdio.h>
#include "mx_import_registry.h"

typedef struct {
    uint64_t mono;
    uint64_t real;
    uint64_t ns_slept;
} fake_host;
static uint64_t mono(void *p) {return ((fake_host*)p)->mono;}
static uint64_t real(void *p) {return ((fake_host*)p)->real;}
static void sleep_cb(void *p, uint64_t n) {((fake_host*)p)->ns_slept+=n;}
static uint32_t process_id_cb(void *p) {(void)p; return 0x1234U;}
static uint32_t thread_id_cb(void *p) {(void)p; return 0x5678U;}
static uint32_t invalid_id_cb(void *p) {(void)p; return 0U;}
static int write_cb(void *p, uint64_t address, const uint8_t *b, uint32_t size) {
    (void)p; (void)address; (void)b; (void)size; return 0;
}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)

int main(void) {
    fake_host host={12000000000ULL,0,0};
    mx_clock_source clock={&host,mono,real,sleep_cb};
    mx_import_runtime rt={&clock,write_cb,&host,&host,process_id_cb,thread_id_cb};
    mx_win64_call call={0};
    CHECK(mx_classify_win64_import("MSVCR90.DLL","_acmdln")==MX_IMPORT_DATA_SYMBOL);
    CHECK(mx_classify_win64_import("kernel32.dll","GetTickCount")==MX_IMPORT_PORTABLE_TIMING);
    CHECK(mx_classify_win64_import("WINMM.DLL","timeGetTime")==MX_IMPORT_PORTABLE_TIMING);
    CHECK(mx_classify_win64_import("KERNEL32.DLL","GetCurrentProcessId")==MX_IMPORT_HOST_IDENTITY);
    CHECK(mx_classify_win64_import("kernel32.dll","GetCurrentThreadId")==MX_IMPORT_HOST_IDENTITY);
    CHECK(mx_classify_win64_import("steam_api64.dll","SteamAPI_Init")==MX_IMPORT_STEAM_SERVICE_REQUIRED);
    CHECK(mx_classify_win64_import("steam_api64.dll","SteamAPI_RestartAppIfNecessary")==MX_IMPORT_STEAM_SERVICE_REQUIRED);
    CHECK(mx_classify_win64_import("OPENGL32.DLL","wglCreateContext")==MX_IMPORT_UNRESOLVED);
    CHECK(mx_classify_win64_import(0,"Sleep")==MX_IMPORT_UNRESOLVED);
    CHECK(mx_dispatch_supported_win64_import(&rt,"kernel32.dll","GetTickCount",&call)==1);
    CHECK(call.rax==12000);
    CHECK(mx_dispatch_supported_win64_import(&rt,"kernel32.dll","GetCurrentProcessId",&call)==1);
    CHECK(call.rax==0x1234U);
    CHECK(mx_dispatch_supported_win64_import(&rt,"KERNEL32.DLL","GetCurrentThreadId",&call)==1);
    CHECK(call.rax==0x5678U);
    rt.current_thread_id=0;
    CHECK(mx_dispatch_supported_win64_import(&rt,"kernel32.dll","GetCurrentThreadId",&call)==-1);
    CHECK(call.rax==0x5678U);
    rt.current_thread_id=invalid_id_cb;
    CHECK(mx_dispatch_supported_win64_import(&rt,"kernel32.dll","GetCurrentThreadId",&call)==-1);
    CHECK(call.rax==0x5678U);
    rt.current_thread_id=thread_id_cb;
    call.rcx=9;
    CHECK(mx_dispatch_supported_win64_import(&rt,"kernel32.dll","Sleep",&call)==1);
    CHECK(host.ns_slept==9000000ULL);
    uint64_t previous=call.rax;
    CHECK(mx_dispatch_supported_win64_import(&rt,"steam_api64.dll","SteamAPI_Init",&call)==0);
    CHECK(call.rax==previous); /* Never synthesize Steam success */
    CHECK(mx_dispatch_supported_win64_import(&rt,"msvcr90.dll","_acmdln",&call)==0);
    CHECK(mx_dispatch_supported_win64_import(&rt,"OPENGL32.dll","wglCreateContext",&call)==0);
    puts("PASS: native import registry refuses Steam and data as executable shims");
    return 0;
}
