# Win32 timing compatibility scaffold

The MX Bikes startup call graph statically references several Kernel32 and WinMM time-related APIs. The portable timing module is the first dependency-oriented runtime component.

| Windows API | Independent helper |
|---|---|
| GetTickCount | mx_get_tick_count |
| timeGetTime | mx_time_get_time |
| QueryPerformanceCounter | mx_query_performance_counter |
| QueryPerformanceFrequency | mx_query_performance_frequency |
| GetSystemTimeAsFileTime | mx_get_system_time_as_filetime |
| Sleep | mx_sleep |

All helpers accept an **injected clock source**. Synthetic tests exercise behavior without original game binaries, and CI cross-compiles the implementation into an AArch64 ELF object. The clock module is currently ABI-independent: it is **not yet connected** to a guest Win64 import dispatcher or running MX Bikes code.

## Limits

- GetTickCount wraps at 2^32 milliseconds. The host callback is responsible for choosing a consistent monotonic epoch; actual Windows boot-time origin is not implemented.
- QueryPerformanceCounter uses nanoseconds at a fixed 1GHz frequency; Windows may expose a different underlying frequency or epoch.
- FILETIME is computed in 100ns intervals from the Windows 1601-01-01 UTC epoch.
- Sleep forwards the requested number of nanoseconds. Callback implementation and timer precision are not provided.
- timeBeginPeriod and timeEndPeriod, Win32 CRT, file APIs, messaging, graphics, audio and Steam are not implemented in this module.
- AArch64 Linux object compilation is not an iOS binary, and does not prove x64 game startup execution.

## Local test

Use any C11-compatible compiler from the repository root:

```sh
cc -std=c11 -Wall -Wextra -Werror -Iruntime runtime/mx_time_compat.c tests/test_mx_time_compat.c -o /tmp/mx_time_test
/tmp/mx_time_test
```
