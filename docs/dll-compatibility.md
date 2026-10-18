# MX Bikes: DLL compatibility strategy

**Evidence:** [Verified private DLL import audit](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39081993052) of the user's own Windows x86-64 executable, cross-referenced with its previous bounded x64 startup trace. This is not a native iOS port or successful Steam initialization.

## Actual static DLL imports

| Windows DLL | Imported names | Purpose / likely port strategy |
| --- | ---: | --- |
| MSVCR90.dll | 127 | CRT state, constructors, allocation, file semantics; compatible runtime needed |
| OPENGL32.dll | 70 | GL symbols; graphics translation/Metal layer needed |
| USER32.dll | 40 | Windows lifecycle, events, input and window state; platform adapter |
| KERNEL32.dll | 30 | Process/thread/timing/filesystem API adapter |
| WS2_32.dll | 18 | Networking API adapter only if exercised |
| GDI32.dll | 14 | Pixel formats and swapping; platform graphics adapter |
| steam_api64.dll | 10 | Steamworks client/integration; cannot assume native iOS support |
| ADVAPI32.dll | 3 | Registry/security services; investigate call requirements |
| SHELL32.dll | 3 | Platform paths/shell integration |
| WINMM.dll | 3 | Timers and multimedia services |
| DINPUT8.dll | 1 | DirectInput -> controller/input adaptation |
| OLE32.dll | 1 | COM lifecycle compatibility |

Exactly **320 static imported names** across **12 DLLs**. DLL filenames are import references, not 12 DLLs that must be recompiled. Only `steam_api64.dll` appeared in the provided game archives by DLL basename; the other imports are typically provided by Windows or the CRT.

## Verified startup evidence

The existing bounded Unicorn x64 run encountered **290 import call invocations**, all matching static imported names. The heaviest was 251 calls to `MSVCR90!fread`, reading all 250,656 bytes of the private archived Steam DLL. `SteamAPI_RestartAppIfNecessary` was answered synthetically; the next unresolved call is `SteamAPI_Init`. **That is not a valid Steamworks session.**

The public `tools/win64_import_audit.py` separates:
- Independently implemented portable timer behavior (C; **not** yet used by original game startup)
- Private x64-only file read bridge
- Synthetic x64-only diagnostic responses
- Confirmed imported CRT data (`_acmdln`, not callable)
- Steam services requiring genuine integration
- Unknown or unimplemented symbols

**A total of 290 static names remain unclassified or unimplemented** at this stage. The number is not a startup-blocker count; many imports have not been exercised. Dynamic `GetProcAddress` calls are outside this static inventory.

## Native runtime contract

The public `runtime/mx_import_registry.c` resolves only what is independently implemented:

- Six timing methods are allowed to reach the tested `mx_dispatch_timing_import` C implementation.
- The imported `_acmdln` symbol is declared *data*; it must not be given an executable stub.
- `SteamAPI_Init` / `SteamAPI_RestartAppIfNecessary` require a real Steam integration or an authorized design decision; the native registry refuses to return success.
- Unknown graphics, DLL, CRT and system functions remain **unresolved** by default, not fake-success responses.

Native host tests and freestanding AArch64 compilation are green; **the registry has not been connected to translated MX Bikes code or a real iPhone runtime**.

## Next practical gates

1. **Resolve a permitted Steam integration strategy** for the target platform. The Windows Steam DLL cannot simply be copied into an iOS app, and success cannot be hardcoded safely.
2. **Implement a scalable x86-64-to-AArch64 lifting path**, prioritizing entry/callee/callback ABI correctness. The current host interpreter can execute original instructions but is not the native port.
3. **Use observed API calls to sequence work:** start with CRT memory, file and process environment semantics, then window/input, OpenGL graphics and Steam interface calls as they are encountered.
4. **Keep commercial files in private CI** and artifacts metadata-only.

Source evidence: [Private audit](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39081993052) · [Original startup trace](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39081324829) · [Public native registry tests](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39082127133).
