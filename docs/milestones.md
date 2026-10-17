# Development gates

The percentages in project updates refer to explicit milestones, not a fraction of game code translated.

| Gate | Criteria | Status |
| --- | --- | --- |
| D0 | Inventory a local Windows PE32+ input safely | Complete locally |
| D1 | Extract limited x86-64 return-sequence candidates, generate C, compile AArch64 object | Verified in private CI against original MX Bikes input; still only isolated byte-pattern lift |
| D2 | Establish true callable function boundaries and differential reference behavior | In progress: Ghidra headless startup call graph plus one x64-vs-C-vs-ARM64 200-case cross-product differential proof |
| D3 | Scalable lifting of original code, indirect branches, guest stack, Windows x64 ABI and exceptions | In progress: restricted scalar SSE lifter translated one 24-instruction original function automatically; most ISA/control flow/runtime features not yet implemented |
| D4 | Execute real original entry path in host/native ARM64 runtime | Not started |
| D5 | Load original archives and bridge OpenGL drawing | Not started |
| D6 | Render interactive original menu | Not started |
| D7 | Gameplay, controller input, iOS device build | Not started |

## Local binary diagnostics

- User-supplied executable SHA-256: 4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6
- PE32+ / x86-64. Image base: 0x140000000. Entry RVA: 0x2ab31c.
- Imported APIs: 320 across 12 DLLs.
- Valid Windows unwind begin/end records: 8,741. This is NOT a verified count of distinct callable functions.
- Short candidate return-value patterns found in raw executable section: 609. These may include byte coincidences or non-entry code.
- One candidate at RVA 0x1549a was converted to C and compiled to an AArch64 ELF64 object, both locally and in private GitHub Actions CI (2026-10-17).
- Of 609 raw byte-pattern candidates, zero started at the 8,741 recorded Windows unwind-function starts; function boundaries remain unverified. This does not establish that none are real leaf functions.
- Private CI decoded 8,563 of 8,741 Windows unwind-record intervals; 2,717 interval starts were referenced by direct calls and 605 intervals ended with a straight-line return (2026-10-17).
- Only two short straight-line interval starts were directly call-referenced, including an SSE math candidate at RVA 0x267AE0 with 196 direct call references. An unwind interval may cover only a fragment, not the entire function.
- The x64 vector-cross-product routine at RVA 0x267AE0 (24 instructions) was run under Unicorn x64. Both a manually written C equivalent and a **restricted automatic Capstone x64 SSE-to-C lift** were compiled to AArch64 and executed under Unicorn ARM64. All 200 normal-range float32 test pairs matched bit-for-bit across original x64, native C, generated C, and both ARM64 binaries (2026-10-17). This is a single supported straight-line function, not general game recompilation.
- Ghidra 12.1.4 headless, using the **verified original private executable**, recognized 4,903 functions and 122 thunks, including the entry function at RVA 0x2ab31c (2026-10-17).
- Bounded four-edge-deep static traversal from that entry found 94 nodes and 101 call edges. Of these, 22 distinct external API names were identified (Kernel32, User32, WinMM, MSVCR90, Steam API). The main startup initialization branch passes through RVA 0x136710; candidate high-fanout internal call sites include RVA 0x133e80 (26 mapped callees) and RVA 0x135cd0 (21 mapped callees).
- Ghidra calls and unwind records are different static signals: its 4,903 recognized functions are **not** 4,903 independently recompilable, behaviorally verified functions.
- The Ghidra headless toolchain is pinned, SHA-256 verified and cached in private CI for repeatability. Exports contain metadata only.
- Startup roadmap from the 2026-10-17 Ghidra snapshot grouped 24 static external-call edges into 22 distinct API names, spread across CRT/process, timing, file paths, window/message, drawing, and Steam lifecycle categories. 53 internal graph nodes reached the four-level analysis cutoff, so the report is not a complete call graph.
- Platform-neutral Win32-style timing helpers now implement GetTickCount/timeGetTime rollover, QueryPerformanceCounter/Frequency, FILETIME conversion, and Sleep forwarding using injected host clock callbacks. Native deterministic unit tests and a freestanding AArch64 cross-compile passed in CI (2026-10-17). A guest import/Windows ABI bridge and iOS-specific clock sources are not yet implemented.
- Expanded five-level Ghidra analysis (2026-10-17): 317 static graph nodes, 390 call edges, 76 external-call edges to 59 distinct API names, with 186 depth-limit nodes still unexplored. The analyzed code includes 17,695 sampled instructions and 86 distinct mnemonics; these are static observations, not executed instructions.
- Newly exposed dependencies include SteamAPI_Init, OpenGL32.wglCreateContext/wglMakeCurrent, GDI SwapBuffers, User32.CreateWindowExA, Kernel32.LoadLibraryA/GetProcAddress, and associated teardown. All 59 observed names were assigned a compatibility category in the refreshed roadmap.
- Original Win64 register-argument import-dispatch scaffolding now routes six timing APIs into deterministic clock helpers through a bounded guest-memory write interface. Native synthetic tests and freestanding AArch64 object compilation passed. No actual original Win64 imports have been invoked through this adapter yet.
- Official rev.ng successfully created its PE/COFF parse-binary model from the original executable. A subsequent full-program LLVM lift failed with exit code 137 under a 6 GiB container memory limit; this is a resource-constrained failure, not proof that lifting is unsupported.
- No translated original game code has been executed on iPhone, and no original engine/menu has booted.

Do not commit game executables, DLLs, archives, or derived original source files to this public repository.
