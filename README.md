# ARM64-Lab

An experiment in ahead-of-time recompilation of Windows x86-64 applications for ARM64. The goal is to preserve original application behavior, not recreate it in a different engine.

**Current status: bounded original x64 startup emulation plus a restricted, compiler-backed ARM64 translation/Win64 import-dispatch proof. Not a playable game, a native iOS build, or a running engine.**

## What works

- Read-only Windows PE32+ inspection, including imported APIs and exception/unwind records.
- Searching a locally owned executable for candidate return-value instruction sequences.
- Lifting two trivial x86-64 patterns (zero return and immediate constant return) to freestanding C.
- Cross-compiling those generated C functions to AArch64 object code.
- Executing a **synthetic Win64 imported-CALL sequence** under Unicorn x64, translating it automatically to C and executing the resulting AArch64 ELF with the actual native timing/import registry (not merely compiling it).
- Translating a **single authentic MX Bikes imported-CALL instruction** at RVA `0x2AB9AE` (`KERNEL32.dll!GetTickCount`) into native C and executing its observable call effects in Unicorn ARM64; its enclosing game function remains untranslated.
- **Five complete authentic MX Bikes function bodies** now have bitwise x64-versus-generated ARM64 differential matches: four branch-free SSE math routines (RVA `0x267AE0`, `0x266D80`, `0x266E20`, `0x266EB0`) and a bounded integer/global-memory record writer (`0x258BB0`). These cover 140 original x64 instructions, but represent narrow patterns rather than a general recompiler.
- **Original multi-basic-block control flow now verified in ARM64 emulation:** 11 instructions from an unwind-backed MX Bikes branch region at `0x2B212C–0x2B215E` were automatically translated, with 128/128 host and AArch64 comparisons matching the x64 reference across both branch paths. This is **not a complete recovered original function** (the prologue is outside the interval), and the translator remains limited to selected MOV/TEST/JE/ADD/RET patterns and explicitly mapped guest memory.
- **Backward loops and signed arithmetic flags:** a 7-instruction synthetic x64 loop passed 81/81 host/AArch64 differential cases, and a 14-instruction **original MX Bikes** indexed backward-loop region (`0x1FC710`) passed 32/32 x64/native ARM64 cases. It is a bounded original code region, not a full recovered function.
- **Original linked-game calls now verified:** two original six-instruction Win64 callers (`0x2412E0`, `0x241960`) reach one shared 12-instruction original callee (`0x15C240`). The original x64 chain and compiled AArch64 C translation passed 48/48 differential cases; a native ARM64 `BL` target was independently verified. Ghidra also confirmed all three exact recovered function entries and call edges. This is strict pattern-specific lifting, not a general executable translator. The separate synthetic two-function test passed 72/72 cases.
- **Remill general-semantics feasibility:** all nine selected genuine MX Bikes function *byte spans* generated LLVM IR that compiled into AArch64 objects, with runtime helpers still unresolved at that stage; comparing first blocks versus full spans did not establish complete CFG recovery ([private evidence](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39175060693)).
- **Authentic game instruction executed via Remill-generated ARM64 code:** one original x64 64-bit guest stack-store at `0x15C240` was lifted via Remill/LLVM, linked to bounded guest-memory/missing-block helpers, executed in Unicorn AArch64, and produced the same observable store as the original x64 instruction under a zero-initialized fixture ([private proof](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39175814048)). **Only one instruction** of this callee was executed through Remill; no entire game function has yet been validated via that lifter.
- A fail-closed native import registry for six timing interfaces, a confirmed CRT data import, and unsupported Steam calls; native C and AArch64 compilation tests pass.
- Private x64 startup traces have executed original CRT callbacks and read the actual archived Steam DLL, reaching `SteamAPI_Init` under emulated Windows services. These are x64 emulation results, **not native translated startup**.
- Synthetic regression tests through GitHub Actions, without any original commercial binaries.

A byte-pattern match is not proof of a true callable function boundary. A cross-compiled object is not proof that original game code runs on iOS.

## Current startup target (October 18, 2026)

The verified private PE entry wrapper at `0x2AB31C` calls the CRT security-cookie initializer at `0x2AB954` before transferring to the larger CRT startup routine at `0x2AB02C`. Run `python -m tools.startup_gate /private/path/mxbikes.exe` for fail-closed read-only inspection of the exact entry chain; do not commit the executable or function bytes.

- **Diagnostics verified in private Actions:** the initializer's 179-byte unwind interval decodes into 39 x64 instructions, with one conditional branch, five indirect calls, nine RIP-relative memory instructions, and sixteen distinct mnemonics.
- **Remill/LLVM feasibility verified in private Actions:** all nine selected original code regions, including this initializer, generated LLVM IR and compiled into AArch64 objects. An object file does **not** prove the initializer's complete control-flow graph or semantics have been translated; no full original startup function has executed on ARM64.
- **Native import compatibility:** five Windows calls observed while emulating this initializer on x64 now have callback-backed host dispatch primitives: GetSystemTimeAsFileTime, QueryPerformanceCounter, GetTickCount, GetCurrentProcessId, and GetCurrentThreadId. Process/thread IDs require genuine host callback providers, not guessed constants. A translated original function is not yet connected to these callbacks.
- **Next acceptance gate:** complete static-to-executable CFG recovery, connect real Win64 API callbacks and verify the full initializer against original x64 behavior. No Steam or engine-initialization success can be inferred from the current tests.

## Verified startup execution and current blocker (October 19, 2026)

- [Private differential run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39207913661): **7/7** original x64 versus Remill-generated ARM64 fixtures matched on the first CRT initializer's **15-instruction early-return path**. The ARM64 code uses a bounded guest-memory implementation and checks the security-cookie complement, stack writes and return address. This is not all 39 instructions, or complete guest register-state equivalence.
- [Private CFG check](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39209743713): the original initializer decodes into **nine static basic blocks and nine direct/control-continuation edges**, with five imported-call sites. This is a control-flow *map*, not executable multi-block translation.
- [Unsupported-branch diagnostic](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39209149365): the default-cookie branch in legacy Remill `--bytes` mode reported five function-call events and four return events, which cannot represent faithful execution of the original one-RET function. This path deliberately fails closed; it must not be reported as working Win64 API integration.

**Next gate:** translate and verify the recovered control-flow blocks and their transitions, then hand off at each Win64 import boundary to the already tested native API registry. Compare the full initializer against original x64 reference traces before advancing into the rest of CRT startup. No Steam session, engine or iPhone app has booted.

## Local commands

Run these commands from the repository root:

    python -m unittest discover -s tests -v
    python -m tools.pe_probe /path/to/local/mxbikes.exe --json /tmp/pe_inventory.json
    python -m tools.leaf_lift --exe /path/to/local/mxbikes.exe --limit 10
    python -m tools.leaf_lift --exe /path/to/local/mxbikes.exe --rva 0x1549a --emit-c /tmp/leaf.c
    clang --target=aarch64-unknown-linux-gnu -ffreestanding -c /tmp/leaf.c -o /tmp/leaf.o
    readelf -h /tmp/leaf.o

The example RVA refers to a specific local executable revision; offsets may change.

## Next

Scale beyond one-instruction import calls: translate full functions and control flow, preserve guest memory/Win64 ABI/exception state, connect a production-compatible host runtime, and only then tackle original assets, OpenGL-to-Metal rendering, controller input, and iOS packaging. Steam initialization remains unresolved. Keep all original game binaries and derived native objects private.

[See evidence-based milestones](docs/milestones.md) and [CI checks](../../actions).

## Project boundaries

Keep commercial game executables, DLLs, archives, extracted code, and IPA builds out of this public repository. Only our independently written tools, build configurations, and synthetic tests belong here. Seek appropriate permission before distributing derivative software.
