# ARM64-Lab

An experiment in ahead-of-time recompilation of Windows x86-64 applications for ARM64. The goal is to preserve original application behavior, not recreate it in a different engine.

**Current status: a complete original 39-instruction CRT initializer translated and differentially executed on ARM64, plus additional narrow authentic functions and bounded x64 startup emulation. Not a playable game, a native iOS build, or a running engine.**

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

## Verified first original CRT initializer on ARM64 (October 19, 2026)

The original entry wrapper at RVA `0x2AB31C` calls the security-cookie initializer at RVA `0x2AB954`, then tail-transfers to the **still-untranslated** main CRT routine at RVA `0x2AB02C`.

**The entire 179-byte, 39-instruction first initializer now has an executable, restricted x64-to-C CFG translation that compiles and runs as AArch64 ELF under Unicorn.** The private [original-game differential CI run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39286558413) passed on its second attempt (10/10 reference cases; native smoke exit 0). The pinned original exe and all generated original-code derivatives remain in the private runner.

- Both original security-cookie branches are exercised: eight non-default-cookie inputs and two default-cookie inputs using five tested Kernel32 timing/identity interfaces.
- Nine static basic blocks and nine direct/control-continuation edges are recovered. Native host C and ARM64 Unicorn outputs match the original Unicorn x64 reference for the tested subset of guest registers and flags, 128 bytes of guest stack, global security-cookie/complement values, executed-instruction bitmap, call count and call order.
- The native Win64 import registry uses **deterministic injected host callbacks**, not real Windows services or a Steam session. This is a **restricted Capstone instruction-to-C control-flow lift**, not full-function execution by Remill, nor a general x86-64-to-ARM64 recompiler.
- The previous [seven-case Remill branch proof](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39207913661) remains an independent partial-path result. Its naive whole-span call/return handling was not used for the now-verified complete CFG differential.
- [ARM64-Lab public CI](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39292823081) passed strict C compilation and synthetic branch/import continuation tests.

**Next CRT routine analyzed:** [Private static inventory](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39293785688) verified 518 bytes, 126 decoded original x64 instructions, **53 candidate blocks**, 20 conditional branches, 28 internal direct branch targets, seven imported callsites, one GS/TEB memory reference, one LOCK-prefixed operation and 11 additional instruction families. Validated imported symbols include `GetStartupInfoA`, `Sleep` and MSVCR90 lifecycle functions. These figures are static metadata only.

**New native runtime primitives:** [Public CI](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39294624028) also validates bounded GS-relative guest TEB reads and a **strictly single-threaded** 64-bit compare-exchange helper (success, mismatch, unmapped memory and exclusive-access refusal). The tests run natively under GCC and cross-compile for AArch64. These helpers are not yet wired into translated original second-CRT code; in particular, the helper does **not** implement the x64 `LOCK` prefix's concurrency guarantees or full flags semantics.

**Next original CRT executable progress:** [Private original-game CI](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39299957358) joined the initial **12 actual x64 instructions** from the 126-instruction second CRT routine at `0x2AB02C` in a restricted ARM64 translation. The original x64 reference, host C and Unicorn AArch64 ELF matched **12/12 fixtures**, including the original Win64 `CALL` across a deliberately **synthetic** 104-byte `GetStartupInfoA` response, the original GS/TEB read and single-threaded guest compare-exchange. Six test cases exercised each compare outcome; selected register values, 512 bytes of guest stack, guest globals and zero flag matched. **It stops before the original JE at `0x2AB064`; the remaining 114 original instructions have not been differentially verified.** This experiment does not implement real `GetStartupInfoA`, multithreaded `LOCK` guarantees, a full CRT startup, Steam or an iOS app.

The independent [first-five-instruction](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39298579583) and [subsequent GS/compare-exchange six-instruction](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39299572277) tests both passed **12/12** before the joined trial. The public [strict synthetic native regression suite](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39299208356) is also green.

**Next gate:** translate that larger CRT routine at `0x2AB02C`, including Windows GS/TEB access, atomic `lock cmpxchg`, loader state and additional Win64 imports. Then join the verified entry wrapper and two CRT callees into one ARM64 entry path. No real Steam session, MX Bikes engine, graphics or iOS package has booted.

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
