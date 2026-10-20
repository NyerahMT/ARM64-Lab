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

**Verified second CRT progress (October 19, 2026):** the [private original-game 13-gate CI](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39348733554) is **13/13 green**. The original **49-instruction contiguous second CRT source region** beginning RVA `0x2AB02C` now has a joined **54/54** original x64 / native host C / AArch64 differential through synthetic `_initterm_e` and `_initterm` call-and-return sequences. The end-to-end fixtures span the earlier `GetStartupInfoA` and `Sleep` callbacks, GS/TEB guest state, exclusive single-thread `CMPXCHG`, lock retry/recursive ownership, CRT global-state branching, both original MSVCR90 import JMP thunks, success/error processing, and the post-`_initterm` state transition and `XCHG` lock-release branch. The non-returning `_amsg_exit` branch is **stopped before the call**, not falsely resumed.

The independently tested [post-import original-code differential](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39347936683) matched **32/32** for the original imported CALL/JMP/RET plus its following CRT branch instructions. The [public CRT post-import synthetic regression](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39347588101) passes. The latest private run preserves all previous regression gates.

**Critical limits:** the Win64 CRT imports use **deterministic fake return values**, not execution of actual C/C++ initializer callback arrays or `msvcr90.dll`; no Steam, engine, graphics or iOS build has run. The test source region contains **49 decoded instructions, not 49 executed on each branch**. The complete second CRT unwind region has **126 statically decoded instructions** and is still incomplete. Guest `LOCK`/`XCHG` are single-threaded tests, not concurrent Windows synchronization.

**Original initializer callback discovery:** The two actual CRT initializer tables contain **7 pointer slots / 5 non-null callbacks** ([passing private inventory and 13/13 regression](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39349893684)). `_initterm_e` has two real callback functions: a 52-instruction CRT setup function (MSVCR90 process/locale/error services) and a 6-instruction callback that invokes `Kernel32!SetUnhandledExceptionFilter`. `_initterm` has three: a 19-instruction main-arguments setup function (`__getmainargs` among its dependencies), a 6-instruction startup callback, and a short jump thunk. **Three of these paths share original helper `0x2AB7E4`**. All five are **statically inventoried, not executed**. One of the five lacks a normal unwind boundary, so its 27 disassembled instructions include trailing `int3` padding; do not count that as a complete semantic function body.

**Verified additional callback cluster (October 20, 2026):** [15/15 private real-game gates](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39370512325) and [public synthetic/native/AArch64 checks](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39370339712) passed. The original six-instruction `SetUnhandledExceptionFilter` callback at `0x2AB714` matched native C and AArch64 under **16/16** fixtures; the eight-instruction shared wrapper at `0x2AB7E4` matched **16/16** more, including zero/nonzero return paths, Win64 call stacks and register effects. The Windows API and the wrapper's direct callee `0x2AB734` use **synthetic returns**, so neither the actual callee nor whole initializer arrays were executed on ARM64. The other three callback paths still require translation. The newly verified wrappers are isolated proofs and do not extend the 49-instruction joined CRT execution interval.

**Bounded automated dependency grouping (October 20, 2026):** A generic unwind-aware PE x64 call/jump cluster mapper now follows exact function entries, classifies RIP-relative imports, unresolved edges and strongly connected function groups, and reports incomplete/over-limit decoding rather than silently dropping it. Synthetic [public tests](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39371835104) pass. The [private original-game grouped run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39371961450) passed **16/16** gates including the new cluster inventory. Starting from five CRT/callback roots, it found **6 bounded decoded functions and 6 translation components**, with no frontier truncation. The real child at `0x2AB734` contains **39 instructions and 7 direct IAT calls**. Three initially unresolved direct calls were subsequently verified as six-byte import jump thunks for `msvcr90.dll::_lock`, `__dllonexit`, and `_unlock`; **zero static direct-call targets remain unresolved in this bounded function**. Its other imported calls reach `_decode_pointer`, `_onexit`, and `_encode_pointer`. This narrows implementation to a coherent CRT pointer/on-exit/lock-service cluster, but none of these imported services or this child body have been translated or executed. No child code was translated or executed by this static analysis.

**Next grouped target:** implement the shared child's identified MSVCR90 pointer/on-exit/lock dependency cluster with differential tests, then join actual initializer callback traversal. Continue the 16 independent gates. Do not confuse a passing inventory with a booting game.

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

[See evidence-based milestones](docs/milestones.md) [grouped issue-resolution policy](docs/batched-triage.md), and [CI checks](../../actions).

## Project boundaries

Keep commercial game executables, DLLs, archives, extracted code, and IPA builds out of this public repository. Only our independently written tools, build configurations, and synthetic tests belong here. Seek appropriate permission before distributing derivative software.
