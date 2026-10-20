# MX Bikes reverse-engineering toolchain audit — 18 October 2026

This is a measured workflow decision for the privately owned original Windows x86-64 game. **No original commercial executable, pseudocode, recovered game source, or native object files belong in this public repository.** All such testing stays in the private `NyerahMT/ReflexBuildInput` CI workspace. External tools below do not grant distribution rights to the original game.

## Technical reality

- PE inventory: 12 imported DLLs, 320 static imports. The bounded original x64 runtime passes CRT file handling and reaches `SteamAPI_Init` after about 4.27 million executed original guest instructions, with test-only compatibility responses.
- Five original unwind-backed branch-free function bodies (140 instructions) have passing x64 ↔ generated AArch64 differential tests. Additional *original code regions*, not confirmed complete callable functions, cover 11 conditional/memory instructions and a 14-instruction indexed backward loop.
- A restricted original imported Win64 API CALL at RVA `0x2AB9AE` maps to a working native timing-registry test; the entire surrounding game function does not run natively.
- Signed backward loops (81/81) and genuinely linked caller→callee functions (72/72) passed **synthetic** ARM64 comparison tests.
- No original engine/Steam lifecycle, native iOS Mach-O runtime, menu, renderer, or gameplay runs yet. These metrics are not percentages of translated game code.

## Specific tools and correct roles

| Tool | Recommended role | What it does *not* solve |
| --- | --- | --- |
| **Ghidra 12.1.4** (pinned SHA, cached) | Authoritative static PE function identification, code ranges, call-graph reconstruction, CFG, P-code and target-function dossiers | Does not generate a working iOS port on its own |
| **Reverse Engineer Anything (REA), morluto/rea** | Optional agent-facing CLI/MCP front end around Ghidra; function assembly, call/xref discovery, P-code dossiers, immutable Evidence and exact-result snapshots | Not an x64→ARM64 compiler; Ghidra projects are ephemeral, and new cache misses can still trigger cold analysis |
| **Capstone** | Targeted fast disassembly and instruction-boundary verification; keep it for private byte-range checks | Not a general-purpose lifter |
| **Unicorn x64 / AArch64** | Exact differential harness, guest-state/ABI effects, memory read/write traces, error reproduction | Not native signed iOS execution or production-compatible performance |
| **Clang/LLVM + LLD** | Portable semantics compiled to freestanding ARM64; future arm64-apple-ios/Mach-O toolchain gate | Cannot reconstruct unknown program control flow or Windows behavior automatically |
| **Remill / McSema** | High-priority **feasibility experiment** for instruction-semantics-scale x64→LLVM IR lifting; Remill supports x86-64 and is designed as a reusable lifting library. McSema adds binary CFG lifting but traditionally depends on IDA and has integration burden | Does not remove the need for correct recovered CFG, image loading, Windows ABI, and imports |
| **rev.ng** | Controlled, isolated input/function experiment only; full original PE quick-lift was killed (exit 137), and smaller launcher lift timed out (exit 124), so neither finished a verified LLVM artifact | Do not promote to primary tool without proving complete bitcode generation under memory/time limits |
| **FEX / Wine** | Linux ARM64 cross-check/prototype possibility, not today's iPhone pipeline | Linux ABI/rootfs and host graphics thunking do not directly work as an iOS App Store runtime |

Official REA: https://github.com/morluto/rea, published `rea-agents` npm package; use a pinned, genuinely published version and the existing Ghidra installation. REA's main branch and npm releases can differ. Do not copy lookalike/forked setup instructions and do **not** run its agent setup inside GitHub CI. Its Linux Ghidra provider needs Java, Node, procps and a bounded analysis startup deadline.

### Measured REA pilot on the original executable

Private workflow [39102065870](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39102065870) successfully ran official, isolated npm `rea-agents@6.5.0` against the exact verified original PE with existing Ghidra 12.1.4 and JDK 21. The direct Ghidra analysis CLI returned valid parseable JSON and exit 0 after **222 seconds**. The optional/global `doctor` command exited 1 in this ephemeral runner (the separate analysis still succeeded). The GitHub source release v6.6.0 was **not yet available on npm** when first attempted; version 6.5.0 was confirmed on npm and pinned. Only sanitized job metrics were retained. **REA's overview success does not demonstrate a faster workflow than direct Ghidra or the ability to recompile a function.** Avoid a fresh analysis session per routine; batch a selected set of function dossiers in one provider session.

## How we remove repeated work

1. **Select from immutable analysis facts.** Private scan `39101884840` exported 290 direct caller/callee leads. It determined 77 closed-callee, no-nested-call pairs across just 10 reusable callee identities. The **fast cached triage** workflow `39102025652` consumed these facts without re-downloading `Game.zip`, scanning PE unwind records, or starting Ghidra.
2. **Amortize shared callees.** First intended target: `0x15C240` (12 static instructions; two internal branches), shared by original short callers `0x2412E0` and `0x241960` (six instructions each). The next native test should lift **the actual callee plus both actual callers**, not one-off isolated call bytes. This is a *candidate*, not a verified cross-function recompilation.
3. **Keep a single Ghidra import alive per investigation batch.** Analyze all selected addresses, caller xrefs, CFG closure, memory effects and decompiler high-P-code in one startup. Export bounded, hash-tied metadata. Avoid another minutes-long cold import for each CLI command.
4. **Separate cheap and expensive Actions.** Cheap code/unit tests and cached metadata rankings run on script changes. Full private original-x64/ARM64 differential tests are explicit, scoped pipelines with exact executable SHA. REA is a separately bounded evaluation, not a prerequisite for passing compiler tests.
5. **Prove semantic equivalence rather than count functions.** Each lifted function must have independently verified boundaries, no unresolved CFG successors, representative success/failure paths, all modified guest-memory regions and register state compared, and a clear note if only an internal region was recovered.
6. **Switch away from bespoke templates when possible.** Add a small **Remill/LLVM instruction lifting pilot** using only an open, synthetic PE fixture before attempting the complete commercial game. Measure instruction coverage, build time, memory and regression mismatches. Reject if integration overhead exceeds the saved work.

## Verified advancement since the initial audit

- The original linked-call milestone is now **verified**, not just a candidate. Two original six-instruction callers (`0x2412E0`, `0x241960`) reach one original 12-instruction callee (`0x15C240`). Private x64 reference execution and AArch64-linked C pass 48/48 differential tests. The compiled ELF independently contains an AArch64 `BL` into the shared translated callee: [verified private run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39103113140).
- **Ghidra independently confirmed all three exact function entries, instruction counts and recovered end addresses**, plus the two original direct-call edges: [private headless Ghidra validation](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39108857646).
- **Remill instruction-lifting feasibility**: a legacy official-publisher container produced an LLVM IR function from an entirely synthetic AMD64 instruction in isolated CI: [synthetic-only Remill pilot](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39108999839). This is LLVM IR generation, *not* compiled AArch64, semantic equivalence or a scalable whole-game recompiler.
- The next program-level gate is to replace strict individual opcode-pattern translations with broad instruction lifting, and check the resulting state changes across representative tests. Startup/Steam/graphics are still pending.

### Verified Remill → LLVM → AArch64 object experiment

A synthetic-only isolated toolchain test completed on October 18, 2026: [GitHub Actions run 39109492273](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39109492273). An older official-publisher Remill container lifted three independent x86-64 instruction forms—memory store, integer add, and compare—into typed LLVM IR. LLVM 14 then assembled and verified all three modules and generated **three genuine AArch64 relocatable object files**. The two arithmetic/compare objects each retain one undefined Remill helper, and the store object retains two undefined helpers. These are *not linked nor executed* and cannot yet substitute for the existing hand-tested original-code translator.

The next feasibility gate is connecting Remill's guest-state and memory semantics, resolving those runtime helpers, executing synthetic ARM64 code, and verifying behavior against x64. After that, test a verified original function privately. The old LLVM 11/14 combination is research-only, not the long-term iOS pipeline.

## New Remill/LLVM production-feasibility evidence (18 October 2026)

- **8/8 verified original game bodies accepted and compiled to AArch64 relocatable objects** under the legacy isolated Remill AMD64 → LLVM11-typed IR → LLVM14 pipeline: [private first coverage run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39174813977). The eight include three Ghidra-confirmed linked-call bodies, four SSE math routines and one indexed-record writer. Each still needed 4–5 runtime symbols; no lifted game code was executed by this run.
- The [first-block comparison run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39175060693) found full-body IR unequal to first-instruction IR for all eight and unequal to the first sequential basic-block IR for all three branching bodies. The five straight-line routines matched the initial-block IR because the block is the whole body. **Difference is not proof that every branch or call is recovered.** Remill's single-trace lifting should not be confused with an end-to-end binary recompiler.
- **A genuine Remill-generated ARM64 memory write executed successfully** with a bounded memory helper: [synthetic test](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39175569820). The test linked the exact `__remill_missing_block` and `__remill_write_memory_32` functions needed by the small instruction sample, then matched an original x64 memory write on Unicorn ARM64.
- **First real original-game Remill semantic execution:** [private original-instruction run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39175814048) lifted the actual first instruction at `0x15C240`, a 64-bit stack store, and linked bounded `__remill_write_memory_64` and missing-block callbacks into executing ARM64 ELF. Under zero-initialized guest registers, the ARM64 helper observed exactly the guest write the original x64 instruction performed (address 8, 64-bit value 0). **Exactly one original instruction**, not the entire 12-instruction callee.

**Implication:** Remill has earned a place as a serious instruction-semantics candidate; replacing pattern-specific translators is justified only after extending memory/register state mapping and multi-block CFG execution with real original-code x64↔ARM64 differential testing. The current LLVM11-to-LLVM14 path remains research-only. REA/Ghidra remains responsible for function/CFG recovery; Remill remains the semantics layer; imported Windows behavior still requires a separate runtime.

## Hard gates to claim a real milestone

- **Original interfunction link:** Two independently identified original function bodies execute together from the original x64 image and match a generated native ARM64 linked pair across meaningful inputs. No fake callee returns.
- **Original startup on ARM64:** Call/return ABI, imports, global state and targetless indirect branches are all correctly handled through the entry path. Millions of *x64 emulator* instructions do not count here.
- **First phone test:** Original game work running in a signed iOS Mach-O app on real Apple silicon, not a freestanding AArch64 ELF under Unicorn.
- **First menu:** Original engine reaches actual asset loading and draws a meaningful UI frame. Only then can we compare it directly against Reflex's iOS progress.

Audit source checkpoints: [Private original-code scan](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39101884840), [private fast cached triage](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39102025652), [verified original backward loop](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39095372274), [verified synthetic nested calls](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39095625844).


## 20 October 2026 — service-focused tooling decision

The pinned private original-game dependency-cluster gate [39372412654](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39372412654) passes 16/16 independent tests. It identifies the 39-instruction CRT child at RVA `0x2AB734` and all its direct service dependencies: seven RIP-relative IAT calls to `msvcr90.dll::_decode_pointer`, `_encode_pointer`, and `_onexit`, plus three verified six-byte import thunks for `_lock`, `__dllonexit`, and `_unlock`. Its **direct static call graph is resolved**, but the function and its imported services are not translated or differentially executed.

### Ranked next tooling

1. **Wine MSVCR90 source and compatibility tests: adopt immediately as behavioral references.** Wine `dlls/msvcr90/Makefile.in` reuses its `dlls/msvcrt/exit.c`, `lock.c`, and `misc.c`. These contain analogous `__dllonexit`, `_onexit`, `_lock`, `_unlock`, and pointer codec behavior. Wine's `dlls/msvcr90/tests/msvcr90.c` tests pointer round trips, encoded null, and compatibility with Windows `EncodePointer`. Model the *contract* in independently authored, bounded guest-memory C runtime code; test null/error, pointer-table reallocations, callback order, lock ownership, and process-local encode/decode consistency. Do not copy Wine LGPL source without checking distribution obligations. A synthetic token codec cannot decode arbitrary real Windows pointer tokens; choose one consistent in-process abstraction for the native runtime and injected deterministic callbacks for x64-vs-ARM64 reference comparisons.
2. **angr/Claripy: bounded experiment for auto-generating execution-path fixtures.** Use only the 39-instruction function with imported services hooked, strict state/instruction ceilings, and recorded import-call sequences. Test whether it discovers distinct return/error paths and guest memory writes more effectively than our handcrafted Unicorn fixtures. Keep Unicorn as the reference execution oracle. angr analysis is not the AOT translator.
3. **Qiling: optional private x64 PE loader/API-hook prototype.** Its PE loader, imported API hooks and Windows environment could reduce custom fixture setup when moving beyond a small isolated CRT child. Already having a proven Win64 import registry and Unicorn execution means this is **not** worth migrating to without an objective reduction in setup or runtime work. Qiling is GPLv2; keep it out of the shipped native runtime unless licensing has been addressed.
4. **DDisasm/GTIRB: optional independent PE x64 function/CFG validation.** Evaluate only if Ghidra/Capstone disagree on a difficult indirect-target or function-boundary case. It creates a structured binary representation; **it does not by itself translate a PE into a working AArch64 iOS binary**.
5. **Ghidra, Capstone, Remill and LLVM: retain rather than replace.** Batch cached Ghidra dossiers for selected function families, keep Capstone as a cheap boundary verifier, and expand Remill/LLVM only where complete CFG and imported call semantics can be validated. Previously measured REA startup took 222 seconds and did not outperform the existing pipeline; rev.ng's full PE lift failed or timed out. Microsoft's llvm-mctoll explicitly lists Windows binary support as future work; it is not a shortcut here.


### Pilot execution outcome — 20 October 2026

- **CRT model:** `runtime/mx_crt_services.h` and `runtime/mx_crt_service_dispatch.h` are independent, explicitly synthetic service contracts covering the six imported MSVCR90 names. Native host tests and a freestanding AArch64 ELF executed in Unicorn passed ([public CI](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39375413047)). Win64 arguments and returns are checked by the typed adapter. Production import registry still classifies these symbols as unresolved; a passing service model is *not* a validated Windows service.
- **angr 9.3.4 pilot:** Early run failed due an incompatible latest `bitstring` dependency; pin `bitstring==4.3.1`. The next run was invalid as evidence of OUR symbolic hooks because angr's default PE imports were already hooked. `replace=True`, a `hooked_by` type check, and a check that at least one model stub executed fixed that defect. Verified private [run 39375232352](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39375232352) succeeded: 2 completed symbolic paths, 2 unique candidate imported-return models, 14 original child block addresses, 23 basic-block steps, 0 errored/pruned states, 0.74 seconds of analysis. Its complete CI duration is longer due to Python tool installation and private input retrieval.
- **Scope:** Uses deterministic/symbolic import doubles, not real `_lock`/on-exit/encoding runtime implementation in angr; the native C prototypes are separate. Generated fixtures need a real original x64-vs-AArch64 differential before being counted as correct. This is a feasible small-target path generator, **not** reason to replace Capstone, Ghidra, Remill, Unicorn, or the compiler.
- **Workflow:** angr remains in a *separate bounded private GitHub Actions job*. The production original-game 16-gate grouped CI remains distinct; it can reuse the tested public native service adapter in a preflight without making angr a dependency. Do not silently return success from unsupported guest APIs.

### Pass/fail experiment to prioritize

- Use Wine's CRT contract/tests as *reference material* to specify independent ARM64 guest-memory-compatible pointer, on-exit, and synchronization services, then test those individually on host and AArch64.
- Try one bounded angr run on the original 39-instruction child: generate input fixtures and report unique CFG paths, new branch outcomes, unresolved dependencies and wall-clock cost. Reject if installation/analysis overhead exceeds the manual fixture savings or if opaque imported services make path results unusable.
- Add child + real service callbacks to the private differential gate and require original x64, native C and AArch64 guest effects to match before replacing synthetic return paths in the larger CRT startup chain.
- Keep private commercial bytes, derived recovered code, and the executable out of the public repository and uploaded CI artifacts.

References: [Wine MSVCR90 build sources](https://github.com/wine-mirror/wine/blob/master/dlls/msvcr90/Makefile.in), [Wine MSVCR90 tests](https://github.com/wine-mirror/wine/blob/master/dlls/msvcr90/tests/msvcr90.c), [Wine exit/onexit behavior](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/exit.c), [Wine CRT locking](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/lock.c), [angr documentation](https://docs.angr.io/en/latest/core-concepts/symbolic.html), [Qiling Windows PE emulation](https://github.com/qilingframework/qiling/wiki/Windows-Emulation), [DDisasm/GTIRB](https://github.com/GrammaTech/ddisasm), [llvm-mctoll support matrix](https://github.com/microsoft/llvm-mctoll).

