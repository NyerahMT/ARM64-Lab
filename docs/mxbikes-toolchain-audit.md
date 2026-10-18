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

## How we remove repeated work

1. **Select from immutable analysis facts.** Private scan `39101884840` exported 290 direct caller/callee leads. It determined 77 closed-callee, no-nested-call pairs across just 10 reusable callee identities. The **fast cached triage** workflow `39102025652` consumed these facts without re-downloading `Game.zip`, scanning PE unwind records, or starting Ghidra.
2. **Amortize shared callees.** First intended target: `0x15C240` (12 static instructions; two internal branches), shared by original short callers `0x2412E0` and `0x241960` (six instructions each). The next native test should lift **the actual callee plus both actual callers**, not one-off isolated call bytes. This is a *candidate*, not a verified cross-function recompilation.
3. **Keep a single Ghidra import alive per investigation batch.** Analyze all selected addresses, caller xrefs, CFG closure, memory effects and decompiler high-P-code in one startup. Export bounded, hash-tied metadata. Avoid another minutes-long cold import for each CLI command.
4. **Separate cheap and expensive Actions.** Cheap code/unit tests and cached metadata rankings run on script changes. Full private original-x64/ARM64 differential tests are explicit, scoped pipelines with exact executable SHA. REA is a separately bounded evaluation, not a prerequisite for passing compiler tests.
5. **Prove semantic equivalence rather than count functions.** Each lifted function must have independently verified boundaries, no unresolved CFG successors, representative success/failure paths, all modified guest-memory regions and register state compared, and a clear note if only an internal region was recovered.
6. **Switch away from bespoke templates when possible.** Add a small **Remill/LLVM instruction lifting pilot** using only an open, synthetic PE fixture before attempting the complete commercial game. Measure instruction coverage, build time, memory and regression mismatches. Reject if integration overhead exceeds the saved work.

## Hard gates to claim a real milestone

- **Original interfunction link:** Two independently identified original function bodies execute together from the original x64 image and match a generated native ARM64 linked pair across meaningful inputs. No fake callee returns.
- **Original startup on ARM64:** Call/return ABI, imports, global state and targetless indirect branches are all correctly handled through the entry path. Millions of *x64 emulator* instructions do not count here.
- **First phone test:** Original game work running in a signed iOS Mach-O app on real Apple silicon, not a freestanding AArch64 ELF under Unicorn.
- **First menu:** Original engine reaches actual asset loading and draws a meaningful UI frame. Only then can we compare it directly against Reflex's iOS progress.

Audit source checkpoints: [Private original-code scan](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39101884840), [private fast cached triage](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39102025652), [verified original backward loop](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39095372274), [verified synthetic nested calls](https://github.com/NyerahMT/ARM64-Lab/actions/runs/39095625844).
