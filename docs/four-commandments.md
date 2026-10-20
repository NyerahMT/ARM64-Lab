# The Four Commandments — MX Bikes native-port development

**Purpose:** Advance toward an original MX Bikes native ARM64/iOS engine boot and usable gameplay without confusing small diagnostic successes for overall port completion. These are priority rules for selecting work, organizing patches, and reporting progress; they do not weaken correctness or licensing boundaries.

## I. Batch the work — not one CRT function per milestone

- Group reachable related functions, import thunks, Win64 services, guest-memory primitives and CFG edges by shared root cause.
- Build and test a coherent cluster. Avoid isolated one-instruction/wrapper milestones unless they unblock a larger batch or establish an essential new capability.
- Diagnose sibling failures together and apply the shared fix once.
- Acceptance: a group moves an actual startup/engine frontier, not merely the count of passing microtests.

## II. Automate translation and verification wherever credible

- Prefer the existing cached Ghidra, Capstone dependency mapper, angr fixture discovery, Remill/LLVM experiment, portable runtime and Unicorn differential harness over manually rewriting each function.
- Do not run an expensive new analysis session per function. Batch targets; cache reusable metadata; pin dependencies; reuse original-code fixtures and generated path models.
- Keep fail-closed behavior for unsupported semantics, ambiguous CFG targets, Win64 import ABI and guest-memory accesses.
- Acceptance: executable native behavior with authentic-original x64 versus host C versus AArch64 evidence across representative branches; synthetic API callbacks must be disclosed.

## III. Probe the engine in parallel with CRT completion

- Maintain a separate, bounded investigation of the *reachable* engine-entry/loader/Steam boundary while the CRT batch continues. Extract only non-proprietary metadata from private analysis.
- Do not block all engine research on perfecting unneeded CRT functions. Prioritize services actually encountered along the executable's startup path.
- Never call an emulated or synthetic-success Steam API a working Steam integration.
- Acceptance: a reproducible verified advancement of the original engine startup frontier, rather than speculation based on static pointers or hardcoded returns.

## IV. Judge progress by player-visible milestones

The strategic milestone sequence is:

1. **Verified native startup:** run required original entry/CRT/runtime initialization with validated guest/ABI/import behavior.
2. **First engine initialization:** original engine path enters and performs meaningful work, with required services resolved.
3. **First rendered frame:** actual game output appears through a functioning graphics bridge, not a test triangle.
4. **First interactive menu:** meaningful original game menu draws and accepts controller/input on the target pipeline.

Only then advance to playable gameplay, stability, performance, and real-device signed iOS packaging. Each report must separate **verified original ARM64 execution**, **static analysis**, **synthetic native tests**, **original x64 emulation**, and **device gameplay**. The number of passing regressions is a quality indicator, not a percentage of game-port completion.

## Non-negotiable engineering constraints

- Preserve regression testing and rollback/diagnostics; prioritize fewer *meaningful* gates over gratuitous one-function achievements.
- Group fixes wherever possible and make runs fail-closed when unsupported.
- Do not put commercial binaries, original-code derivatives, native compiled game objects, DLLs, archives or assets in the public repository or public CI artifacts. Respect distribution/licensing obligations.
- Never claim the engine, renderer, iOS build or game works without corresponding executable evidence.
- If a development action is blocked, report that accurately and continue only with legitimately permitted, independently useful work.

## Current reference point (October 20, 2026)

- The accepted private original-game startup gate is now **24/24** ([verified original-code run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39469888988)). This represents bounded test coverage, **not** a launch, playable native engine or progress percentage.
- **All five non-null callback bodies** in the original two CRT initializer tables have now been independently differentially executed against x64 and host C on **actual AArch64**: app setup `0x2AB234` (52 instructions, 8/8); exception filter `0x2AB714` (6, 16/16); argument setup `0x2AAFC4` (19, 8/8); second-tail `0x320770` (6, 8/8); first-tail `0x320790` (original 2 → wrapper 8 → child 39, 16/16). The 52-instruction app setup verifies initialized PE headers, correct imported writable `_fmode`/`_commode` test-data slots and source guest effects.
- **Neither whole original callback table completes.** The reusable native table walker correctly fails closed at first unresolved `_initterm_e` slot 1 and `_initterm` slot 1; only the two earlier callback paths are invoked through individually bounded authentic table slices. The new function bodies still require real dependency binding and ordered execution. Original local callees and imported MSVCR90 services are injected deterministic test callbacks, not production-compatible implementations.
- The separate 126-instruction CRT routine and Steam's three imported bootstrap APIs still require integration. Native Steamworks lacks documented iOS client support, so developer authorization/alternative interfaces are required; never treat mock Steam success as verified startup.
- No original engine entry, actual game frame, menu, iOS package, or playable iPhone build has been validated.

**Daily execution check:** What is the highest-impact *reachable* bottleneck? Which related fixes can ship as one batch? Can tooling handle them? Does the result advance one of the four strategic milestones?
