# Native process runtime checkpoint — 2026-11-24

## Scope

Portable, bounded x64 guest memory and native ARM64 translation infrastructure.
Original executable bytes are accessed only in the private owned-input
workflow. No authentication result, Windows DLL implementation, game boot,
original frame, main menu, or rideable bike is claimed. No commercial binary or
generated original-code module is committed to the public source tree.

## Process components

| Component | Source | Contract |
|---|---|---|
| Guest virtual memory | `runtime/mxb_guest_memory.{h,c}` | Caller-owned backing; sorted non-overlapping regions; R/W/X permissions; checked full-range transfers and cross-region memmove |
| PE image mapping | `runtime/mxb_pe_guest_image.{h,c}` | Original preferred guest base; PE32+ x64 headers, section bounds, zero-fill, section permissions; no relocation or imported DLL resolution |
| CRT call boundary | `runtime/mxb_guest_crt.{h,c}` | Explicit memcpy/memset/memmove, Win64 return slot/shadow-space checks, bounded guest memory; no unknown/Steam imports accepted |
| Resumable native execution | `runtime/mxb_native_exec.h` | Caller-owned CPU + cursor, explicit PC, trace and cumulative guest instruction count |
| Native dispatch registry | `runtime/mxb_native_dispatch.{h,c}` | Disjoint verified instruction-PC sets; native units share CPU/memory/cursor across local frontiers; unknown PCs fail closed |
| Automatic CFG lifter | `scripts/mxbikes_native_cfg_lift.py` | Decode supported forms; generate C; compare actual x64 and compiled AArch64 execution traces, GPRs, defined flags and page hashes |
| Standalone iOS-linked generated module | `runtime/generated/mxb_native_probe.c` | Public synthetic CRT sequence only, generated reproducibly, verified against independent x64 reference, linked into XcodeGen app |

## Verified actual original input

[Private owned-image/CPU/CRT differential](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45339557003), canonical public source at 9f97e54c.

* Original SHA-pinned PE preferred base 0x140000000.
* All seven original sections plus headers mapped, eight guest regions.
* 17,813,504 image bytes, including 4,112,968 original raw/header bytes
  compared against independent PE parsing and 13,700,536 zero-filled bytes.
* 28 section permission checks; no host execution of mapped original image.
* Original nested-loop sequence: 57 unique original instructions, 4,157
  dynamic executions per scenario, eight scenarios, all 16 GPRs, defined
  flags, instruction trace hash/length and seven 4KiB page hashes compared.
* Repeated with six original non-code image data pages (24,576 bytes);
  stack and seeded register state remain synthetic. The same actual-image
  differential passed when split into two independently dispatched native
  code units sharing persistent state. AArch64 execution used two
  bounded four-case ELF runs; no increase to the hard per-run budget.
* Independently executed original local caller and complete leaf callee
  return. Original CRT memcpy and memset E8 CALL and FF25 IAT jump thunks
  were verified against the original import table. Guest arguments and CRT
  service reference are modeled fixtures; the Windows DLL itself is not run.

The PE mapping initially rejected the vendor-added terminal section because
its raw payload length is not aligned to FileAlignment. The fix accepts only
a bounded final payload with at most one alignment unit of tail padding,
without modifying original file bytes or copying beyond the declared payload.

## Public reproducibility and platform integration

```sh
cd mxbikes-ios
python scripts/mxbikes_native_cfg_lift.py --source-only
python scripts/mxbikes_native_cfg_lift.py --source-only --imports-fixture
python scripts/mxbikes_native_cfg_lift.py --source-only --imports-fixture --split-modules
python scripts/mxbikes_native_cfg_lift.py --source-only --imports-fixture --emit-module /tmp/mxb-native-probe.c
diff -u runtime/generated/mxb_native_probe.c /tmp/mxb-native-probe.c
python scripts/mxbikes_native_module_smoke.py
```

Dependencies: Capstone, Unicorn, pyelftools, host C compiler, clang/lld.

[Public native module and unsigned simulator/device app builds passed](https://github.com/NyerahMT/ARM64-Lab/actions/runs/45339045277).
[Public cross-unit synthetic differential passed](https://github.com/NyerahMT/ARM64-Lab/actions/runs/45339373237).
The iOS app calls the same generated synthetic CPU/CRT/guest-memory module
through the C bridge. A subsequent simulator launch gate uses an explicit
`--native-selftest` flag and checks a result marker from the installed app;
do not call that gate a pass until its actual run is inspected.

## Remaining critical path

1. Expand supported instruction forms and use the generic lifter for larger
   verified original functions, especially asset/path handling.
2. Connect native units from more original control-flow regions to a common
   image-backed process state and route actual original imports to verified
   native adapters; don't silently treat unresolved imports as success.
3. Add bounded guest heap/allocator and actual owned-file I/O with verified
   Win64 ABI. Integrate the existing native GL bridge with that state.
4. Establish legitimate entitlement/platform access and execute authentic
   game startup through the first original OpenGL frame and main menu.

The original-game player-visible milestones remain **0/4**. Dynamic loop
iterations, mapped image bytes, public synthetic fixtures and Apple build
success are not equivalent to percentage of original engine translated.
