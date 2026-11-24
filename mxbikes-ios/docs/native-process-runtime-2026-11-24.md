# Native process runtime checkpoint — 2026-11-24

## Scope

Portable, bounded x64 guest memory and native ARM64 translation infrastructure.
Original executable bytes are accessed locally or in the private owned-input
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
The installed simulator app passed the source-only native self-test after the
runner started the simulator during compilation and required a fresh marker.
[Public simulator execution](https://github.com/NyerahMT/ARM64-Lab/actions/runs/45341343748)

## Owned iOS startup checkpoint

The private build translates the SHA-256-pinned Windows binary ahead of time.
The app starts its linked ARM64 entry routine directly. Five import values and
16 bytes of initial globals are compiled into the startup module. The Windows
executable is a build-time input only. Its original entry is RVA `0x2AB31C`. The
generated ARM64 code enters the original first CRT initializer, calls five
host-backed time and identity services, returns through the original entry
wrapper, and tail-jumps to RVA `0x2AB02C`. The app retains startup globals,
guest registers and a 4 KiB stack at this boundary. The default original
cookie path takes 40 original instructions. The host services use the
platform's realtime clock, monotonic clock, process ID and thread ID.
[Private installed-simulator pass and unsigned device build](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45343653469)

A separate build-machine directory diagnostic against a mapped image runs the original
caller and complete helper with a virtual Windows executable path. Eight
x64/native cases exercised all 53 original instructions and both CRT imports,
including no separator, drive-relative paths, multiple colons and a high-bit
byte. All eight returned to their caller. The directory diagnostic is
invoked separately from the entry checkpoint. In a separate original heap
initialization test the game called a local leaf, allocated 9,600 bytes,
stored the guest pointer in its global, and cleared the allocation across
three pages. Eight x64/native cases matched.

Run from `mxbikes-ios` with the matching executable outside the checkout.

```sh
python scripts/mxbikes_owned_startup_differential.py --owned-exe "$MXB_EXE"
python scripts/mxbikes_native_cfg_lift.py --owned-exe "$MXB_EXE" --original-filename
python scripts/mxbikes_native_cfg_lift.py --owned-exe "$MXB_EXE" --original-crt heap-init
python scripts/mxbikes_private_apple_directory.py --owned-exe "$MXB_EXE"
xcodegen generate --spec project.yml
```

The first test compares eight original x64 runs against the host-compiled
startup using identical time/identity observations, including a cookie
collision. It checks all 16 general registers, flags, PC, stack bytes,
both cookie globals and call/instruction counts. The Apple build command
writes private generated C in the ignored `runtime/private` directory.
The public build provides the renderer harness. The private build launches
the compiled original startup code automatically.

## Remaining critical path

1. The compiled startup now reaches the original `_initterm` call at RVA
   `0x2AB0EC`. From the native entry it dispatches both `_initterm_e` callbacks
   using a modeled MSVCR iterator, verifies their zero returns, and resumes
   the original caller. The first callback establishes GUI application type,
   initializes exit-pointer globals and file modes, and runs two local helpers.
   The second registers its guest exception filter. Exception delivery and
   binary compatibility with Windows pointer tokens remain unverified.
   The following void initializer table now returns from its first callback,
   registers its exit handler, and supplies one virtual process argument and
   an empty environment using the process CRT adapter. The second callback
   enters the original constructor and writes its initial 24-byte object header.
   The current stop is its first subobject constructor, RVA `0x3042B0`.
   The default path takes 191 original instructions and 13 completed services.
   Eight original x64 comparisons cover the complete stack, argument vectors,
   registered handler, and object header at that boundary.
2. Connect native units from more original control-flow regions to a common
   image-backed process state and route actual original imports to verified
   native adapters; don't silently treat unresolved imports as success.
3. Connect native file I/O and the existing GL bridge to the process state.
   Preserve the tested Win64 stack, heap, and file semantics.
4. Establish legitimate entitlement/platform access and execute authentic
   game startup through the first original OpenGL frame and main menu.

The original-game player-visible milestones remain **0/4**. Dynamic loop
iterations, mapped image bytes, public synthetic fixtures and Apple build
success are not equivalent to percentage of original engine translated.
