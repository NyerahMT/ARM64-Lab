# MX Bikes iOS — three-tier original-instruction handoff

Updated: 2026-11-23. Scope: original Steam-version EXE SHA-256
`4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6`.

## Purpose

Keep x64 reverse engineering as a reference, **not a separate road to
completion**. Each verified original-game x64 instruction sequence must
eventually become an explicit ARM64 translation contract and a source component
that can be built by the iOS project. Synthetic Windows/Steam results used to
explore the original code are research fixtures, not authentication.

The current project contains a verified **post-Steam timer-state three-
instruction handoff**, not a full original-game translation or iOS game boot.

## Tier 1 — original x64 oracle (private owned-game input)

The SHA-pinned EXE is opened **only in a private GitHub Actions run**, not
stored in public Git history. The validator checks the original Capstone
disassembly at RVAs `0x133F66`, `0x133F6B`, `0x133F70`. It extracts
only those 16 bytes into private test memory, executes the original three
instructions using Unicorn x64, and stops at the next original CALL
(`0x133F76`), **before executing that call**.

The oracle captures RAX, RCX, RDX, flags, RIP and a 32-bit original-image
global value at RVA `0xE4B240`. Five independent seeded cases exercise
the 32-bit register zero extension, preservation of RAX/flags and the
low-DWORD store. The actual private original executable code and memory
contents are not included in public source, C fixtures or public artifacts.

## Tier 2 — compiled ARM64 native translation

The same semantic operations live in **ordinary C**:
`runtime/mxb_poststeam_timer_native.c`,
`runtime/mxb_poststeam_timer_native.h`.

The entrypoint `mxb_poststeam_timer_apply` accepts an explicit
Win64 **guest-state structure**, applies the original operations and
stops at the exact original next PC. It does not dereference a Windows
virtual address from the host. The original game global DWORD is
represented by a bounded guest-state field. Unexpected initial RIP
returns failure without mutation.

`scripts/mxbikes_poststeam_timer_differential.py` compiles and executes
the same translated C under the Linux host and under AArch64 Unicorn. In
**private mode**, expected results come from **independently executed
original x64 bytes**, not a hand-authored test expectation. In public
mode, expected results come from a clearly labeled independent
instruction-semantics fixture; that mode does **not** prove original
binary equivalence.

Passing criteria:

- Original x64 instruction sequence passes exact SHA and disassembly checks.
- All five original x64 guest-state outcomes match the compiled native C on
  the host and AArch64 Unicorn, including the global DWORD and flags.
- Missing / wrong guest PC is rejected without modifying the state.
- The next original game CALL remains unresolved, **not silently treated
  as an implemented engine call**.

## Tier 3 — actual iOS project integration

The C translation source and header are included in `project.yml`.
The native header is exposed through
`ios/MXBViewportPrototype/Bridge.h`. The SwiftUI application invokes
the function on **synthetic guest state** and labels the check explicitly.

Linux public CI compiles this C to an iOS ARM64 Mach-O object. A separate
macOS public CI job generates the actual Xcode project with XcodeGen and
builds an **unsigned iOS Simulator** version of the viewport. It may verify
source and Swift/C bridging integration, but cannot establish iPhone
hardware launch, actual MX Bikes engine execution, original asset loading,
Steam entitlement or real game rendering.

## Machine-readable callsite contract

`contracts/poststeam-timer-v1.json` is the committed bridge linking:

- Original EXE SHA, original input and continuation RVAs, instruction count;
- Original guest-state registers, affected flags and memory-write address;
- The translated C symbol, source file and differential test runner;
- The iOS XcodeGen source list, Swift bridging header and prototype app;
- Unresolved original dependencies, including the following game helper.

The differential runner **rejects stale mappings** when source,
manifest or iOS integration paths disagree. This prevents a verified
x64 discovery from being misplaced in unrelated simulator-only code.

## Next batched milestone

Join the above translated block with the **original post-Steam clock
import / immediately following helper** in a preserved ARM64 guest
state. Every new original callsite should move through the same
reference -> native differential -> iOS integration contract, with
unknown external imports failing closed. Prefer repeated shared Windows
runtime services over one-off original-game code patches.

**Never count** a static call graph, x64 block count, compiled ARM64
object, synthetic Metal frame, synthetic Steam positive response, or
unsigned demo viewport as a playable original game. Player-visible
milestones are still **0/4**.


## Second verified three-tier checkpoint — original E8 CALL into game helper

The first true **cross-function** native checkpoint now executes original
RVAs `0x133F66` through `0x133F76` and the entry of the called original
game helper at `0x2A9AE0` through `0x2A9B06`. It stops before the
helper's first **nested** original game CALL at `0x2A9B08`.

Original x64 operations:

- The previous three timer-state instructions are run first.
- An original `E8 CALL` at RVA `0x133F76` pushes the original
  `0x133F7B` return PC and enters the helper.
- Nine authentic helper-prologue instructions store `RBX` and `RSI`
  in caller shadow-space slots, push `RDI`, allocate a `0x130`-byte
  Win64 stack frame, read the original image security-cookie global at
  **RVA `0x3928A0`**, XOR with post-prologue RSP, save the resulting
  cookie and copy zero-extended `EDX`/`ECX` into `ESI`/`EDI`.
- The native implementation uses an explicitly bounded, fully testable
  1,024-byte **guest stack**, not real Windows pointers or actual iOS
  process stack addresses.

All 13 exact original instructions were disassembled and executed
from the SHA-pinned, privately owned executable in Unicorn x64.
Across five independent fixture inputs, their resulting register,
defined status flags, original timer-global DWORD and **all 1,024 guest
stack bytes** matched the compiled host and AArch64 implementation.
Original security cookie bytes were not exported to source or logs;
the oracle used explicit synthetic test cookie inputs. Undefined
x64 auxiliary flag `AF` from XOR is not asserted.

[Private authentic x64/native AArch64 differential passed](
https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45304495014).

The native translation lives in
`runtime/mxb_poststeam_helper_entry_native.{h,c}` and the
source-only/public plus private-original differential in
`scripts/mxbikes_poststeam_joined_differential.py`.
The explicit machine-readable original-to-native/iOS contract is
`contracts/poststeam-joined-entry-v1.json`.
The C source is included in the XcodeGen project and bridged into
the actual SwiftUI prototype, which calls a C-owned **synthetic**
guest-state smoke test. Both unsigned iOS Simulator and iPhone
ARM64-target applications compiled successfully.

[Public source-only and actual iOS application build passed](
https://github.com/NyerahMT/ARM64-Lab/actions/runs/45304483495).

**Next technical frontier**: original game call at `0x2A9B08`
enters original RVA `0x2838F0`, after which the current helper
uses many more internal calls. Our native join does not translate
that target, does not maintain a complete process-wide Win64
memory model, and does not execute the full MX Bikes engine.

**Milestone assessment**: the scoped 13-instruction cross-function
native checkpoint is complete (100%); the overall original-game
playable milestones remain **0/4 (0%)**. No original game graphics
have been rendered on iPhone or in native ARM64 game execution.
