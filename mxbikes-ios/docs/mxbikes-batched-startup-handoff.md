# Latest verified platform dependency and native progress — 2026-10-27

Current green CI run 40497252349.

- Three different SHA-verified original game parser/initializer scenarios
  execute in native AArch64 with original independent x64 register and
  stack comparison all the way to Steam CALL RVA 0x1306ED.
- The game processes the complete real 250656-byte owned DLL in each
  scenario, executing 251 original fread/CRC loop iterations, original
  fclose and CRC comparison. The original guest stack persists.
- The executable imports 320 Win64 symbols across 12 DLLs, including
  10 Steamworks symbols, 70 legacy OpenGL32 and WGL functions, and
  other Windows windowing and input APIs.
- Explicit iOS Steam platform gate rejects unsupported original Steam
  calls without changing guest state or inventing any authorization.
- Publisher sells a separate Windows standalone build/license,
  potentially a legitimate non-Steam route with publisher permission;
  this does NOT provide an iOS license by itself.
- Detailed implementation/status:
  docs/mxbikes-ios-platform-decision.md.
- Engine, real renderer, first frame and signed IPA remain unimplemented.
  Player-visible milestones: 0 of 4.

---

# Fused original startup milestone — GitHub Actions 40453582801

Verified green in one compiled AArch64 ELF and ONE preserved guest CPU/
stack state on Unicorn ARM64, resumed across bounded instruction budgets.

- **This supersedes the prior limitation of separately tested native
  parser/initializer/fopen and native DLL CRC paths for ONE fixture.**
- The SHA-pinned original game parser, initializer/cookie, authentic
  fopen and fseek setup carry their existing live state directly into
  actual-file read-only CRT adapters and translated original branch
  instructions (251 fread/CRC iterations, fclose and checksum compare).
- The full 250,656 original privately owned Steam DLL bytes are processed
  without manually reseeding the guest registers or memory at the join.
- Independent original x64 execution for that SAME parser fixture matches
  final guest RAX/RBX/RCX/RDX/R8/R9/RSI/RDI/R11, CPU flags, preserved
  RBP/R12/R13/R14 and authentic Win64 stack return/saved register slots.
- The final guest PC is the original RVA 0x1306ED, immediately before
  steam_api64.dll!SteamAPI_RestartAppIfNecessary, with app ID 0xA008C.
- The imported Steam routine is NOT executed or given an invented result.
  No Steam license bypass, original engine/renderer, iOS executable or
  displayed game frame. User-visible launch milestones remain 0/4.
- Source: scripts/mxbikes_fused_startup_native.py and
  scripts/mxbikes_large_native_executor.py. Both are gated in
  .github/workflows/mxbikes-startup-native-fast.yml.
- Native guest execution uses one emulator CPU and memory, and bounded
  instruction-count slices with preserved registers between calls.
  Do NOT claim this is a single uninterrupted emu_start call or that
  CI under Unicorn is native execution on an actual iPhone.
- Next actions: increase fused case coverage and isolate legitimate
  Steam platform/runtime compatibility before claiming game boot;
  investigate actual renderer/asset code only after a lawful startup path.

---

# Latest native execution boundary — 2026-10-27

CI 40450250150 passed. Original x64 SHA-pinned file processing and
postclose logic are now translated and executed on actual AArch64:

- Starts original Win64 call semantics at RVA 0x1305D9, and executes
  fseek, ftell, rewind, the genuine file-size comparison, 251 fread/CRC
  loop backedges, fclose and original register restores.
- Original game CRC equality/inequality JNE: exact result 0xBC72;
  wrong result reaches original error path.
- Executes native control through original RVA 0x1306ED, the
  steam_api64.dll SteamAPI_RestartAppIfNecessary imported CALL, then
  STOPS WITHOUT EXECUTING THE IMPORT OR INVENTING ITS RETURN VALUE.
- Native register and flags at that exact PC match independent
  original Win64 x64 oracle, app-ID argument RCX=0xA008C.
- Original file bytes used privately: 250,656. Single uninterrupted
  native AArch64 ELF for this code sequence passes.
- Earlier native game prefix through fopen remains a separate test.
  The whole original entry-to-Steam path is NOT YET one linked ELF.
  No Steam client, license state, game engine, graphics, IPA or first
  game frame running. Visible milestones remain 0/4.

Core files: scripts/mxbikes_original_postseek_native.h,
scripts/mxbikes_original_postseek_native.py,
scripts/mxbikes_original_postseek_full_native.py,
scripts/mxbikes_postclose_steam_boundary.py,
scripts/mxbikes_original_steam_frontier_native.py.

NEXT: fuse earlier native startup prefix with postseek execution into
one continuous original guest-state run. Treat the Steam import as a
real unsupported dependency requiring a legitimate platform strategy;
no canned success, injected license result or Steam API bypass.
Then pursue actual engine/renderer initialization.

---

# Current verified native milestone (Actions 40440323561)

- Exact SHA-verified original executable and private owned Steam DLL inputs.
- Single **uninterrupted** AArch64 ELF execution of the native guest
  file-service + original CRC routine across **250,656 actual DLL bytes**.
- **251 original x64 CRC guest-state checkpoints**, verified during this
  same continuous ARM64 run; checksum **0xBC72**.
- Verified file service order: seek-end, tell, rewind, 251 guest-memory
  fread/CRC chunks, close; guest state remains live between all chunks,
  with no x64 emulation used inside the native run.
- Invalid guest address, bad seek, wrong CRC register setting, and closed
  file tests reject unsupported operations. Both the complete single
  execution and prior eight-batch regression are green.
- Code: scripts/mxbikes_native_file_crc_chain.h,
  scripts/mxbikes_native_file_crc_chain.py,
  scripts/mxbikes_native_file_crc_single.py, and
  scripts/mxbikes_crc_cluster_bridge.h.
- **IMPORTANT**: These are native read-only CRT service adapters plus
  authentic original CRC code translation. The original Win64 CALL-site
  sequence connecting startup into those services is not yet translated;
  this is not proof of original engine boot, Steam client execution, or
  any iOS frame. The next task is translating and hooking the original
  0x1305D9 onward CALL/branch CFG with original x64 differential tests,
  up to the unsupported SteamAPI_RestartAppIfNecessary runtime boundary.

---

# MX Bikes: scalable startup execution handoff

Cumulative baseline: use the private branch feat/mxb-multi-root-batches-1022.
Original x64 execution, actual ARM64 guest translations, and iOS game launch
are separate verification tiers. Never conflate their counters.

## CI evidence (run 40411534980)

- Native AArch64 translated startup prefix and owned-file-open status
  remain verified against original SHA-pinned Win64 x64 oracle.
- The NEW reusable x64 multi-block runner streamed ALL 250,656 owned
  steam_api64.dll bytes from the private SHA-verified archive.
- Real x64 original import calls handled by the bounded guest CRT:
  fseek 2, ftell 1, fread 251, fclose 1; total 256.
- Actual original x64 dynamic BASIC BLOCK executions: 251,670.
  Estimated instructions inside blocks: 4,265,702. This is not native
  ARM64 translation or distinct code coverage.
- Distinct original basic block entries: 16, distinct unwind functions: 3.
  The 17-op original CRC-style loop at RVA 0x130670 ran 250,405 times.
- First unsupported service: steam_api64.dll!SteamAPI_RestartAppIfNecessary.
  Fail-closed stop; no Steam client executed or auth result simulated.

## Infrastructure

- scripts/mxbikes_owned_file_crt.py: actual-byte-backed guest FILE*
  read-only service; explicit unsupported import and bad-pointer stop.
- tests/test_mxbikes_owned_file_crt.py: signed seek, file reads, EOF,
  guest pointer checks and unsupported services.
- scripts/mxbikes_startup_batch_runner.py: detailed, bounded original
  x64 trace with unique PCs / hot loop statistics.
- scripts/mxbikes_startup_fast_blocks.py: Unicorn BLOCK-hook original x64
  accelerated execution with guest CRT import callbacks only in the
  trampoline range, original Win64 IAT discovery, unique-block metrics,
  unsupported-service report. Does not execute ARM64.
- .github/workflows/mxbikes-startup-native-fast.yml privately extracts
  the genuine Steam DLL, executes cumulative ARM64/x64 and batch-run CI,
  and archives metadata without original executable or DLL bytes.

## Next engineering batch

1. Native-batch lift of the SHA-pinned original hot CRC loop from RVA
   0x130670 including the real back edge / exit. Compare standalone
   x64 Unicorn CPU / memory state against portable C and ACTUALLY executed
   ARM64 code for varied seeds, buffer sizes, and the full owned DLL.
   Do not infer the CRC formula without validating every original opcode.
2. General native guest CFG control dispatcher across verified blocks,
   tracking memory and Win64 ABI states and diffing original x64 checkpoints.
   Avoid handwritten new test scripts for every three instructions.
3. Preserve SteamAPI_RestartAppIfNecessary as a genuine runtime
   compatibility barrier. Determine legitimate platform integration
   rather than fake successful Steam calls. A Win64 Steam DLL cannot
   execute as native iOS code.
4. Bring up real engine init, graphics, assets, first frame, then menu.
   These milestones remain unfinished.

## Truthful reporting

Distinct original code reached, total original x64 executed instructions,
actually translated and executed ARM64 instructions, and player-visible
milestones are different numbers. At this run, player-visible 0 of 4.
