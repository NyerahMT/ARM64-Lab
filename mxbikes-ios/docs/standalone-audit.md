## Publisher standalone target audit

MX Bikes has a publisher-sold standalone Windows edition. That is a possible
**legitimate** route for removing a *Steam-client dependency* from the port,
but it is neither automatically licensed by a Steam purchase nor a native iOS
build. We must inspect the actual owned standalone executable first.

From the public repository root on your own computer, with the original
standalone executable **outside the checkout**:

```sh
python mxbikes-ios/scripts/mxbikes_standalone_import_audit.py \
  --standalone-exe /path/to/publisher-licensed/standalone/mxbikes.exe \
  --out /tmp/mxb-standalone-audit
```

The output `standalone-candidate-imports.json` includes an independent SHA,
entry point, exception record count, and Steam/graphics/Windows import
inventory. It does not copy the EXE, assets, original code, keys, or game
memory. It never executes the candidate.

A report with zero `steam_symbol_count` only means **no static imported
Steam API symbols were found**. It does *not* prove that the original program
will initialize without Steam, that its licensing is valid, or that it has
a functioning engine/renderer. A new SHA needs its own original-code trace,
CFG map, and independent native ARM64 validation: the Steam EXE's pinned RVAs
must NOT be reused as if they were the standalone layout.

See [authenticated original game execution](run-original-locally.md) for
the *Steam* target. Those tests still stop at the unsupported Steam API.

## Public beta21e demo research target (November 24, 2026)

The publisher's publicly distributed beta21e demo was downloaded and
extracted transiently on a standard public GitHub runner. Its observed
executable SHA-256 is
`b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742`.
The import audit identified 11 DLLs, 310 imported symbols and **zero static
Steam imports**. This is a distinct executable from the private Steam build.

The separate `mxbikes_public_demo_entry.py` reference runner starts at the
PE's real entry, maps original sections with bounded permissions and
models only basic Win32 clock and process identity calls. It stops at any
unsupported import, fault or execution budget. It never supplies a licensing
success result or changes demo restrictions.

No private repository workflows, credentials, commercial assets or owned
Steam binaries are needed for this public demo experiment. The workflow
downloads the public installer directly from its publisher, verifies the
extracted executable's pinned SHA before execution, and deletes the temporary
files. Only aggregate diagnostic metadata is emitted. It is still x64
reference execution, not native ARM64 translation or a booted game.

## Standalone reference frontier (November 25, 2026)

The [official public demo reference run](https://github.com/NyerahMT/ARM64-Lab/actions/runs/45652227449) opened an actual MX Bikes window under Wine on x86-64 and captured two 1280x720 screenshots. It is a desktop compatibility reference, not the native ARM64/iOS port. The [bounded standalone startup run](https://github.com/NyerahMT/ARM64-Lab/actions/runs/45570595336) executed 64 original x64 instructions with six modeled Windows environment calls, then stopped at MSVCR90.dll!_initterm_e. Neither used a Steam client. The full licensed edition remains distinct from the demo.

The next reference-runner implementation provides a bounded _initterm_e callback walker: an independently authored 48-byte Win64 guest routine calls original executable targets in table order, skips null pointers and returns the first nonzero callback result. Only immutable original image tables with executable targets and verified callsite provenance are accepted. Unsupported callbacks and dependencies remain fail-closed. Four native x86-64 Microsoft-ABI smoke cases passed locally for the walker; integrated Unicorn regressions and the actual beta21e callback trace are pending. This is not native ARM64 translation, a full CRT, or a license implementation.

### Both CRT tables implemented in the standalone reference runner

The additional void _initterm walker executes every non-null original callback regardless of EAX. The checked _initterm_e walker stops on the first nonzero 32-bit result. Eight native x86-64 Microsoft-ABI cases passed locally, including 32-byte caller shadow space, stack alignment, null/empty tables and nonzero results. The embedded guest code was assembled independently. The reference runner now checks callback return stack and preserved registers and reports verified callsite metadata for unsupported imports. Integrated Unicorn regressions and original demo execution remain pending; no ARM64 engine or game menu is claimed from these changes.

### Typed CRT data and process state

The standalone runner now separates four known MSVCR90 data imports from executable IAT thunks: _acmdln, _wcmdln, _fmode and _commode. The backing page has documented text-mode/default commit values, explicit virtual command-line pointers, and a one-argument, empty-environment vector. Three bounded startup services track application type, locale-mode flags and no-wildcard __getmainargs outputs. Unknown modes, invalid/overlapping output pointers and foreign imports remain unsupported; no real locale, heap, wildcard expansion, exception or license service is implemented. Seven pure-Python service/layout tests passed locally; two additional integration fixtures were added but require Unicorn. The original beta21e runtime trace has not yet been rerun.

### Native standalone CRT process component milestone

The standalone process data and three process services now have a portable C implementation in `runtime/mxb_standalone_crt.c` (relative to mxbikes-ios). It writes little-endian Win64 guest data, resolves exactly four typed MSVCR90 globals, checks the fifth stack argument, handles 32-bit scalar widths, and preflights all output spans before modifying guest memory. The caller must guarantee that writes to prevalidated spans cannot fail. It is not yet connected to the native game importer.

Local verification: all 21 numbered smoke checkpoints returned success on x86-64 Linux, both optimized and UBSan-enabled. Both implementation and fixture compiled as arm64-apple-ios15.0 Mach-O objects; the freestanding AArch64 Linux smoke ELF linked successfully. ARM64 execution and actual game startup were not tested. No original game files or CI runs were used. Run the repeatable host/build tests with `python mxbikes-ios/tests/test_mxb_standalone_crt_native.py`.

### Milestone: original standalone WinMain handoff (November 25, 2026)

A local, SHA-pinned, single-stepped x86-64 CPU reference experiment (not an iOS launch) on the original beta21e executable reached the original WinMain entry, RVA 0x136c60, from the original PE entry after 977 original instructions. Both initializer tables completed: checked table 3 slots / 2 returned callbacks / status 0; void table 4 slots / 3 returned callbacks. argc=1, application type=GUI, three exit callbacks registered. No Steam services or licensing decisions were modeled. Execution stopped before the first WinMain instruction. The six initial Windows environment services and exception-filter registration were modeled; exception dispatch is not implemented.

The native C service module now also handles reversible process-local pointer tokens (not Windows-compatible tokens), bounded exit registration (no execution at exit), and ASCII-only lead-byte checking in the modeled initial C locale. The native module passed 32 smoke checkpoints with optimized host and UBSan builds and both C sources compiled as iOS ARM64 Mach-O objects. Eight bridge tests passed locally, and the exact native host bridge was used in a second local 977-instruction trace.

The repeatable Unicorn runner can now opt into the native C services and stop at the verified original WinMain call boundary:

```sh
cc -shared -fPIC -O2 mxbikes-ios/runtime/mxb_standalone_crt.c -o /tmp/mxb-crt.so
python mxbikes-ios/scripts/mxbikes_public_demo_entry.py --demo-exe /path/to/official/demo/mxbikes.exe --native-crt-library /tmp/mxb-crt.so --stop-at-winmain
```

The local single-step harness was experimental and is not distributed; the updated Unicorn runner has not yet been executed because Unicorn is unavailable locally. Neither this reference trace nor ARM64 compilation proves native ARM64 execution of the game. No original executable bytes or assets are committed. Next frontier: decode and translate the standalone WinMain body.

### WinMain initial semantic lift and module directory frontier

The same pinned official beta21e executable was traced from PE entry through WinMain's first original callee. Default arguments: 995 original x64 instructions at the first callee return (RVA 0x136c96). With a modeled GetModuleFileNameA result and bounded strcpy/strrchr implementations the original trace reached RVA 0x136cbc (immediately before SetCurrentDirectoryA) at 1,452 original x64 instructions. This uses the original executable under a local experimental x64 single-step harness; it does not run the full game or translate those instructions in place.

Added native C semantic lifts for the initial WinMain frame, security-cookie store and command-line argument parsing (including in-place separators, quoted strings, malformed quotes, and the 128-entry argument limit), plus the executable-directory extraction helper. The caller must verify the binary and apply the returned startup fields to actual guest storage. No native importer integration is claimed. The parser matched original observable fields, argument pointer offsets and changed buffer bytes in 16 local differential cases (default empty input plus synthetic inputs). The path helper matched the original full 260-byte storage region in 11 differential cases, including drive-relative, mixed separators, UNC, empty and maximum-length paths. The initial implementation of colon lookup was corrected to use the last colon, matching the original strrchr call.

Fifteen source-only regression checkpoints passed optimized host and ASan/UBSan builds; both C files compiled as arm64-apple-ios15.0 Mach-O objects. ARM64 execution was not available. Local differential harness is not distributed. Repeatable source-only test: python mxbikes-ios/tests/test_mxb_standalone_winmain.py. Next step is a bounded native filesystem/current-directory service and application of the translated startup fields in the importer. No original game bytes, license bypass, or private workflow use.

### Virtual working directory and multimedia clock milestone

Added a native bounded platform model for SetCurrentDirectoryA / GetCurrentDirectoryA semantics, a caller-advanced 32-bit wrapping millisecond clock, and balanced 1 ms virtual timer period registration. The directory namespace admits only the configured virtual root and its drive root. No host directory is changed, no actual assets are opened, and no physical timer resolution is changed. Twenty-five numbered checks passed the optimized host and ASan/UBSan builds. Both sources compiled to arm64-apple-ios15.0 Mach-O objects.

Local experimental reference trace, same pinned beta21e executable, native C CRT and new native C platform model: 249,866 original x64 instruction executions in a total 250,000-step budget (including the modeled import/CRT transitions). Actual imported SetCurrentDirectoryA returned success for the configured virtual directory; timeGetTime was serviced twice and timeBeginPeriod once. The guest clock advanced deterministically by original instruction count, not wall time. Trace stopped on budget at RVA 0x285d83 inside an initialization loop. Instruction executions are not unique instructions, translated instructions, or an estimate of completeness. No game window, asset loading, native ARM64 engine execution, or licensing modification was demonstrated. The new component was exercised through the local reference harness but is not yet wired to the committed Unicorn runner or the iOS importer. Next: characterize the remaining startup dependencies without changing any demo restrictions, and integrate the supported platform calls into the portable importer. Repeatable source-only test: python mxbikes-ios/tests/test_mxb_standalone_platform.py.

### Native import batch: filesystem, heap and memory operations

Three connected native C modules now unify the earlier process and virtual directory services with a bounded 16 MiB, 256-block guest allocator and bounded CRT byte-memory operations. The allocator implements malloc/calloc/free, including 16-byte alignment, first-fit reuse, capacity limits, overflow handling and rejection of invalid frees. The memory model implements memset/memcpy/memmove/memcmp with preflight checks and bounded guest callbacks. No real host heap pointer is returned. Realloc, general filesystem I/O, sockets and a full Windows runtime remain unsupported.

Local verification: 25 unified import checkpoints, 17 heap checkpoints and 16 byte-memory checkpoints passed (58 native checks), including sanitizer executions. Ten Python/C integration tests passed and all eight implementation/fixture translation units cross-compiled into ARM64 iOS Mach-O objects. Source-only repeatable tests:

```sh
python mxbikes-ios/tests/test_mxb_standalone_batch.py
python mxbikes-ios/tests/test_mxb_demo_native_startup.py
```

A local experimental single-step x64 reference harness using the exact native service library reached the original standalone's next actual unsupported import. Successive traces: 287,069 instructions / 819 unique addresses at malloc; 287,075 / 825 at memset; 287,083 / 833 at WS2_32.dll ordinal 115. The last trace used a genuine guest allocation and byte fill, and retained both initializer-table completion results. Instruction totals include repeated work; they are not ARM64 translation coverage. No networking result was fabricated, no licensing behavior changed, and no menu rendered. The experimental local harness is not distributed.

The committed Unicorn runner now has a separate optional unified backend and records hot RVAs, unique addresses and heap use:

```sh
cc -shared -fPIC -O2 mxbikes-ios/runtime/mxb_standalone_{crt,platform,heap,memory,imports}.c -o /tmp/mxb-startup.so
python mxbikes-ios/scripts/mxbikes_public_demo_entry.py --demo-exe /path/to/official/demo/mxbikes.exe --native-startup-library /tmp/mxb-startup.so --instruction-limit 1000000
```

The Unicorn-specific wiring is not yet execution-tested locally, and the native iOS importer still needs integration. No original executable bytes or assets committed. No Actions runs started.

### Batch: local Winsock setup, variadic formatting, indirect-call provenance and read-only mounted files

A local original-code x64 reference trace, using the same SHA-pinned official beta21e executable and exact native C runtime, advanced from 287,083 executions / 833 unique original addresses to 290,025 executions / 1,939 unique original addresses. These counts are not translated ARM64 instructions or a game completion percentage.

Verified ordinal 115 as WSAStartup using the public Winsock specification and the Wine ws2_32 ordinal table; Win64 WSADATA is modeled as 408 bytes. The new backend implements bounded Winsock 2.x initialization/cleanup, error-state access, byte-order conversions, IPv4 numeric parsing/formatting, and the explicitly configured localhost IPv4 name and reverse-name mapping. A bounded guest heap allocation owns each returned local address record, released by freeaddrinfo. No sockets, external DNS, server responses, network login or license behavior are modeled; unsupported transport calls stop the runner. The original startup's observed local loopback resolution sequence completed.

Added a bounded Win64 sprintf subset for literal text, integer conversions including Windows 32-bit long, strings and characters, reading argument five onward from the guest stack. Width/precision, floating-point, %n, unsupported specifiers and invalid destinations remain unsupported. The original address-formatting call returned. A separate conditional IAT fallback verifier checks original/mapped instruction bytes, exact observed call/jump trace, null fallback pointer and live IAT destination; the next allocation wrapper was accepted and ten additional original malloc calls were reached after the earlier boundary.

The next actual original import is MSVCR90!fopen, requesting core.ini in rb mode. No genuine core.ini was present in the local executable-only upload. Implemented an explicitly mounted read-only flat file namespace: fopen, fread, fseek, ftell, fclose, feof, ferror, fgets; no host paths from guest data, synthetic config, missing-file fallback, write mode or general Windows filesystem. Capacity: 16 immutable caller-selected files, 32 generation-tagged handles, 64 MiB per file. Real asset contents stay outside the repository. Binary streams only; unmounted requests are rejected rather than pretending file absence. The module has fixture validation but the original game was not run past fopen.

Local checks: all five optimized and ASan/UBSan native suites passed (102 numbered checkpoints: 25 unified imports, 17 heap, 16 memory, 24 network/format, 20 file). Fifteen native Python/C bridge tests and eight conditional-callsite tests passed. Thirteen translation units (eight C implementations plus five fixtures) compiled as iOS ARM64 Mach-O objects. All 15 staged source/test blobs were verified against locally tested source hashes. The final Unicorn-specific optional asset and callsite wiring is unexecuted locally (Unicorn unavailable), and the iOS native importer is not yet integrated. No CI usage or original executable/assets committed.

Build and source-only regression:

```sh
python mxbikes-ios/tests/test_mxb_standalone_batch.py
python mxbikes-ios/tests/test_mxb_demo_native_startup.py
python mxbikes-ios/tests/test_mxb_demo_conditional_callsite.py
cc -shared -fPIC -O2 mxbikes-ios/runtime/mxb_standalone_{crt,platform,heap,memory,imports,winsock,format,files}.c -o /tmp/mxb-startup.so
python mxbikes-ios/scripts/mxbikes_public_demo_entry.py --demo-exe /path/to/official/demo/mxbikes.exe --native-startup-library /tmp/mxb-startup.so --asset /path/to/official/demo/core.ini --instruction-limit 1000000
```

Next milestone: real asset/config parsing using the genuine standalone installation, followed by graphics/window initialization. No ARM64 game execution or menu rendering is claimed.

### Complete bounded read-only streaming asset module

Replaced the 64 MiB whole-file mount limitation with random-access sources up to the signed Win64 CRT long offset limit (2,147,483,647 bytes), retaining 64 MiB per fread call and 16 KiB per backing read. The existing memory-backed fixtures remain supported. The full scoped binary read lifecycle now includes fopen, fread, fseek, ftell, fclose, feof, ferror, fgets, fgetc, clearerr and rewind. Short reads and source failures maintain distinct EOF/error state, partial fread item counts, independent file cursors, and no guest writes on invalid destination preflight. Guest-selected host paths, write mode and arbitrary Windows filesystem remain unsupported. Backing storage must not be changed while mounted.

The new host adapter opens explicitly selected regular files, retains read-only descriptors and callbacks, and streams without copying entire packages into RAM. The verified beta21e directory option checks the original executable SHA-256, core.ini SHA-256, and exact observed sizes of all twelve data files (the other eleven assets are size-checked, not independently hash-verified). The prior public demo reference job 139339475363 recorded core.ini as 179 bytes and SHA-256 92d455770a96575e75239b317408d0c5516fbf087d5f28b3a8646e22f06b07bf. The current runtime cannot download the public installer (DNS unavailable), and the private release contains ZIP assets not accessible as local bytes through the connector. No synthetic config is substituted for the original game.

Local verification: 30 numbered native stream lifecycle checks passed optimized and ASan/UBSan builds. The implementation and smoke fixture compiled as arm64-apple-ios15.0 Mach-O objects. Nine host/Python-to-native integration tests passed, including a real sparse 1,751,015,009-byte fixture matching the recorded tracks archive size, large-offset seeking, multi-chunk reads, underlying truncation, explicit mount hash rejection, invalid output handling and cleanup. The synthetic fixture is not the original archive. The actual game has not been rerun past core.ini. The updated unified startup/Unicorn wiring remains unexecuted in this environment; iOS importer integration is not yet proven.

Repeatable source-only tests:
```sh
python mxbikes-ios/tests/test_mxb_standalone_batch.py
python mxbikes-ios/tests/test_mxb_demo_assets.py
```

With the genuine extracted public beta21e directory and a locally built native startup library:
```sh
python mxbikes-ios/scripts/mxbikes_public_demo_entry.py --demo-exe /path/to/demo/mxbikes.exe --native-startup-library /tmp/mxb-startup.so --demo-assets-dir /path/to/demo
```

### Native sandbox file adapter and iOS target source integration

The POSIX asset-session component binds caller-selected regular files to the same streaming guest file table using read-only descriptors and bounded pread. It handles short reads and EINTR, rejects final-component symlinks, nonregular files, incorrect sizes and duplicate guest names, and invalidates handles before descriptor release. Generation numbers survive session closure, preventing stale handle aliasing. This component is intended for native platform code in the iOS sandbox; paths must come from trusted platform code, not guest strings.

All 21 native POSIX checkpoints passed both optimized and ASan/UBSan Linux host builds, including a real sparse 1,751,015,009-byte fixture, multi-chunk reads, truncation and descriptor release. The Python asset tests now include reopening a file table without accepting a stale token (10 tests passed). No original assets were available for either fixture.

The XcodeGen target and Swift bridging header now include the existing ten standalone native components (CRT, directory/clock, heap, memory, import dispatch, local Winsock, formatter, streaming files, descriptor-backed asset session and WinMain helpers). This is build configuration integration, not an original-game launch or proven Xcode link. The actual iOS SDK is unavailable here; the POSIX adapter and final Xcode project have not been compiled on Apple hardware. The user must supply the genuine standalone package before the original game's asset reads can be validated.

Repeatable POSIX test: python mxbikes-ios/tests/test_mxb_standalone_asset_session.py.

### Roadmap Batch A: package ingestion / Batch B: automated scalar leaf pilot

Batch A's new package tool verifies a local directory or stages an explicitly supplied ZIP into a new directory, requiring one common parent, exact manifest sizes, pinned hashes for the demo EXE and core.ini, no duplicate basenames, no traversal/symlinks, and streamed extraction with CRC verification. Other files are size-checked (not publisher-authenticated). It never creates a replacement configuration. Fourteen fixture tests passed. Local preflight of the real uploaded beta21e EXE (renamed mxbikes.exe for inspection) passed its SHA-256, but all twelve data assets are absent. Genuine configuration parsing and resource loading are still blocked, so Batch A's original execution exit gate is not satisfied.

Batch B has an independently useful automated leaf pilot. It pins the standalone demo SHA-256, decodes with LLVM objdump, verifies decoded bytes against executable PE sections, inventories unwind intervals and direct CALL targets, ranks membership in the static PE-entry/WinMain call graph, and generates private C with guest GPRs and bounded memory callbacks. It accepts only straight-line scalar operations and plain RET, rejecting unsupported destinations, control flow, and nonvolatile-register changes. Guest flags and RET control effects are not modeled, so this is not a general x64-to-ARM64 translator. The caller must provide guest memory callbacks and the original guest address mapping. Fourteen synthetic translator tests passed, including host-compiled register width, sign extension, memory and fault checks.

Actual beta21e pilot: 735,694 byte-matched linear decoded addresses; 8,747 PE unwind intervals; 4,244 direct-call target candidates; 172 intervals and 232 direct targets in the bounded static startup graph. Generated and compiled host shared and iOS ARM64 Mach-O objects for 119 bounded leaf candidates covering 720 original decoded instructions; 17 candidates belong to that static graph. All 119 are unwindless; direct-call-target discovery is not proof of a complete function boundary or dynamic reachability. No original differential tests, ARM64 execution, joined startup, or game frame were demonstrated by this pilot. Generated source and binaries remain private. No original game bytes, generated code, or assets are committed. No Actions runs started.

Reproduce with LLVM installed:
```sh
python mxbikes-ios/scripts/mxb_demo_package.py verify /path/to/demo
python mxbikes-ios/scripts/mxb_demo_package.py stage-zip /path/to/demo.zip /private/new-demo
python mxbikes-ios/tests/test_mxb_demo_package.py
python mxbikes-ios/tests/test_mxb_demo_leaf_batch.py
python mxbikes-ios/scripts/mxb_demo_leaf_batch.py /path/to/demo/mxbikes.exe /private/new-lift
```

Remaining Batch B gates: general control flow and calls, stack/unwind and flags, SIMD/floating point, import dispatch, original x64 vs actual ARM64 differentials and continuous native execution. These remain incomplete; the pilot is not full-game recompilation.

### Roadmap Batch B: unwind-bounded scalar CFG and direct-call linking

Added a separate ahead-of-time C generator for bounded original scalar control-flow graphs. It models the sixteen guest GPRs, RIP, known/unknown arithmetic status flags, callback-mediated little-endian memory, stack pushes/pops, conditional branches, loops, direct calls and RET. The caller must supply bounded memory callbacks, a guest return sentinel and a finite instruction budget. Unknown flags stop execution rather than fabricating branch outcomes. Cross-interval transfers are limited to direct CALL/JMP targets at exact unwind starts; conditional branches and ordinary fallthrough cannot escape the interval. Unsupported instructions reject the graph. No imported API calls, SIMD, exception/unwind semantics, general indirect branches, or integrated guest process execution yet.

Same pinned public beta21e executable: LLVM disassembly matched 735,694 decoded addresses to raw executable bytes; 8,747 unwind intervals inventoried. Initial interval-only pass compiled 474 CFG candidates (46 with branches). With cross-interval direct-call linking, 481 candidate graphs compiled as one iOS ARM64 Mach-O object: 53 containing branches, 8 containing calls, 7 spanning multiple unwind intervals, 4,285 summed graph instruction nodes / 4,089 unique original addresses. These are bounded static graph candidates, not proven dynamically reachable complete functions or native game execution. Separate prior leaf pilot counts are not added to this total.

Local host validation: 24 unittest methods passed, including direct CPU differential of 11 scalar arithmetic/logical operations across four widths with 64 deterministic boundary/random input pairs per operation/width (2,816 actual x86-64 fixture comparisons with host-generated C register output and defined status flags). Other synthetic tests exercise stack restoration, calls, loops, known/unknown flags, bounded execution, memory failures, and cross-interval edge rejection. An iOS ARM64 compilation fixture also passed. The original candidate graphs were not executed or differential-tested, and the generated ARM64 object has not been run on ARM64. This module does not prove actual game startup, native runtime integration, or full Batch B completion.

Run locally with LLVM/Clang:
```sh
python mxbikes-ios/tests/test_mxb_demo_cfg_batch.py
python mxbikes-ios/scripts/mxb_demo_cfg_batch.py /path/to/demo/mxbikes.exe /private/new-cfg
```

The generated C and object remain in caller-selected private storage, not in the repository. Next: original-graph differential execution, imported-call dispatch, shared runtime integration, additional integer operations, SIMD and floating point. Batch A's genuine asset frontier remains blocked on the standalone data files. No Actions runs started.

### Self-hosted runner reconciliation: original configuration, real assets, and window initialization

The previous local-container asset blocker is superseded by the existing private self-hosted Windows branch `NyerahMT/ReflexBuildInput:mxb-local-runner`. Its existing runner, ASSCLAPPER, retrieves the pinned release archives directly and uses private temporary directories. No hosted GitHub runner is used. Do not treat inability to download private binary assets in the chat container as proof the assets are unavailable to the project.

Prior archived configuration proof: private run 45654227038 reached 385,089 original x64 instruction executions / 3,217 unique addresses at USER32!LoadCursorA. The 179-byte private core.ini has the exact public standalone SHA-256; 17 reads totaling 3,043 bytes and 17 closes completed. This is configuration parsing, not complete package equivalence or gameplay.

New successful private runner evidence:
- Run 45727226422 (private commit cfe44501ec8068ea6b89d4791b6dc2e9dfde7538): 385,120 original executions / 3,248 unique addresses, 115 adapter checks, reached CreateWindowExA after cursor/brush/window-class registration.
- Run 45727735774 (private commit bfe926831ac50f141e20bd9f09c08a836e53fc56): 385,168 reference x64 instructions, original registered window callback executed for WM_NCCREATE, WM_NCCALCSIZE and WM_CREATE, bounded virtual window/device context created, virtual Choose/Describe/SetPixelFormat completed. 33 display checks passed. The original frontier is OPENGL32!wglCreateContext; no real context or frame yet. Six previously independently verified standalone ARM64 functions were dispatched 18 times in the hybrid startup (63 original x64 instruction executions replaced), with all terminal CPU state and mapped memory matching the pure x64 reference. This is executed AArch64 ELF under Unicorn, not on-device Mach-O execution. Do not count these six functions as new functions or the newer scalar CFG pilot as fully validated by this older bridge.
- Run 45727896231 (private commit aac530f804da722e6cebae3b555ad9a6e8edeb45): 11 genuine archive files (2,388,697,745 bytes) staged from SHA-verified Game.zip and tracks.pkz release inputs. Exact core.ini SHA verified. The actual C streaming module from public commit 05826ddf4bb83952f95335965dd8b58c301d281a was compiled for Windows host and called through AssetMounts; all 189 checks passed, including 932,880 sampled original bytes, large random seeks, independent cursors and EOF. The actual assets include cross-revision bikes.pkz and ui.pkz size differences; joysticks.cfg is not present in that private package. Do not claim full standalone asset equivalence. Resource package parsing by the original engine has not yet been observed.

Batch A: real configuration parsing and native asset transport subgates are complete; original engine resource parsing remains open and depends on graphics initialization. Batch B: bounded live ARM64 startup replay subgate passes to the new graphics boundary; whole-engine native execution, the expanded CFG pilot's own differential verification, imported-call/indirect control flow and SIMD remain open. The current batch should use the self-hosted runner for original executable and private archive tests, with immutable public tool revisions and aggregate metadata only. No private game bytes, compiled original functions or assets committed.

### Expanded CFG actual execution and corrected unwind accounting

Private self-hosted run 45728047054, harness commit be9c2079402ebd9d707762a42274cbd8ebf9a65b, used the newer scalar CFG generator from 05826ddf4bb83952f95335965dd8b58c301d281a with Capstone decoding restricted to raw verified unwind intervals. All 42 completed original x64 controlled-input cases matched executed ARM64 ELF results (22 graphs, including 20 branch graphs and 6 call graphs). It compared GPRs, final RIP, known arithmetic flags, and all captured memory. Of 1,443 attempted x64 fixtures, 1,401 did not complete the reference test (1,284 x64 faults, 108 memory faults, 9 incomplete). Do not count these as native pass or fail. They are missing reference evidence.

A new dependency-free unwind provenance classifier resolves UNW_FLAG_CHAININFO parent records and rejects malformed or cyclic chains. It was run against the pinned standalone executable and the exact 481 compiled graph candidates: 452 chained unwind regions, 29 unchained ranges, 23 direct-CALL target candidates, and 461 represented unwind roots. 458 candidates are not referenced by a statically decoded direct CALL. A chained region is not an independently callable function. These figures correct the misleading interpretation of 481 graphs as 481 complete functions. Six synthetic parser regression tests passed; the original demo classification completed successfully. The next validation should prioritize actual startup contexts rather than entering a chained continuation with an invented stack.

Follow-up self-hosted run 45728314597 (private harness commit 64622223f0261ebd6247623b3ad3179016b6c166) added real startup graph-context captures against the SHA-pinned original core.ini. It reached unchanged wglCreateContext frontier with no memory fault, captured six completed live cases across two previously unvalidated graph regions, and passed all six executed ARM64 differentials. Combined with the prior 42 controlled-input cases, 48/48 cases passed across 24 distinct graph candidates (20 with branches, 6 with calls). The controlled reference rejection counts are unchanged. Live-context cases were replayed independently, not substituted into the running game; the separate 18-dispatch hybrid proof above is the actual live substitution result. The two added graphs are not necessarily full functions. No original engine frame, full native startup, iOS app, or complete Batch A/B exit criterion is claimed.

Next critical path: establish a real graphics backend/context (not fabricated success), preserve the verified configuration and asset transport path, then observe actual original resource package parsing. For translation, use verified dynamic call/continuation contexts and full unwind-root closure, add indirect/import dispatch and SIMD, and integrate the new generated CFGs into continuous native execution. Keep the self-hosted Windows runner as the original-data and execution-test environment. All four current successful self-hosted runs used ASSCLAPPER, not hosted GitHub Actions minutes.

### Actual hardware OpenGL bootstrap reference and expanded scalar CFG batch

Private Windows runner ASSCLAPPER now connects the virtual guest window/pixel-format path to an actual hidden Windows window, device context and WGL context owned by the reference process. Win64 import callsites are verified; available extension addresses are represented by guest-only tokens, and invocation of an untyped extension stops rather than reporting a false unavailable result or exposing driver pointers. No game assets, driver strings beyond capability metadata, original generated code or game frames are exported.

- Run 45730606140, private commit a1738abbf4058b2572622372876bf1757d1f1c01: actual NVIDIA GeForce RTX 4060 Ti / OpenGL 4.6.0 NVIDIA 610.88, pixel format 9; real wglCreateContext and wglMakeCurrent; independent diagnostic clear and pixel readback passed; four original glGetString calls; 385,214 original instruction executions, 3,336 unique addresses; no memory fault, cleanup passed. Original log formatting stopped on long real driver extension string.
- Run 45730721570, private commit ca3728cb58bd8d38322bf1f44cd1300eebaa79a5: bounded driver string logging and real extension token lookup implemented; 385,616 instructions, 3,437 unique addresses; five original extension lookups; reached GL_MAX_ELEMENTS_VERTICES integer query.
- Run 45730878982, private commit 6d310721690d8bc81293c585869efde24f357833: 387,844 original instruction executions, 3,934 unique addresses; 133 adapter checks, eight integer queries and one float query, 62 extension lookups / 60 available tokens, real WGL extension string, original context detached and deleted, original hidden window destroyed and actual resources cleaned up. Frontier USER32!UnregisterClassA. Real GPU capability values include texture dimension 32768 and maximum anisotropy 16. No original draw calls, swaps, or game frame yet; no mobile OpenGL/Metal or ARM64 startup claim. This backend is Windows-specific reference infrastructure, not the iOS renderer.

Public commit 1bf3a0d81f81cf4bd9cac0d25a60c58a65b5ce05 expands bounded scalar CFG translation: ADC/SBB with known carry, SHL/SHR/SAR with count and flag semantics, two/three-operand signed IMUL, CMOVcc/SETcc using decoded condition opcodes, sign-extension instructions, BSWAP, register XCHG, carry controls, PUSH immediates/memory, transactional memory RMW (requires an atomic callback). Unknown flags remain explicit. Host verification: 33 scalar translator test methods plus six unwind provenance methods pass, including 2,432 new native x64 comparisons of extended instruction families and the previous 2,816 arithmetic comparisons. The private generated C from the pinned standalone executable compiled with Clang to an iOS ARM64 Mach-O object: 581 candidate CFGs, 11,157 summed nodes, 10,074 unique instruction addresses (previous 481/4,089 unique). This is candidate-region compile coverage, not count of complete verified functions. Original-code differential rerun is tracked separately. No proprietary bytes or generated output committed. Both public source blob hashes matched the actual locally tested sources.

Batch A still requires original resource parsing after graphics setup; Batch B requires broader native instruction/ABI support and continuous native execution. The self-hosted runner is used exclusively for private execution tests; no hosted Actions minutes consumed.

Follow-up real graphics run 45731301895, private commit 09717f863f033b9342f97ea3483409579831be11, passed bootstrap class unregistration. Original reference frontier advanced to DINPUT8!DirectInput8Create at 409,765 x64 instruction executions / 4,000 unique addresses. All 136 adapter checks passed; original core.ini accesses increased to 20 reads / 3,580 bytes / 20 closed handles, no memory fault, real graphics resources cleaned up successfully. Bootstrap GPU detection and teardown subgate is closed. This is not a main game context or a rendered frame. Next original dependency is input initialization. Preserve the original demo restrictions, avoid fabricated platform capabilities, and test actual input-device interface semantics with guest-only handles.

Expanded scalar differential run 45731302043 on ASSCLAPPER, private harness commit 09717f863f033b9342f97ea3483409579831be11 and public translator commit 1bf3a0d81f81cf4bd9cac0d25a60c58a65b5ce05: 437/437 original x64 vs executed ARM64 ELF comparisons passed across 162 candidate regions, including 158 with branches and 122 with calls. 422 controlled cases and 15 real startup-context cases (five regions) all matched, with zero comparison failures. 340 controlled x64 fixtures did not yield comparable reference returns (245 x64 faults, 62 memory faults, 30 incomplete, three unexpected returns/regions). The Capstone interval decoder identified 706 eligible candidates, distinct from the LLVM linear-sweep build's 581 compiled candidates; do not merge their counts or assume exact correspondence. LLVM classifier: 490 chained regions, 91 unchained, 71 direct-CALL target candidates; 130 branch graphs, 21 call graphs, 19 linked. This is bounded differential evidence, not full function coverage or an ARM64 game launch. No hosted runner was used.


## Publisher asset acquisition, input initialization, SIMD and block differential (2026-11-25/26)

Batch A publisher staging: private self-hosted run 45733813204 completed successfully. The exact publisher beta21e installer (2,379,994,783 bytes, SHA-256 a4c688dab24ab5499171d1416649b109a39b8cd6e82892055db382ea852c0ab0) was extracted without installing or executing the installer. The extraction tool was obtained from a digest-pinned official 7-Zip release and extracted from MSI cabinet data using read-only Windows Installer database APIs. All twelve expected publisher data files (2,388,698,140 bytes) and the SHA-pinned standalone executable were mounted. This resolves the private archive's missing joysticks.cfg and differing bikes.pkz/ui.pkz sizes. Prior extractor acquisition attempts failed TLS, Authenticode verification, or portable extraction; none bypassed verification.

Original x64 reference reached 410,776 instruction executions / 4,031 unique addresses without a memory fault. The guest completed DirectInput8Create and EnumDevices using a guest-local interface with no attached virtual controllers; no physical devices were read. Original game file calls opened, read and closed core.ini twenty times and the exact publisher joysticks.cfg once (72 bytes); all 21 handles closed. Original engine next stopped at MSVCR90!_create_locale. Mounting all files does not prove that all PKZ archives are parsed by the original engine. Private commit 518c15aff98f14c189b2f23fbde745091911294c adds the observed C numeric-locale API family with 15 local regression checks; integrated original-engine validation remains outstanding. No original frame, mobile input backend or iOS execution claimed.

Batch B: 3fcfa7efe232729574ac31ef8d35d80c9ef0187b added bounded SSE/SSE2 XMM data movement, bitwise and packed integer operations, and comparisons. Initial private run 45733133341 passed 140 controlled original-code ARM64 comparisons in 47 regions. Public commit 227ab9f66bba20cf76ecefff0d7b094f88fd22f5 added scalar and packed normal-domain FP arithmetic/conversion and MXCSR precision tracking. Local native x64 CPU oracle comparisons: 1,984 SIMD checks, 2,899 FP arithmetic checks, 1,412 FP conversion checks, 6,295 accepted cases total; 553 arithmetic/conversion cases explicitly rejected outside domain. Expanded private run 45733739189 initially found 15 MXCSR-only discrepancies after matching GPR/XMM comparisons, not necessarily memory (the MXCSR check preceded memory readback). Independent fixed-instruction real-x64 CPU oracle run 45734060030 established emulator MXCSR omissions (1.0f + 2^-25 returned the same result but actual CPU set precision, Unicorn did not); 4,484 oracle instruction calls. All 184 accepted ARM64 cases passed full comparisons against corrected reference state, zero failed, 48 explicitly unsupported FP cases; 66 all-captured-pass graphs, 593 reference-side rejected/incomplete fixtures. No actual live SIMD startup captures in this run. Original-code ARM64 executed via AArch64 ELF emulator, not iPhone hardware.

Public commit ddb56f01db6db6289db0a0280197ea32e4b2b6b9 added an original-PC block dispatcher, indirect call/jump, stack-correct return and bounded unknown-PC handoff, with 8 new block tests including ARM64 Mach-O compilation. Combined scalar CFG, unwind provenance and block regression: 47 passing tests. Private run 45734438170 tests contiguous observed startup blocks against original x64 snapshots. Pending result must not be interpreted as success. Neither batch has reached its full exit gate: resource consumption by the original engine and continuous translated ARM64 engine startup remain incomplete. All execution jobs used the existing Windows self-hosted runner, not hosted Actions minutes.


## Automatic trace-driven translation controller

Public commit 176590686e2077648e89762f67fa6461fa8738f7 adds mxb_demo_auto_translate.py. It automatically selects supported byte-verified instructions from an observed PC inventory, prioritizes frequently executed addresses, groups unsupported forms by mnemonic/reason and execution frequency, and emits disjoint page-owned C shards plus a shared guest-PC dispatcher. Unsupported addresses remain explicit boundaries. Generated sources, snapshots and binaries stay private.

Self-hosted private run 45748705639 (commit 66ad7d0a5c1162b6977fbadd7ad421a7d50a0d7d) passed 11 planner regression checks. From the earlier 385,168-execution virtual graphics reference trace (3,294 unique PCs), 3,280 PCs were automatically selected and compiled into six ARM64 shards and a shared dispatcher. Those selected PCs account for 378,708 original reference executions (98.32% of that trace's execution count, NOT 378,708 native executions). The resulting private AArch64 ELF (2,746,176 bytes) executed 223/223 independently captured contiguous differential cases, 4,069 original instruction instances / 3,109 unique PCs, 306 calls and 92 returns. These reproduce the earlier block validation cases with automated selection and sharded linking, not additive unique coverage. The highest-weight gap was REPNE SCASB (5 addresses, 6,316 of 6,460 uncovered reference executions). Remaining gaps: REPZ RET, ROL, MUL, IDIV, LOCK CMPXCHG, a prefixed MOV, memory XCHG, and two excluded FP conversions. The run used the existing Windows self-hosted runner.

Next: extend the automatic trace capture to the latest publisher-asset startup frontier and integrate verified block dispatch into continuous execution. The current driver uses the earlier virtual wglCreateContext boundary, not the latest 563,868-instruction real-graphics trace. It does not synthesize implementations of unsupported instructions or imports, and no native device launch is claimed. Batch A remains open; this automation improves Batch B throughput without changing its exit criteria.

## Continuous startup checkpoint and bounded shard regression (2026-11-26)

The publisher beta21e demo is the unmodified executable. Private self-hosted run
[45755173446](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45755173446)
and independent rerun
[45765004226](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45765004226)
both reached the same verified boundary:

- 604,407 architectural original instructions completed by translated AArch64
  ELF in the ARM64 emulator, 5,970 distinct guest PCs, 367 reference checkpoints,
  zero mismatches and no denied guest-memory accesses in the original baseline.
- 635,797 x64 reference code-hook events are not the architectural instruction count.
  All 5,970 observed addresses translated; no unsupported address in this trace.
  Neither the complete executable nor on-device iOS startup is established.
- 12 verified publisher data files (2,388,698,140 bytes) staged. Original code
  read 4,084 configuration bytes over 23 completed reads and closes; zero PKZ
  archive bytes consumed by the engine.
- The empty profile directory and texture cache were handled without creating
  fictitious cached content. Both runs stopped on the request to open
  `license.ini`; no license data fabricated or entitlement behavior modified.
- Windows reference graphics initialization and teardown passed; zero original
  game draw calls or swaps, and no actual game frame.

The second run pins public source commit `3fd0ec7eddacb503ef3389504fdac55399e6c145`.
The dispatcher now enforces its per-shard instruction count even within one
4 KiB guest page; sparse holes return an untranslated-PC boundary. Both host
compiled regression methods passed, as did all 15 planner checks. The complete
original startup trace and terminal stop matched after the change.

Batch B observed-trace translation and differential subgates pass. Full
startup/whole-engine coverage remains unestablished. Batch C is open at the
original license-file dependency. Batch A has genuine package staging and
configuration reads, but original resource archive consumption remains open.
Batch D has desktop bootstrap evidence and earlier isolated rendering proofs,
not an original menu frame or a mobile backend integration pass.

A separate bounded read-only ZIP/PKZ resource oracle was added at
`mxbikes-ios/scripts/mxb_demo_pkz_audit.py`; it independently verifies stored and
DEFLATE entries, CRC, and sample SHA-256 digests without extraction. Synthetic
tests passed, including a 70,105-byte sampled fixture. Independent oracle
results must never be counted as original engine reads. Actual publisher
archive sampling is a separate pending validation until its run logs confirm it.

### Publisher resource oracle: verified (2026-11-26)

Self-hosted [run 45765177289](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45765177289) completed successfully. All six synthetic resource regression tests passed. All eight genuine publisher PKZ archives were indexed (1056 total file entries); three entries per archive were independently decoded, for 24 samples and 33,004 decompressed bytes. Every sample passed CRC verification and yielded SHA-256 evidence; both stored and DEFLATE methods were exercised. This is independent resource-oracle evidence, not full archive integrity verification or original-engine asset consumption. The same run repeated 604,407 translated architectural instructions across 5,970 distinct PCs and 367 checkpoints with no mismatch, stopping at the original license.ini dependency. Original engine archive reads and first actual game frame remain unverified. Batch A archive sampling subgate passes; full Batch A and Batch C closure remain open.

### Full publisher resource integrity subgate: passed (2026-11-26)

Self-hosted [run 45766733047](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45766733047) verified all 1,056 entries across the eight publisher PKZ archives, streaming 3,457,160,210 uncompressed bytes without extracting files. Every entry passed ZIP CRC validation and contributed to a deterministic SHA-256 manifest; zero failed, zero skipped. Eight synthetic tests passed, including corrupt-entry and budget-exhaustion checks. The same run replayed the complete 604,407-instruction ARM64 reference trace across 5,970 distinct PCs and matched the terminal stop. This closes the independent archive integrity subgate only: original engine archive reads remain zero, and no genuine engine frame was rendered.

A separate true-color TGA decoder and host native texture-upload probe (raw/RLE, 24/32 bits, bounded dimensions, guest Win64 ABI dispatch, exact RGBA readback and storage cleanup) is now implemented. Its synthetic and genuine asset integration tests are pending until a self-hosted run reports results. This path does not execute original game rendering or alter the original licensing dependency.

### Genuine texture uploads and fresh-profile demo startup (2026-11-26)

[Run 45766907836](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45766907836) passed all four TGA/native-texture fixture tests and 12 actual publisher asset uploads (four each from ui.pkz, misc.pkz, effects.pkz). The C texture adapter's owned RGBA bytes exactly matched the independent decoder, and texture storage was released. This was host CPU adapter execution, not a real GPU draw or original-engine graphics call.

The publisher's [download page](https://mx-bikes.com/?page=downloads) explicitly states the public standalone download runs as a demo until unlocked by a license key. The harness previously stopped at an ordinary fopen request in its provably empty newly created profile; it now models that file's real absence (read-only open returns NULL). It does not synthesize a key, license file, authorization response, modify any original branch or unlock paid content. Original demo behavior remains authoritative.

[Run 45774112103](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45774112103) passed all 64 guest-folder checks and replayed 609,015 architectural instructions across 5,996 unique original PCs (643,267 raw reference hooks), 367 reference checkpoints, zero mismatches, all observed PCs translated. It passed the previously blocked file-open boundary and stopped at the ordinary MSVCR90 _strupr import; original engine archive reads remain zero, no original game frame. This is +4,608 architectural instructions and +26 PCs relative to the 604,407 checkpoint, not additional full-function coverage. The demo executable SHA is unchanged. Actual GPU texture readback and a bounded C-locale uppercase/lowercase import implementation are separate pending checks.

### Original engine reads genuine PKZ archives; hardware texture proof (2026-11-26)

[Run 45774328859](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45774328859) passed 14 bounded ASCII case checks and executed 668,622 architectural original instructions as translated AArch64 ELF (702,929 raw reference hooks), covering 6,318 unique guest PCs, 381 reference checkpoints, zero mismatches, zero unhandled instruction forms in the observed trace. This advances 64,215 instructions and 348 distinct PCs over the 604,407-instruction starting checkpoint. The original engine itself opened, read and closed three genuine PKZ packages: bikes 387 reads / 13,771 bytes, effects 269 / 10,334, misc 231 / 7,977. Total 887 archive reads and 32,082 archive bytes. All 26 asset handles closed. These are actual original-code archive reads in both reference and ARM64 replay, not proof that every resource entry has been loaded or that the first game frame exists. Next observed boundary is the absent Music.pkz request.

The same run used the native C texture adapter's actual owned RGBA output in a separate hidden OpenGL hardware context on NVIDIA RTX 4060 Ti (OpenGL 4.6). All 12 genuine TGA textures from ui/misc/effects rendered at 1:1 texel/pixel resolution; 38,784 framebuffer pixels matched byte-for-byte across all four RGBA channels (155,136 channel bytes). The real GPU draw diagnostic is separate from original-engine rendering, not an MX Bikes menu/frame or a Metal/iOS runtime pass. No game textures, executable bytes or framebuffer images exported.

Native C case conversion now has staged transactional writes, 4096-byte C-locale ASCII limit, explicit unsupported high bytes and an independent smoke fixture. Host and ARM64 object verification are pending the next self-hosted test. Complete extracted publisher root PKZ inventory verification will also test the absence of optional archives without fabricating assets.

### Extended package indexing, timestamp oracle and strict gate correction (2026-11-26)

[Run 45774628119](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45774628119) passed the native C case conversion smoke and ARM64 object compile, 39 VFS checks, and exact eight-package inventory from the SHA-pinned extracted publisher root. The original demo handled the genuinely absent optional Music.pkz without fabrication. The full strict trace replay passed at 763,935 architectural instructions / 6,913 unique PCs / 417 reference checkpoints, zero mismatches. Seven of eight publisher archives had been opened/read, 85,463 archive bytes, 2,308 archive read calls, with one active tracks.pkz handle at the terminal MSVCR90 _mktime64 request. Archive reads alone are not original decompression or menu rendering.

[Run 45774970697](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45774970697) passed 236 actual Windows CRT UTC calendar comparisons and 12 synthetic archive region-classification checks. Original x64 reference observed 2,485,226 architectural instructions / 7,459 unique PCs, all supported by the translator. Strict native reached 1,276,290 instructions with 7,029 distinct PCs, no reported prefix mismatch, but the run FAILED the full replay gate: the original reached its short wall-clock limit, while the native dispatch-loop cap terminated at a different point. Neither terminal state nor resource totals matched. Do not replace the 763,935 full checkpoint with a partial replay. Archive classification showed all observed bytes so far were ZIP central-directory/end-record reads (native 1,135,884 bytes; reference 3,994,372 bytes), not compressed member payload. The original engine has been indexing packages, not yet decoding/rendering them. No original frame.

The reference harness now has explicit bounded continuous execution limits (16 million original instruction budget, 120-second reference watchdog, 1,048,576 native dispatch cap), and the trace observer no longer installs a no-op memory hook. Strict gating now requires identical complete instruction trace, terminal stop, asset and folder statistics. Native C UTC timestamp implementation with 238 known-calendar fixtures, and a bounded native observed-PC execution ABI/loop with explicit import boundaries, are implemented but remain pending independent verification. Full iOS Mach-O / Android ELF object archive building remains a separate compile-only check; it is not on-device execution.

### 13.88 million instruction full replay and first mobile archives (2026-11-26)

Self-hosted [run 45775380734](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45775380734) succeeded. Reference: 14,458,782 raw x64 code hooks, 13,879,731 architectural instructions. Strict AArch64 ELF replay: 13,879,731 matched instructions, 11,536 distinct translated PCs, 464 CPU-state checkpoints, no reported mismatch or untranslated observed PC, exact terminal stop and asset-region/folder statistics. The executable is the SHA-pinned public standalone beta21e demo; this is not a full commercial executable or on-device test. Original engine read 9,637,883 PKZ bytes over 240,034 archive read calls; all 755 opened files closed. First observed compressed member reads: tracks.pkz 29,214 bytes across 32 members, tyres.pkz 76 bytes across two members. This establishes original payload access, not independently verified original decompression. Terminal request: fresh profile cache/usage.ini, read-only. No original draw or swap, no menu. Determine the cache file's actual semantics before expanding filesystem support.

The same run cross-compiled all 24 translated compilation units into private ARM64 iOS Mach-O (3,416,016 bytes static archive) and Android ELF (3,825,654 bytes static archive). No SDK application link, signing, install, or device execution occurred. Native C timestamp (238 cases) and observed-runtime smoke passed.

Subsequent public commits add checked portable guest memory mapping, transactional vector writes, a shared generated-code/runtime CPU ABI, and host/ARM64 synthetic generated-call integration tests. Independent local verification used source files whose four Git blob SHA-1 IDs matched the committed files: 100 randomized maps, 30,000 operations (14,882 reads, 15,118 writes; 13,547 permitted, 16,453 denied), zero mismatches including denied-write atomicity. Both portable runtime C units compiled with Clang to iOS ARM64 Mach-O and Android AArch64 ELF and were archived. These local archives contain the two runtime units, not the original translated engine. Self-hosted [run 45776231860](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45776231860) is a separate deterministic 3-million-raw-hook checkpoint regression with shared runtime library build; its shorter checkpoint must not replace the 13,879,731 full frontier. Full commercial purchased-copy compatibility and legitimate licensing integration remain separate outstanding work.

### Portable runtime integration verified; post-cache startup pending (2026-11-26)

[Self-hosted run 45776231860](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45776231860) passed the generated AOT dispatcher plus native guest memory/explicit fixture-import tests on host and executed AArch64 ELF. The deterministic shorter regression replayed 2,999,232 architectural instructions across 10,476 distinct PCs with full trace, terminal CPU state, asset-region and folder agreement. All 22 translated units and both portable runtime units compiled into 24-unit private mobile static libraries: iOS Mach-O 3,147,016 bytes, Android ELF 3,562,752 bytes. This shorter integration regression does not supersede the 13,879,731-instruction full startup checkpoint.

The verified fresh-profile cache directory has no file-creation service. The exact observed read-only request for cache/usage.ini now returns ordinary missing-file failure, without fabricating a cache file, changing the executable, or modifying authorization behavior. Five additional folder regression cases cover exact path, mode and directory existence. A bounded 32-million instruction observation window and deterministic 20-million raw-hook checkpoint are configured for [run 45776811176](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45776811176); results pending.

The portable runtime now includes a native startup import bridge with trusted immutable token/return-PC pairs, mapped executable return validation, Win64 stack alignment and checked guest memory callbacks. New synthetic generated-code fixtures exercise actual native _strupr and GetTickCount, unsupported import rejection and invalid return/write rejection. These new fixtures are pending self-hosted verification; no original game calls have been run through this new bridge yet. Future mobile archive build includes 11 runtime units. Full purchased-game compatibility, original game frame, SDK linking, and on-device run are still outstanding.

### Locked regression baseline and fast frontier discovery (2026-11-26)

[Run 45776811176](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45776811176), public source fc6ea4c29545c5fd32661badcc8cdd6a958725c7 and private harness 82472e5fa139949c8a685e00efabb061c90a7b28, passed: 15,462,903 architectural instructions, 16,117,686 raw reference hooks, 12,275 distinct PCs, 478 CPU state checkpoints, complete trace and terminal CPU state agreement, zero reported mismatch, 11,072,046 PKZ bytes read. First additional bike payload reads: five members. Both 27-unit iOS/Android archives compiled successfully. No first original frame. Stop: MSVCR90 _findfirst64i32, unsupported package enumeration pattern. This pinned baseline must not be replaced with reference-only results or a shorter trace.

[Run 45776995550](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45776995550) passed all four generated-dispatch/runtime integration tests on host and executed ARM64 ELF, including native _strupr and GetTickCount import bridge fixtures.

The private fast-frontier workflow skips repeat resource integrity/texture audits and native full-trace replay, retaining reference execution, bounded FP oracle, exact publisher provenance, and translation planner analysis. It prints newly verified ARM64 instructions = 0; new results are discovery only until the strict gate passes. The package-enumeration model now supports root PKZ wildcards and searches for packages in verified fresh guest profile directories (no host lookup, no unverified absence); records the actual rejected search pattern. [First fast discovery run 45778130931](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45778130931) pending.

Private guest checkpoint primitives capture CPU register state and every writable guest-memory region; compare hashes and restore into an identical mapped emulator. Future full runs report guest-memory and service-summary comparison, with checkpoint-candidate status separate from full process resume. This does not yet serialize/recreate all runtime services, host resources or immutable mapped content; restartable engine checkpoints are not yet established. No game memory or executable data are uploaded. Full purchased-game compatibility and original frame are still outstanding.

### Loose directory discovery and exact checkpoint service metadata (2026-11-26)

Fast reference run 45778130931: 141 seconds, same 15,462,903 architectural reference instructions, observed rejected wildcard series/*.*. Previous full run 45776811176 took 430 seconds. These are different test scopes, not a like-for-like full regression speedup.

Fast reference [run 45778577601](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45778577601) passed in 138 seconds. Verified extracted publisher root lacks all eight loose package directories (bikes, effects, misc, rider, series, tracks, tyres, ui); archive files remain mounted. 23 enumeration and six CPU/memory checkpoint primitive regression cases passed. Both series directory enumerations returned ordinary no-match results from this verified absence. Reference advanced to 15,463,060 architectural instructions (16,117,843 raw hooks), 12,337 supported observed PCs, no planner gaps, and read-only series/.pkz probe. No original draw or swap. This adds 157 reference instructions and 62 observed unique PCs, **not** newly verified ARM64 execution. Locked full baseline remains 15,462,903 instructions / 12,275 PCs.

Private harness now supports ordinary read-only missing-file requests inside certified absent loose directories and adds eight VFS regressions. New allocator and VFS checkpoint implementations validate allocation coverage, metadata, handle generation, file cursors, EOF/error state, inventory identity and archive counters; restore only trusted sources. [Run 45778983073](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45778983073) exercises these fixtures and the next engine probe. At documentation time this run was still in progress. Later private commits add immutable mapped-region hashes and exact virtual service fingerprints to future full differential checkpoint comparisons; not yet validated. Process-level checkpoint restart remains unimplemented, and the full purchased-game path and original menu remain outstanding.

### Paint cache cleared; deterministic checkpoint reached (2026-11-26)

[Run 45779804419](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45779804419) passed four native generated dispatcher/CRT host and executed ARM64 fixtures, including verified absent loose package directory and wildcard imports. Reference progressed through missing paint index to the optional paints.pkz sidecar. The first attempt had failed to advance because the paint subdirectory was not yet created; corrected scoped absence checks advanced the engine.

[Run 45780688196](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45780688196) and [run 45781034865](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45781034865) independently reached the same explicit pre-service checkpoint (service ordinal 592479, token 0x7100008a0), 19,834,920 architectural reference instructions, 20,503,168 raw hooks, 13,087 supported observed PCs, zero planner gaps, 11,231,876 VFS bytes read. All 80 folder and 23 binary guest-cache fixture regressions passed. Engine cache writes: zero. No original draw or swap. This is a configured checkpoint rather than an unsupported import or missing-file blocker.

The first recorded 15,462,903-instruction reference prefix SHA-256 is d1892fbc4c4a46c31b3222ed18fa5be11ffe8b1ec1f65195411a18b2f84f3b5e, computed from little-endian uint64 PC sequence in run 45781034865; not independently recorded in the historical full native run. Future discovery and full runs enforce equality to this reference fingerprint. Historical full ARM64 verified frontier remains 15,462,903 instructions.

New bounded 28M raw-hook discovery [run 45781865003](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45781865003) submitted; full 20M-hook deterministic replay with exact memory/service-state comparison queued separately. Neither is a verified result yet. No claim of restartable process checkpoint or first original rendered frame. Only unmodified public publisher standalone inputs are tested, not the purchased full-game route.
