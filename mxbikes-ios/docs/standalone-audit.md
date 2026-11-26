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
