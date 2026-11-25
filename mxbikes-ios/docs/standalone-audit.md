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
