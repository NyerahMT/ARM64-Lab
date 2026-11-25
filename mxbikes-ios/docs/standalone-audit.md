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
