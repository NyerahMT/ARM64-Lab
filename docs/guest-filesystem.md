# Guest CRT filesystem bridge (MX Bikes investigation)

The public `tools/guest_file_bridge.py` module is a fail-closed, read-only model of a subset of Microsoft CRT file operations. It is used by the **private** startup experiment to deliver authentic bytes from the game owner's original archive into the x64 emulator.

## Supported operations

`fopen` with `rb` mode, `fread`, `fseek`, `ftell`, `fclose`, `fgetc`, `feof`, `ferror`, and `rewind`.

Guest `FILE*` values are opaque tokens tracked by a host-side handle table; they are **not** real MSVCR90 `FILE` structures. Any guest direct structure dereference should fault instead of fabricating CRT memory. Files are provided as an in-memory allowlist—guest paths never open arbitrary host filesystem locations. Only an explicit basename can be opened, each read is bounded to 512 KiB, files are bounded to 2 MiB, and the handle count is limited.

Synthetic tests verify actual returned bytes, element counts for partial reads, seeking, EOF, invalid handles and rejection of unauthorized paths. Private binary data is never committed to this repository.

## Verified private startup result

The earlier original x64 CRT run stopped at `fopen("steam_api64.dll", "rb")`. The private owner-supplied `Game.zip` contains one matching original DLL, 250,656 bytes long.

With the new bridge, original x64 code requested 251 reads, received all 250,656 bytes, and closed the file. Across this bounded trace the emulator executed 4,266,952 original x64 instructions. A separate continuation with a *synthetic* "Steam already launched the game" answer reached the original `SteamAPI_Init` import after 4,266,955 executed original instructions.

**This is neither Steam runtime initialization nor native AArch64 execution.** The original code is still running under Unicorn x64, supported by simulated Windows/CRT behavior. No game menu or renderer has booted.

## Next engineering blockers

1. The genuine `SteamAPI_Init` lifecycle and related interface semantics; do not treat a hardcoded `true` as a working Steam integration.
2. A scalable Win64-to-AArch64 translation strategy capable of handling real calls, indirect branches, guest memory, and exceptions.
3. Native platform adaptations (windowing, graphics, audio, input and iOS signing/build).

These are separate from the successful private DLL-reading checkpoint.
