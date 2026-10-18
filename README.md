# ARM64-Lab

An experiment in ahead-of-time recompilation of Windows x86-64 applications for ARM64. The goal is to preserve original application behavior, not recreate it in a different engine.

**Current status: bounded original x64 startup emulation plus a restricted, compiler-backed ARM64 translation/Win64 import-dispatch proof. Not a playable game, a native iOS build, or a running engine.**

## What works

- Read-only Windows PE32+ inspection, including imported APIs and exception/unwind records.
- Searching a locally owned executable for candidate return-value instruction sequences.
- Lifting two trivial x86-64 patterns (zero return and immediate constant return) to freestanding C.
- Cross-compiling those generated C functions to AArch64 object code.
- Executing a **synthetic Win64 imported-CALL sequence** under Unicorn x64, translating it automatically to C and executing the resulting AArch64 ELF with the actual native timing/import registry (not merely compiling it).
- Translating a **single authentic MX Bikes imported-CALL instruction** at RVA `0x2AB9AE` (`KERNEL32.dll!GetTickCount`) into native C and executing its observable call effects in Unicorn ARM64; its enclosing game function remains untranslated.
- **Five complete authentic MX Bikes function bodies** now have bitwise x64-versus-generated ARM64 differential matches: four branch-free SSE math routines (RVA `0x267AE0`, `0x266D80`, `0x266E20`, `0x266EB0`) and a bounded integer/global-memory record writer (`0x258BB0`). These cover 140 original x64 instructions, but represent narrow patterns rather than a general recompiler.
- **Original multi-basic-block control flow now verified in ARM64 emulation:** 11 instructions from an unwind-backed MX Bikes branch region at `0x2B212C–0x2B215E` were automatically translated, with 128/128 host and AArch64 comparisons matching the x64 reference across both branch paths. This is **not a complete recovered original function** (the prologue is outside the interval), and the translator remains limited to selected MOV/TEST/JE/ADD/RET patterns and explicitly mapped guest memory.
- **Backward loops and signed arithmetic flags:** a 7-instruction synthetic x64 loop passed 81/81 host/AArch64 differential cases, and a 14-instruction **original MX Bikes** indexed backward-loop region (`0x1FC710`) passed 32/32 x64/native ARM64 cases. It is a bounded original code region, not a full recovered function.
- **Native translated-to-translated direct calls:** a synthetic Win64 caller and callee now execute together in freestanding ARM64, passing 72/72 nested CALL/RET stack, register and arithmetic flag comparisons. This has not been proven with original game interfunction calls yet.
- A fail-closed native import registry for six timing interfaces, a confirmed CRT data import, and unsupported Steam calls; native C and AArch64 compilation tests pass.
- Private x64 startup traces have executed original CRT callbacks and read the actual archived Steam DLL, reaching `SteamAPI_Init` under emulated Windows services. These are x64 emulation results, **not native translated startup**.
- Synthetic regression tests through GitHub Actions, without any original commercial binaries.

A byte-pattern match is not proof of a true callable function boundary. A cross-compiled object is not proof that original game code runs on iOS.

## Local commands

Run these commands from the repository root:

    python -m unittest discover -s tests -v
    python -m tools.pe_probe /path/to/local/mxbikes.exe --json /tmp/pe_inventory.json
    python -m tools.leaf_lift --exe /path/to/local/mxbikes.exe --limit 10
    python -m tools.leaf_lift --exe /path/to/local/mxbikes.exe --rva 0x1549a --emit-c /tmp/leaf.c
    clang --target=aarch64-unknown-linux-gnu -ffreestanding -c /tmp/leaf.c -o /tmp/leaf.o
    readelf -h /tmp/leaf.o

The example RVA refers to a specific local executable revision; offsets may change.

## Next

Scale beyond one-instruction import calls: translate full functions and control flow, preserve guest memory/Win64 ABI/exception state, connect a production-compatible host runtime, and only then tackle original assets, OpenGL-to-Metal rendering, controller input, and iOS packaging. Steam initialization remains unresolved. Keep all original game binaries and derived native objects private.

[See evidence-based milestones](docs/milestones.md) and [CI checks](../../actions).

## Project boundaries

Keep commercial game executables, DLLs, archives, extracted code, and IPA builds out of this public repository. Only our independently written tools, build configurations, and synthetic tests belong here. Seek appropriate permission before distributing derivative software.
