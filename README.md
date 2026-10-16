# ARM64-Lab

An experiment in ahead-of-time recompilation of Windows x86-64 applications for ARM64. The goal is to preserve original application behavior, not recreate it in a different engine.

**Current status: PE reconnaissance and a very limited translation proof of concept. Not a playable game, emulator, iOS build, or running engine.**

## What works

- Read-only Windows PE32+ inspection, including imported APIs and exception/unwind records.
- Searching a locally owned executable for candidate return-value instruction sequences.
- Lifting two trivial x86-64 patterns (zero return and immediate constant return) to freestanding C.
- Cross-compiling those generated C functions to AArch64 object code.
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

Validate genuine function boundaries and differential behavior before scaling translation. Future phases must address indirect control flow, Windows x64 ABI, exceptions, DLL integration, original assets, OpenGL and iOS rendering.

[See evidence-based milestones](docs/milestones.md) and [CI checks](../../actions).

## Project boundaries

Keep commercial game executables, DLLs, archives, extracted code, and IPA builds out of this public repository. Only our independently written tools, build configurations, and synthetic tests belong here. Seek appropriate permission before distributing derivative software.
