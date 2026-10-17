# Development gates

The percentages in project updates refer to explicit milestones, not a fraction of game code translated.

| Gate | Criteria | Status |
| --- | --- | --- |
| D0 | Inventory a local Windows PE32+ input safely | Complete locally |
| D1 | Extract limited x86-64 return-sequence candidates, generate C, compile AArch64 object | Verified in private CI against original MX Bikes input; still only isolated byte-pattern lift |
| D2 | Establish true callable function boundaries and differential reference behavior | **One candidate validated:** cross-product function called at RVA 0x267AE0, x64-vs-C-vs-AArch64 200-case differential proof (not automated general lifting) |
| D3 | Scalable lifting of original code, indirect branches, guest stack, Windows x64 ABI and exceptions | Not started |
| D4 | Execute real original entry path in host/native ARM64 runtime | Not started |
| D5 | Load original archives and bridge OpenGL drawing | Not started |
| D6 | Render interactive original menu | Not started |
| D7 | Gameplay, controller input, iOS device build | Not started |

## Local binary diagnostics

- User-supplied executable SHA-256: 4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6
- PE32+ / x86-64. Image base: 0x140000000. Entry RVA: 0x2ab31c.
- Imported APIs: 320 across 12 DLLs.
- Valid Windows unwind begin/end records: 8,741. This is NOT a verified count of distinct callable functions.
- Short candidate return-value patterns found in raw executable section: 609. These may include byte coincidences or non-entry code.
- One candidate at RVA 0x1549a was converted to C and compiled to an AArch64 ELF64 object, both locally and in private GitHub Actions CI (2026-10-17).
- Of 609 raw byte-pattern candidates, zero started at the 8,741 recorded Windows unwind-function starts; function boundaries remain unverified. This does not establish that none are real leaf functions.
- Private CI decoded 8,563 of 8,741 Windows unwind-record intervals; 2,717 interval starts were referenced by direct calls and 605 intervals ended with a straight-line return (2026-10-17).
- Only two short straight-line interval starts were directly call-referenced, including an SSE math candidate at RVA 0x267AE0 with 196 direct call references. An unwind interval may cover only a fragment, not the entire function.
- The x64 vector-cross-product routine at RVA 0x267AE0 (24 instructions) was run under Unicorn x64, manually rewritten as a portable C equivalent, compiled to AArch64, and actually executed under Unicorn ARM64. All 200 normal-range float32 test pairs matched bit-for-bit across original x64, native C, and the ARM64 compiled code (2026-10-17). This is a single-function proof, not an automated instruction lifter.
- No translated original game code has been executed on iPhone, and no original engine/menu has booted.

Do not commit game executables, DLLs, archives, or derived original source files to this public repository.
