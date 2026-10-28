# MX Bikes iOS — public source snapshot

Experimental, unofficial Windows x64-to-ARM64/iOS compatibility and rendering project.
**Not affiliated with or endorsed by PiBoSo, Valve or Apple.**

## Status (October 27, 2026)

- The SHA-pinned original MX Bikes executable has executed in a **private**
  Linux/x64-emulator and AArch64 testing environment through original CRT
  file operations and checksum logic.
- The original game stops at the unsupported
  `steam_api64.dll!SteamAPI_RestartAppIfNecessary` platform boundary.
- **No original game rendering calls, real game frames or working MX Bikes
  iOS game launch have been verified.** Metal screenshots in prior reports
  show synthetic graphics tests only.
- This public snapshot includes the authored source, tests, documentation
  and iOS Metal renderer, **not** the commercial executable, DLLs,
  tracks, game packages, textures or original game release archives.

## Layout

- `runtime/` — C renderer, Win64 OpenGL argument adapter, bounded guest
  texture and guest-memory services
- `ios/` and `project.yml` — unsigned SwiftUI / MetalKit viewport prototype
- `scripts/` — reverse-engineering tools, SHA-based code provenance tests,
  controlled execution harnesses and translator orchestration
- `tests/` — host, emulator and differential test harnesses
- `docs/` — engineering notes, observed boundaries and technical decisions
- `archive/private-workflow-definitions/` — saved historical workflow
  definitions, **not active GitHub Actions**. They refer to a separate
  private source repository and require user-owned original game data.

## Run source-only tests

From this directory (Linux + clang/gcc + Python):

```sh
cc -O2 -std=c11 -Wall -Wextra -Werror -Iruntime \
  runtime/mxb_gl_surface.c tests/mxb_gl_surface_smoke.c -lm -o /tmp/mxb-gl-test
/tmp/mxb-gl-test
python -m pip install 'unicorn>=2,<3'
python tests/mxb_gl_win64_unicorn_import_test.py
python tests/mxb_gl_win64_indexed_guest_test.py
```

The containing public `ARM64-Lab` repository has a dedicated source-only
workflow at `.github/workflows/mxbikes-ios-public-checks.yml`. It does
**not** fetch or test against the original commercial game files.
Private original-game acceptance tests must run in a separately authorized
environment and are not suitable for untrusted public pull requests.

## Data and licensing boundaries

Keep original executable/DLL archives, release ZIP files, track files,
Steam accounts and credentials, signing material and original game asset
collections out of public Git history, releases, tests and CI artifacts.
The old private repository and its release attachments have **not** been
copied or made public. This snapshot is based on its current source tree,
**not** its private Git history.

Publishing source does not automatically grant permission to distribute
the commercial game. No standalone runtime, Steam licensing bypass or
working iOS MX Bikes game is claimed.
