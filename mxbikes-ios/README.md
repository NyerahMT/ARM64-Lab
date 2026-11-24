# MX Bikes iOS — main ARM64-Lab development workspace

**Canonical source:** `NyerahMT/ARM64-Lab` `main`, `mxbikes-ios/`. The current continuous native startup development is on `feat/mxb-offline-relaunch-experiment-20261122`; the private `ReflexBuildInput` repo stores user-owned game files and is not our working source tree.

Experimental, unofficial Windows x64-to-ARM64/iOS compatibility and rendering project.
**Not affiliated with or endorsed by PiBoSo, Valve or Apple.**

## Status (November 24, 2026)

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

### Continuous native startup checkpoint

On the development branch, the private owned-input ARM64 differential now starts
at the original executable entry, completes CRT initialization, enters the
original WinMain, runs the actual filename and game initialization routines,
and executes the original file-reading/checksum loop through the first Steam
import CALL at guest VA `0x1401306ed`.

- Native ARM64 differential: [8 cases passed](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45446609357).
- Last case: 4,266,965 dynamic original instruction steps (mostly repeated
  checksum-loop instructions), 288 modeled CRT/Win32 service calls, 251
  actual reads of 250,656 owned DLL bytes.
- Original x64 and native ARM64 agree on all general-purpose registers, 16 XMM
  registers, flags, full guest stack, selected object/globals and file state.
- Private data image: six non-executable ranges totaling 14,299,136 bytes,
  with a 128 KiB guest stack. No original x64 instruction pages mapped in the
  iOS native runtime.
- The installed iOS simulator has separately passed the earlier continuous
  1,254-instruction checkpoint at guest VA `0x1402aaebc`:
  [private simulator run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45446067917).
- Full checksum iOS verification is tracked in
  [private run 45446771447](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45446771447).

The Steam call is not executed or simulated. Publisher-supported entitlement
and platform integration remain unresolved. No original main menu or frame
has been rendered. Dynamic instruction totals measure executed steps, not
unique translated instructions or percentage of the game.

Private build generation now requires the original `mxbikes.exe` and its
matching original `steam_api64.dll` in the same private input directory.
Generated original data and compiled game-specific artifacts must remain
private. The DLL bytes are read as immutable data, never executed.

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

The `arm64-lab` symlink inside this directory points back to the
public repository root for older translated-code tool paths on Linux and WSL2.
Native Windows Git checkouts may require symlink support; WSL2 is the
supported local execution environment.

## Run the actual original game code locally

See [the private-input local runner](docs/run-original-locally.md). The same runner also supports `--static-graphics-only` and `--map-graphics-paths` for original-PE direct-call/IAT mapping (explicitly **not** executed engine graphics).
For a publisher-licensed standalone candidate, run the [non-executing standalone import audit](docs/standalone-audit.md) to determine whether that executable imports Steamworks and what graphics/Windows APIs it requires. It executes the SHA-verified original x64 startup from an owned ZIP or installed files, produces metadata-only evidence, and stops fail-closed at unsupported Steamworks. **Never upload the game archive to this public repository.**

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

The public `ARM64-Lab` `main` branch has a dedicated source-only
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
