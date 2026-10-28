# Run authentic MX Bikes startup locally (without private Actions)

This is a **real original-executable** test runner, unlike our synthetic Metal
triangle fixtures. It deliberately stops at an unsupported Steamworks import.
It neither activates nor bypasses Steam licensing.

## Requirements

- Linux or WSL2 Ubuntu, Python 3.11+, Clang or GCC, and the **public**
  `ARM64-Lab` checkout.
- `python -m pip install 'unicorn>=2,<3' 'capstone>=5,<6' 'pyelftools>=0.31,<1'`
- Your own **original** MX Bikes `Game.zip`, or installed `mxbikes.exe`
  and matching `steam_api64.dll`. Never commit, upload or publish these.
- The exact original executable SHA-256 is checked against
  `4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6`.

## Single-command genuine execution

Run from the repository root, with the owned ZIP **outside the clone**:

```sh
python mxbikes-ios/scripts/mxbikes_run_owned_local.py \
  --game-zip /mnt/c/Users/YOU/Downloads/Game.zip \
  --out /tmp/mxb-real-original-report
```

For directly installed files:

```sh
python mxbikes-ios/scripts/mxbikes_run_owned_local.py \
  --game-exe /path/to/owned/mxbikes.exe \
  --steam-dll /path/to/owned/steam_api64.dll \
  --out /tmp/mxb-real-original-report
```

Validate inputs before an expensive guest run:

```sh
python mxbikes-ios/scripts/mxbikes_run_owned_local.py \
  --game-zip /path/to/owned/Game.zip --validate-only \
  --out /tmp/mxb-real-original-report
```

The owned files are extracted only by fixed basenames into a restricted
temporary directory that is automatically destroyed. The output directory
must be **outside the public repository**, and contains bounded metadata
such as guest block counts, original imported call counts, blocked original
import, and actual original-OpenGL event count. No PE bytes or game assets.

Reports:

- `local-original-game-gate.json` — short factual original-code results
- `original-game-to-metal-provenance.json` — authenticated game callsite/
  guest-ABI provenance and fail-closed stop reason
- `startup-fast-blocks.json` — original x64 translated basic-block summary
- `owned-steam-file-manifest.json` — safe input size and hash verification

**The currently verified limitation:** original game x64 reaches
`steam_api64.dll!SteamAPI_RestartAppIfNecessary`, with **zero** original
OpenGL events. To progress beyond this boundary, work with the legitimate
desktop Steam environment or publisher-supported standalone initialization
and trace the genuine dependencies. Do not substitute a fabricated
Steamworks success or count a synthetic image as a real game frame.

This command makes private source-dependent testing repeatable on your own
machine. Public CI runs only fixture-based tests; it never downloads
`Game.zip` from `ReflexBuildInput`.
