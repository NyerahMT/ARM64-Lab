# Observe the Steam-initialization *failure* path in the owned original game

This opt-in diagnostic extends the existing MX Bikes ARM64/iOS port's
authentic original Win64 x64 startup runner. It does not use the standalone
demo and does not fake a successful Steam login or license.

The normal runner still stops at the first unsupported Steam API.

## One-command diagnostic (Linux / WSL2, from repository root)

```sh
python mxbikes-ios/scripts/mxbikes_run_owned_local.py \
  --game-zip /path/to/your/owned/Game.zip \
  --out /tmp/mxb-steam-failure \
  --steam-failure-probe
```

The original SHA-pinned executable and original DLL are required exactly as
for the existing runner. The probe does not modify or upload the originals.

The opt-in handler checks the exact original import CALL bytes, IAT identity,
return PC, Win64 stack alignment and expected Steam App ID. It only returns:

- `SteamAPI_RestartAppIfNecessary` = `false`: do not relaunch.
- `SteamAPI_Init` = `false`: Steam *failed* to initialize.

All other Steam functions remain unsupported. The real game's own original x64
instructions determine the next branch. That branch may exit, fail at another
API, or follow a different code path. **No outcome is claimed until the owner
runs it and inspects the actual report.**

## Read the output

- `/tmp/mxb-steam-failure/local-steam-failure-probe.json`: brief result
- `/tmp/mxb-steam-failure/startup-steam-failure-blocks.json`: observed original
  block RVAs after the failure return(s), original import events, and stop reason
- `/tmp/mxb-steam-failure/startup-steam-failure-blocks.md`: human summary

Output is metadata only and belongs **outside** the public repository. No
game executable, DLL content, patch bytes or license data may be committed.

## Why this matters

The first startup call is not the main blocker. A failure result from
`SteamAPI_Init` lets us see how the original executable handles having no
Steam client at all. It cannot establish that an authenticated single-player
engine path exists, nor does it supply the Steamworks interfaces expected by
`SteamInternal_ContextInit` or the indirect call at `0x130722`.

The next meaningful engineering action is to use the report to identify the
first *actual* original instruction path that still prevents offline startup.
Only then decide whether a properly authorized, publisher-compatible
Steamworks adapter is feasible. The eventual iOS CPU/graphics translation
remains separate.
