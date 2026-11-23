# MX Bikes original Steam-version startup — verified experimental frontier

Date: 2026-11-23 UTC. Canonical code: ARM64-Lab. Owned game binary input:
private `NyerahMT/ReflexBuildInput` release `Mxbikes1/Game.zip`.

**This is source-only reverse engineering of an owned Windows x64 executable,
not native iOS game startup, real Steam initialization, or license validation.**
No private game bytes have been committed to the public repository.

## Observed original x64 paths

The main original setup CRC/Steam gate uses the exact SHA-pinned binary:

- At `0x1306ED`, `SteamAPI_RestartAppIfNecessary` can be modeled false
  (no relaunch) to reach `0x1306FB`, `SteamAPI_Init`.
- Modeling Steam Init false takes original game execution into its
  error/unwind path, stopping at unsupported `KERNEL32!RtlCaptureContext`.
- Modeling Steam Init true for a **counterfactual research trace** reaches
  `SteamInternal_ContextInit` at original call `0x130710`.
- Original context argument is at RVA `0x3965D0`, with embedded callback
  RVA `0x1301C0`. The snapshot contains zero counter/cache fields.
- The original game follows an interface pointer at context offset
  `0x30` to a virtual method at table offset `0x30`, call RVA
  `0x130722`, App ID `655500`. This matches a SteamApps
  `BIsSubscribedApp`-style ownership query, but the synthetic research
  response is **NOT** a Steam ownership verification.
- With only that single virtual call answered true inside an isolated
  synthetic guest, original x64 continues to function RVA `0x133F08`
  and subsequently encounters Windows runtime/initialization services.

## Original non-Steam imports recovered in order

| Original call RVA | Interface | Research-only status |
|---|---|---|
| `0x133F24` | `WINMM!timeGetTime` | Bounded deterministic DWORD |
| `0x133F5A` | `WINMM!timeBeginPeriod(1)` | Bounded synthetic TIMERR_NOERROR |
| `0x133F60` | `WINMM!timeGetTime` | Second verified original CALL |
| `0x283956` | `MSVCR90!malloc(0x2580)` | One 9600-byte allocation into mapped guest RAM |
| `0x28396D` | `MSVCR90!memset` | Exact zero-fill of the allocated 9600 guest bytes |
| `0x284EC3` | `WS2_32.dll!#115` | **Next unsupported dependency**, corresponds to WSAStartup |

The timer, allocation and memory operations are deterministic *test*
adaptations, not native iOS integrations. Original Win64 imported-CALL
provenance is checked against exact PE bytes/IAT identity, including direct
E8 calls to original FF25 import jump thunks. All other services fail closed.

## Which CPU actually executed?

- **Original game startup in private tests:** x86-64 Unicorn guest emulator
  operating on the user's SHA-pinned original purchased executable.
- **Independent native AArch64 verification:** the narrow original post-Steam
  caller's conditional branches, pointer lookups and virtual-CALL preflight
  have been translated into freestanding C and executed in an AArch64
  emulator with synthetic Win64 guest memory.
- **Not yet achieved:** a joined native AArch64 game startup, a functioning
  Steam client/legitimate entitlement on iOS, any actual original OpenGL call,
  an MX Bikes main menu, or a rideable original game.

## Reproducible private tests

- Steam failure path:
  https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45114215817
- Real original context pointer:
  https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45114908688
- Original virtual ownership call through to timeGetTime:
  https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45115215574
- Original WinMM timing initialization:
  https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45115847232
- Original bounded CRT heap + memset:
  https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45116346462

`mxbikes-ios/scripts/mxbikes_run_owned_local.py --steam-subscription-research-probe`
is the **explicit opt-in** private diagnostic. It requires the owned
original Game.zip or installed files and produces only metadata outside the
public source tree.

## Next obstacle

Determine the real Win64 argument/version and expected WSADATA contents
for `WS2_32!WSAStartup` (imported by ordinal 115) and model its
offline/single-player behavior in an isolated guest service without
claiming an actual Windows networking stack. Do not automatically assume
Windows networking can be skipped; later socket calls or networking
initialization may be required even without online multiplayer.

For a genuine usable iOS port, a lawful ownership/entitlement path and
the still-incomplete Windows x64-to-ARM64/Metal compatibility work remain.
