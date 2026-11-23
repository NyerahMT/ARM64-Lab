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


## Follow-up: tested Winsock and PE data initialization (2026-11-23)

The original Steam-version guest continues beyond the first Winsock import
with an explicitly simulated, **offline** Windows compatibility layer.
All behavior is confined to the SHA-verified original x64 Unicorn interpreter;
no Steam authentication, host networking or original engine rendering occurs.

| Original RVA | Original import / action | Observed ABI and experimental result |
|---|---|---|
| `0x284ec3` | `WS2_32!#115 = WSAStartup` | Requested Winsock version **0x0002 (2.0)**; Win64 408-byte WSADATA written in mapped guest memory; returned synthetic success |
| `0x284cf9` | second `MSVCR90!memset` | Zero-filled **400** bytes only after validating destination is a writable, non-executable PE data section |
| `0x284d26` | `WS2_32!inet_pton` | Read a bounded, NUL-terminated guest IP literal; converted IPv4/IPv6 to network-order bytes without sockets |
| `0x284d4c` | `WS2_32!getnameinfo` | Verified original Win64 arguments: family 2 (IPv4), sockaddr byte count 28, host capacity 1025, no service buffer, flags=0. An offline numeric fallback **passed private original-executable execution**, progressing to the next WS2_32 import, `getaddrinfo` at RVA `0x284d61` |

Private original executable results:
- [WSAStartup accepted, next second memset](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45116994979)
- [Second PE data memset accepted, next inet_pton](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45117271472)
- [inet_pton accepted, next getnameinfo](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45117468156)
- [getnameinfo ABI observed](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45117590814)

`getnameinfo` with original flags=0 can return a numeric IPv4 string if a
name isn't available and `NI_NAMEREQD` is unset. Our deterministic adapter
chooses that documented fallback **without attempting a DNS query**.
It must not be mistaken for completed networking compatibility.

Production-level work remains: cross-architecture integration, actual game
asset startup, platform input/video rendering, legal entitlement integration,
and true offline/online networking decisions. The main menu has not been reached.


## Latest verified continuation: getnameinfo to getaddrinfo

The owned original-game private runner completed successfully with
the audited, DNS-free numeric `getnameinfo` fallback at `0x284d4c`.
This is a synthetic service response based on documented Windows
numeric-fallback behavior, not a resolved hostname or online networking.

Next actual unsupported original import:
`WS2_32.dll!getaddrinfo`, original IAT CALL RVA `0x284d61`,
return RVA `0x284d67`. Do not implement DNS, socket handles or
network I/O until their precise original call arguments and usage
have been independently inspected.

Evidence: [private original-game getnameinfo test](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/45117838100).
