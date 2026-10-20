# MX Bikes Steam bootstrap — verified boundary and allowed integration plan

Updated 2026-10-20. This is a planning/compatibility specification, **not** a functioning Steam client, game launch, iOS binary or Steamworks authorization.

## Observed original-game boundary (private, pinned owned executable)

A bounded original x64 execution trace reached **4,266,955 guest instructions** and **290 imported call events** over **25 imported function names**, then stopped at an unsupported `steam_api64.dll::SteamAPI_Init`. No windowing, OpenGL/WGL or graphical game engine call had yet been observed.

The original 19-instruction unwind function at RVA `0x1306E8` contains these verified import callsites, treated as **one dependency family**:

| Observed original import | Host policy |
| --- | --- |
| `SteamAPI_RestartAppIfNecessary` | Steamworks external runtime required, no success manufactured |
| `SteamAPI_Init` | Steamworks external runtime required, no success manufactured |
| `SteamInternal_ContextInit` | Steamworks external runtime required, no pointer/interface manufactured |

The original blocked `SteamAPI_Init` CALL is at RVA `0x1306FB`. Guest stack continuation RVA `0x130701` remains **unexecuted**; a nearby conditional branch exists but the strict accumulator-zero classifier could not validate its exact branch destinations. These RVAs apply only to the SHA-pinned original revision.

Evidence: [private x64 entry run](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39382073548), and [19-gate native CRT regression](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39420065828).

## What the official platform and API documents establish

Steam officially supports **Windows, macOS and Linux/SteamOS**, but does not advertise iOS Steamworks client support. The macOS `libsteam_api.dylib` can contain ARM64 code; that does **not** make it an iOS Steam client library.

- [Steamworks API overview](https://partner.steamgames.com/doc/sdk/api): supported desktop development environments, required redistributable binaries and platform linking.
- [Steamworks platforms](https://partner.steamgames.com/doc/store/application/platforms): Windows, macOS, Linux/SteamOS.
- [SteamAPI_Init documentation](https://partner.steamgames.com/doc/api/steam_api): successful initialization means required interfaces are available. It can fail when the Steam client is absent, the App ID/license is unavailable, or environment/user context is wrong.
- `SteamAPI_RestartAppIfNecessary` can relaunch the executable through the Steam client; simply returning false or inventing an App ID does not implement Steam services or authenticate ownership.

## Development approaches, ranked

1. **Developer-authorized native initialization contract** (recommended): ask PiBoSo to define and/or provide an approved non-Steam initialization route for an iOS build and the relevant game runtime/assets, replacing Steam-specific services with genuine developer-supplied interfaces where necessary. Verify license and ownership requirements explicitly. Until available, the Windows Steam client ABI is an external unresolved frontier.
2. **Privately inspect and isolate the complete Steam call family** without executing past the unsupported API or assigning invented successful return values. Use static and real Windows-host instrumentation to determine which interfaces and callbacks are actually required for gameplay versus optional overlay/achievements. Record results as independent metadata, not a working native boot.
3. **Supported desktop execution or legitimate streaming** for playing on a phone is a separate product and does not count as running the game engine natively on iOS.

Do not build or ship bypasses for game ownership/license enforcement. No DLL token, Steam authentication pointer, synthetic initialization-success return, or Windows-only runtime shim may be classified as **production supported** until its actual semantics and legal integration are verified.

## Measurable milestones

- **Steam bootstrap inventory:** all three imports classified as external services and native dispatcher refuses them without mutating guest return registers.
- **Original failure-path/control-flow evidence:** independently observe the real failure behavior on a supported, licensed desktop environment (or obtain developer guidance); distinguish static conditional edges from executed ones.
- **Authorized iOS startup integration:** actual Steam-free developer contract available, native ARM64 CRT and external dependencies joined, and first original engine work verified on target.
- **Frame/menu:** only count true original game rendering and controller-usable menu after that.

The four overall project milestones remain native startup, engine initialization, first real rendered frame, and interactive original menu.
