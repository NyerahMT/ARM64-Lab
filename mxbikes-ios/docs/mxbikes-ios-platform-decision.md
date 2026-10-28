# MX Bikes iOS compatibility decision record — 2026-10-27

## Verified executable and measured native progress

Original game SHA256: 4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6.
GitHub Actions green baseline: 40497252349.

- 3 independently original-x64-verified parser/initializer/CRT input cases
  now run as complete fused AArch64 guest-state tests.
- One original game startup guest CPU/stack per test is preserved through
  original DLL file-size checks, 251 fread/CRC iterations, and original
  fclose and original fixed 0xBC72 checksum comparison.
- Each native guest state reaches original SteamAPI_RestartAppIfNecessary
  CALL RVA 0x1306ED, with RCX=0xA008C (Steam App ID 655500).
- At no point is the imported Steam API invoked or its result fabricated.
  This is a Linux CI Unicorn AArch64 ELF test, NOT a compiled/signed iOS
  game, Steam client authentication, or original engine render.
- Current player-visible milestones remain zero of four.

## Actual original Windows API dependency inventory

Gated by scripts/mxbikes_platform_import_audit.py, green in same CI:

- 320 original imported Win64 symbols from 12 DLL modules.
- 10 symbols from steam_api64.dll, including Init, RestartAppIfNecessary,
  Shutdown, callback, user/pipe, and internal context/interface APIs.
- 70 symbols from OPENGL32.dll, including old fixed-function / immediate
  mode calls such as glBegin, glEnd and matrix/material functions, plus
  desktop WGL context functions wglCreateContext and wglMakeCurrent.
- 1 DirectInput8Create import, 40 USER32, 127 MSVCR90, and other Windows
  windowing, timers, networking and CRT calls.

An IAT import inventory is not a dynamic count of actual runtime calls.
Treat all unimplemented Windows services as blockers rather than success.

## Steamworks on iOS: decision

Valve Steamworks client distribution/documentation supports Windows,
macOS and Linux/SteamOS (not an official iOS game client runtime).
Valve's SteamAPI_RestartAppIfNecessary checks whether a game was
launched via desktop Steam and requests a client relaunch if necessary.
Passing a constant false result or claiming SteamAPI_Init succeeded
would manufacture a platform/authorization state and is prohibited in
this project. The native gate:

    scripts/mxbikes_steam_platform_boundary.h

stops in an explicit Unsupported iOS state at the verified guest PC
without advancing RIP or modifying RAX, RCX or import counters.
The fused ARM64 differential run verifies this behavior.

Official sources:
- https://partner.steamgames.com/doc/store/application/platforms
- https://partner.steamgames.com/doc/sdk/api
- https://partner.steamgames.com/doc/api/steam_api

## Publisher-supported alternative worth evaluating

PiBoSo also provides an official standalone MX Bikes Windows release
and a separately sold standalone license, with its own legitimate
unlock flow. This is NOT proof of an iOS license, publisher permission
for an unofficial mobile port, or a substitute for Steam ownership.
Steam-purchased and standalone licenses are not interchangeable by
assumption. Do not embed keys, patch protection, or emulate an
unverified license outcome.

Publisher sources:
- https://www.mx-bikes.com/?page=downloads
- https://www.mx-bikes.com/?page=purchase

For actual original engine execution on iOS, the viable route needs
publisher-approved distribution/authorization or a supported standalone
build and real entitlement integration. The original Windows release
has no published iOS system target.

## Engineering gates to an actual game frame

1. Obtain a legally permitted, platform-compatible startup and licensing
   strategy from the publisher. Keep ownership/authorization outside
   the generated AArch64 guest test and require genuine decisions.
2. For any authorized standalone original binary, privately hash-pin
   and map its own startup and true non-Steam dependencies; do not reuse
   the Steam executable's code addresses or license assumptions.
3. Translate the Windows window/context and original OpenGL 1.x
   fixed-function calls to a real iOS graphics backend (Metal, shaders,
   input, textures). Existing Win64 WGL cannot just be linked on iOS.
4. Measure original engine/resource-loading progress with live assets
   and actual GPU output. The first valid frame is a separate milestone
   and no screenshot/render is claimed until produced.

Do not count the number of emulated original x64 instructions as
translated original ARM64 instructions. Keep exact host/native test
cases and stop frontiers in CI metadata, not private game content.
