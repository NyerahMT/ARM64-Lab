# Steam relaunch offline ABI experiment (source-only)

This is a narrow, opt-in probe for the existing MX Bikes iOS port, **not**
Steam initialization bypass, licensing emulation, or a runnable game.

## What the first call means

At SHA-pinned original game PC `0x1401306ED`, the Windows executable calls
`steam_api64.dll!SteamAPI_RestartAppIfNecessary` with App ID 655500.
The API's `false` return means the process should not exit and relaunch
under Steam. It does not establish ownership or create Steamworks interfaces.
Valve documents this API separately from `SteamAPI_Init`.

Our proposed offline development behavior, *only in a synthetic test*, is
to return false for that exact call, set guest RIP to the verified original
return PC `0x1401306F3`, preserve the Win64 stack and other guest state,
and leave later Steam calls unimplemented.

## Source and tests

- `scripts/mxbikes_steam_offline_relaunch_experiment.h` is disabled by
  default. Enable with `MXB_EXPERIMENTAL_OFFLINE_RELAUNCH=1`.
- `tests/test_mxbikes_offline_relaunch_experiment.py` cross-compiles and
  executes both default-disabled and explicitly enabled probes on ARM64
  emulation, plus host regression cases. No game assets or DLLs are used.
- The probe asserts exact original PC, App ID, mapped and aligned stack,
  non-overflowed import count, and unchanged stack memory. It refuses
  other locations, including `SteamAPI_Init`.

Run from `mxbikes-ios`:

```sh
python -m unittest discover -s tests -p test_mxbikes_offline_relaunch_experiment.py -v
```

## Remaining blockers

The probe does **not** execute any authentic post-call game instruction.
It is not wired to the normal owned-game runner. The next startup dependency
is `SteamAPI_Init`; `SteamInternal_ContextInit` and an indirect call through
a Steam-derived context appear on statically possible later paths. Those
interfaces cannot be fabricated by this one return value. The original
engine/menu has not started.

The correct next investigation is to inspect authenticated desktop execution
of the Steam init/context interfaces and identify which features single-player
startup actually consumes. A legitimate platform entitlement approach is
still required; importing this test header into a production iOS build does
not supply one.
