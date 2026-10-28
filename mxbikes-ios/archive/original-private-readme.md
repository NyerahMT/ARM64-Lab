# ReflexBuildInput

Private build-input repository for `NyerahMT/ReflexRecomp`.

Expected layout:

```text
game/
  MXReflex.exe
  fmodexL.dll
  fmod_eventL.dll
  binkw32.dll
  steam_api.dll
  ...eventually the rest of the installed game...
```

The public recompilation repository consumes this repository only during manually triggered GitHub Actions runs.

Pinned executable for the first target:

```text
MXReflex.exe
SHA-256: 917d14e7ef7ce492b665fea7d0c87c9a39b549e2a43b09883d2a786988e7c02c
```

Do not rename `game/MXReflex.exe`; the analysis workflow verifies the exact hash before Ghidra or the translator run.
