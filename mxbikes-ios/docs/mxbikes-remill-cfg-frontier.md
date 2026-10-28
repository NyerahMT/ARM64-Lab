# MX Bikes CRT initializer — native translation control-flow frontier

Verified October 19, 2026 against the SHA-pinned private original executable.

## Passing execution baseline

- [Private CI run 39207913661](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39207913661) passed seven x64-vs-Remill/AArch64 test fixtures on the initializer's **15-original-instruction early-return path**.
- A strict, bounded native guest-memory fixture checks original stack writes, security-cookie complement, saved stack slots, and return-target behavior. This is a **partial path differential**, not full CPU-state or full-function equivalence.
- Nine original selected code spans generate LLVM and AArch64 objects. This is separate from correctness coverage.

## Failed full-branch probe (intentional fail-closed outcome)

- The default-cookie branch attempts five imported Windows calls. The native Remill `--bytes` experiment with unsupported-import sentinels reported **five function-call helper events and four function-return helper events** ([run 39209149365](https://github.com/NyerahMT/ReflexBuildInput/actions/runs/39209149365)).
- The original 39-instruction initializer contains only one explicit RET. The lift's call/return event pattern cannot be treated as faithful dynamic execution of the original function. No imported Win32 APIs were actually executed by this probe.
- Do **not** artificially mark the default-cookie branch working or accept unsupported Windows call returns as API success. The experimental probe has been removed from the required passing smoke test.

## Next implementation gate

1. Recover the complete original initializer CFG using verified function boundaries, block starts, direct branches, and IAT callsite targets.
2. Lift and execute individual **bounded basic blocks** in a guest-state harness; compare each transition and branch condition with original x64 Unicorn reference traces.
3. Stop at the **first unsupported imported CALL** with an explicit continuation record instead of blindly returning from `__remill_function_call`.
4. Only then connect the tested host-backed Win64 timing and process/thread-ID registry to translated register/stack state.
5. After every control-flow edge is covered, verify complete end-to-end stack, RAX/flags, global writes, and all five callsite effects, before claiming D4 complete.

The game executable, extracted function bytes, LLVM and AArch64 binary artifacts remain private and are not uploaded by this diagnostic.
