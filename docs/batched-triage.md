# Batched root-cause / integration workflow

**Default project workflow: fix related issues together, then run one meaningful acceptance gate.** This reduces repeat GitHub Actions runs, unconnected instruction proofs and regression churn.

1. **Map related blockers** at the current *reachable original-code frontier*: record unsupported mnemonics, operand sizes, guest addresses, x64 flags, imported calls, and branch edges. Separate test-fixture errors, compiler-only errors, runtime ABI errors and authentic x64/ARM64 behavior mismatches.
2. **Solve classes, not one symptom:** extend reusable translator/runtime primitives with fail-closed input checks; keep original-game-specific bytes and code derivatives inside private CI only. Fix all identified sibling forms when they share a genuine semantic cause.
3. **Build one test matrix:** normal, failure, recursive/fallback, retry and malformed-input cases in the same public test module. Differentially compare original Unicorn x64 versus generated host C versus ARM64 ELF; check register/flags, stack/global effects, branch coverage and call order.
4. **Use the same pinned toolchain** for synthetic and private original-game checks. Create a coherent code + tests + workflow commit where practical, run a full regression batch, and inspect the complete failure summary before the next fix batch.
5. **Report precise milestones:** static decoding is not executable translation; a compiler pass is not a successful guest execution; synthetic Windows callbacks are not complete Win64 implementations; and a green startup test is not a playable iOS app. Preserve previous green evidence.
6. **Prioritize reachable startup dependency clusters** over counting arbitrary instructions. The next milestone is full correct original CRT and Win64 host behavior, not merely increasing raw translated byte counts.

Current accepted baseline: entire first CRT initializer (39 original instructions, 10/10), second CRT **49-instruction continuous original CFG region (27/27)**, and **10/10 green** private batched regression gates. The three nearest direct CRT callees resolve to import JMP thunks (`_amsg_exit`, `_initterm_e`, `_initterm`). A new synthetic-only callback bridge is native/AArch64 compile-tested but has not yet passed a private original-code call/return differential. No real Steam/engine/iPhone boot or concurrently correct LOCK.
