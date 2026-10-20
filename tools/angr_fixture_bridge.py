"""Validate symbolic CRT path-model metadata before differential testing.

This module accepts only bounded, independent JSON metadata (no binary code,
no raw lifted instructions). Symbolic results are *candidate fixtures*, not
proof of imported-service behavior or cross-architecture equivalence.
"""
from __future__ import annotations

KNOWN = frozenset({
    "_decode_pointer", "_encode_pointer", "_lock", "_unlock",
    "_onexit", "__dllonexit"
})
VOID = frozenset({"_lock", "_unlock"})
MAX_EVENTS = 24
MASK = (1 << 64) - 1


def normalize_symbolic_models(report: dict) -> list[dict]:
    """Convert distinct completed symbolic import traces to bounded fixtures.

    Fail closed on missing service callbacks, malformed results, illegal
    values, and conflicting names. Preserve repeated import order.
    """
    if not isinstance(report, dict):
        raise ValueError("Symbolic path report must be a dictionary")
    if report.get("imports_are_symbolic_stubs") is not True:
        raise ValueError("Only explicitly modeled symbolic service paths accepted")
    if report.get("original_runtime_apis_executed") is not False:
        raise ValueError("Unexpected claim of actual runtime execution")
    candidates = report.get("candidate_models")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 24:
        raise ValueError("Missing or unbounded candidate model set")
    output = []
    seen = set()
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise ValueError("Invalid candidate")
        names = candidate.get("imports_called")
        models = candidate.get("modeled_return_values")
        if (not isinstance(names, list) or not isinstance(models, list) or
                not 1 <= len(names) <= MAX_EVENTS or len(models) > MAX_EVENTS):
            raise ValueError("Missing or unbounded import trace")
        if any(not isinstance(x, str) or x not in KNOWN for x in names):
            raise ValueError("Import trace contains an unknown callback")
        expected_names = [name for name in names if name not in VOID]
        if len(expected_names) != len(models):
            raise ValueError("Missing modeled return values")
        nonvoid = []
        for expected, item in zip(expected_names, models):
            if not isinstance(item, dict) or item.get("service") != expected:
                raise ValueError("Modeled return sequence is not aligned to imports")
            literal = item.get("chosen_synthetic_return")
            if not isinstance(literal, str) or not literal.startswith("0x"):
                raise ValueError("Model values must be explicit hexadecimal strings")
            try:
                value = int(literal[2:], 16)
            except ValueError as exc:
                raise ValueError("Malformed hexadecimal model") from exc
            if not 0 <= value <= MASK or len(literal) > 18:
                raise ValueError("Modeled value exceeds unsigned 64-bit width")
            nonvoid.append(value)
        signature = (tuple(names), tuple(nonvoid))
        if signature in seen:
            continue
        seen.add(signature)
        output.append({
            "source_candidate_index": index,
            "import_order": list(names),
            "testdouble_return_values": [hex(x) for x in nonvoid],
            "import_count": len(names),
            "is_testdouble_fixture": True,
            "verified_original_x64_equivalence": False,
            "verified_arm64_equivalence": False,
        })
    if not output:
        raise ValueError("No unique symbolic fixtures produced")
    return output
