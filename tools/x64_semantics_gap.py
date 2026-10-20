"""Read-only, aggregate x64 instruction-family coverage report.

This does not lift code or emit byte sequences, original instruction text,
control-flow listings, or decompiled program structure. Its input may be
synthetic; callers working with licensed private binaries must keep input
private. Supported categories describe a *specific limited translator*, not
the capabilities of AArch64 or x64 generally.
"""
from collections import Counter

# The deliberately narrow public translator's currently modeled families.
SUPPORTED = frozenset({
    "mov", "lea", "cmp", "push", "pop", "add", "sub",
    "je", "jne", "jmp", "call", "ret", "nop"
})
FAMILIES = {
    "test": "flags_and_predicates",
    "jns": "flags_and_predicates",
    "js": "flags_and_predicates",
    "jbe": "flags_and_predicates",
    "ja": "flags_and_predicates",
    "movzx": "integer_width_conversion",
    "movsxd": "integer_width_conversion",
    "setne": "integer_width_conversion",
    "or": "integer_logic",
    "xor": "integer_logic",
    "and": "integer_logic",
}
MAX_INSTRUCTIONS = 4096

def summarize_mnemonics(mnemonics: dict[str, int]) -> dict:
    """Aggregate a caller-provided instruction count inventory.

    No original instructions or opcode bytes are needed. An implemented
    mnemonic can still have unsupported operands and call dependencies.
    """
    if not isinstance(mnemonics, dict) or not mnemonics or len(mnemonics) > 128:
        raise ValueError("Expected a bounded mnemonic-count dictionary")
    supported = 0
    unknown = Counter()
    groups = Counter()
    total = 0
    for mnemonic, count in mnemonics.items():
        if (not isinstance(mnemonic, str) or not mnemonic.isascii() or
            not mnemonic or len(mnemonic) > 24 or
            not mnemonic.replace("_", "").isalnum() or
            not isinstance(count, int) or isinstance(count, bool) or
            count <= 0):
            raise ValueError("Invalid mnemonic count")
        total += count
        if total > MAX_INSTRUCTIONS:
            raise ValueError("Exceeded bounded instruction inventory")
        if mnemonic in SUPPORTED:
            supported += count
        else:
            unknown[mnemonic] += count
            groups[FAMILIES.get(mnemonic, "unclassified_instruction")] += count
    return {
        "instruction_total": total,
        "mnemonics_currently_recognized": supported,
        "mnemonics_needing_extensions": sum(unknown.values()),
        "extension_families": dict(sorted(groups.items())),
        "unsupported_mnemonics": dict(sorted(unknown.items())),
        "operand_and_import_semantics_verified": False,
        "native_translation_claimed": False,
    }

def aggregate_callbacks(callbacks: dict[str, dict[str, int]]) -> dict:
    """Group several bounded function profiles in one analysis pass."""
    if not isinstance(callbacks, dict) or not 1 <= len(callbacks) <= 32:
        raise ValueError("Expected up to 32 callbacks")
    combined = Counter()
    covered = {}
    for identifier, mnemonics in callbacks.items():
        if not isinstance(identifier, str) or not identifier or len(identifier) > 64:
            raise ValueError("Invalid callback identifier")
        item = summarize_mnemonics(mnemonics)
        covered[identifier] = item
        combined.update(mnemonics)
    return {
        "callbacks": covered,
        "grouped_instruction_profile": summarize_mnemonics(dict(combined)),
        "note": "Aggregate mnemonic profile only; not a proof of translation.",
    }
