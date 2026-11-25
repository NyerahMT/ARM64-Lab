"""Prove bounded x64 OpenGL callsites; never synthesize guest return state."""
import struct


def prove_callsite(pe, iat, base, read_guest, return_va, import_pc, library, symbol):
    """Accept FF15 [RIP+disp32] or E8 -> a single FF25 import thunk.

    Match disk and mapped executable bytes and the live IAT destination.
    Other indirect calls, multi-hop thunks and mismatches remain unsupported.
    This is structural evidence, not an independent dynamic branch trace.
    """
    if not 0 <= return_va - base < 2**32 or not 0 < import_pc < 2**64:
        return None
    executable = [(rva, rva + raw) for _, _, rva, raw, _, flags in pe.sections
                  if flags & 0x20000000 and raw]

    def verified(rva, size):
        if not any(lo <= rva and rva + size <= hi for lo, hi in executable):
            return None
        try:
            raw = bytes(pe.read_rva(rva, size))
            mapped = bytes(read_guest(base + rva, size))
        except Exception:
            return None
        return raw if len(raw) == size and raw == mapped else None

    def evidence(call, slot, kind, thunk=None):
        if iat.get(slot) != (library.lower(), symbol):
            return None
        try:
            target = struct.unpack('<Q', bytes(read_guest(base + slot, 8)))[0]
        except Exception:
            return None
        if target != import_pc:
            return None
        result = {'original_call_rva': hex(call), 'original_iat_rva': hex(slot),
                  'import': library + '!' + symbol, 'call_form': kind}
        if thunk is not None:
            result['original_thunk_rva'] = hex(thunk)
        return result

    ret = return_va - base
    candidates = []
    direct = verified(ret - 6, 6)
    if direct and direct[:2] == b'\xff\x15':
        slot = ret + struct.unpack_from('<i', direct, 2)[0]
        candidates.append(evidence(ret - 6, slot, 'rip_relative_iat_call'))
    near = verified(ret - 5, 5)
    if near and near[0] == 0xe8:
        thunk = ret + struct.unpack_from('<i', near, 1)[0]
        jump = verified(thunk, 6)
        if jump and jump[:2] == b'\xff\x25':
            slot = thunk + 6 + struct.unpack_from('<i', jump, 2)[0]
            candidates.append(evidence(ret - 5, slot, 'direct_call_iat_thunk', thunk))
    matches = [row for row in candidates if row is not None]
    return matches[0] if len(matches) == 1 else None
