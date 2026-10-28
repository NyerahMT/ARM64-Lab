#!/usr/bin/env python3
"""Bounded angr experiment on one SHA-pinned, privately owned CRT child.

Loads an authentic original PE into angr, but models *all* MSVCR90 imports
as explicitly symbolic test doubles. Discovers feasible local branch outcomes
and import-result assignments. No Windows runtime, correct child behavior,
native ARM64 game execution, or game code translation is claimed.

No original PE bytes, IR, pseudocode, original instruction text or LLVM is
printed/uploaded. The only output is bounded address/call-path metadata.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sys
import time

import angr
import claripy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "arm64-lab"))
from tools.pe_probe import PE

SHA = "4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE = 0x140000000
CHILD = 0x2ab734
SENTINEL = 0x500000100
STACK = 0x700000000
SP = STACK + 0xfe08
MAX_STEPS = 90
MAX_ACTIVE = 24
MAX_SECONDS = 105
# The function's exact ten import call sites were recovered by private CI.
# These are IMPORT IAT slots; 7 direct and 3 via verified call JMP thunks.
SLOTS = {
    0x321550: "_decode_pointer",
    0x321548: "_onexit",
    0x321508: "_encode_pointer",
    0x321540: "_lock",
    0x321538: "__dllonexit",
    0x321530: "_unlock",
}

class ModelService(angr.SimProcedure):
    """Intentionally symbolic call boundary, NOT MSVCR90 implementation."""
    def run(self, *args):
        name = self.display_name
        records = list(self.state.globals.get("crt_service_trace", []))
        index = len(records)
        records.append(name)
        self.state.globals["crt_service_trace"] = records
        if index >= 24:
            self.exit(1)
            return None
        if name in ("_lock", "_unlock"):
            # These are void APIs; symbolic-lock semantics are not asserted.
            return claripy.BVV(0, 64)
        token = claripy.BVS("testdouble_" + name.replace("_", "x") +
                             "_" + str(index), 64)
        symbols = list(self.state.globals.get("crt_return_tokens", []))
        symbols.append((name, token))
        self.state.globals["crt_return_tokens"] = symbols
        return token


def configure(exe):
    if hashlib.sha256(exe.read_bytes()).hexdigest() != SHA:
        raise RuntimeError("Original-game executable hash mismatch")
    pe = PE(exe)
    if pe.u64(pe.opt+24) != BASE:
        raise RuntimeError("Pinned original PE image base changed")
    project = angr.Project(str(exe), auto_load_libs=False)
    if project.loader.main_object.mapped_base != BASE:
        raise RuntimeError("angr mapped the original PE at an unexpected base")
    iat_rva, length = pe.directory(1)
    if not iat_rva or length > 0x10000:
        raise RuntimeError("Original import descriptor bounds changed")
    imports = {}
    for n in range(128):
        ilt, _, _, lib, iat = __import__("struct").unpack(
            "<IIIII", pe.read_rva(iat_rva+20*n, 20))
        if not ilt and not iat:
            break
        dll = pe.string(lib).lower()
        for index in range(4096):
            thunk = int.from_bytes(
                pe.read_rva((ilt or iat)+8*index,8), "little")
            if not thunk:
                break
            if thunk & (1<<63):
                name = "#" + str(thunk & 0xffff)
            else:
                name = pe.string(thunk + 2)
            imports[iat+8*index] = dll + "::" + name
        else:
            raise RuntimeError("Unbounded import table")
    wanted = {"msvcr90.dll::" + name for name in SLOTS.values()}
    hooked = {}
    for slot_rva, name in SLOTS.items():
        expected = "msvcr90.dll::" + name
        if imports.get(slot_rva) != expected:
            raise RuntimeError("Original IAT symbol mismatch at " + hex(slot_rva))
        addr = int.from_bytes(
            project.loader.memory.load(BASE+slot_rva, 8), "little")
        if addr == 0 or addr in hooked:
            raise RuntimeError("Unresolved or aliased imported target " + name)
        # Symbol lookup alone may not preserve the exact PE IAT indirection.
        # Hook the address which the original call instruction will read.
        project.hook(addr, ModelService(display_name=name), replace=True)
        if not isinstance(project.hooked_by(addr), ModelService):
            raise RuntimeError("Our explicit service hook did not replace angr import stub: " + name)
        hooked[addr] = name
    if set(hooked.values()) != set(SLOTS.values()):
        raise RuntimeError("One or more import hooks not installed")
    return project, hooked


def run(exe, output):
    started = time.monotonic()
    project, hooked = configure(exe)
    state = project.factory.blank_state(
        addr=BASE+CHILD,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.rsp = claripy.BVV(SP, 64)
    state.regs.rcx = claripy.BVV(BASE+0x2ab900, 64)
    state.memory.store(SP, claripy.BVV(SENTINEL,64),
                       endness=project.arch.memory_endness)
    state.globals["crt_service_trace"] = []
    state.globals["crt_return_tokens"] = []
    simgr = project.factory.simgr(state, save_unconstrained=True)
    finished, visited, stepped, pruned, errored = [], set(), 0, 0, 0
    while simgr.active and stepped < MAX_STEPS and time.monotonic()-started < MAX_SECONDS:
        for s in simgr.active:
            if s.addr == SENTINEL:
                finished.append(s)
        simgr.move(from_stash="active", to_stash="finished",
                   filter_func=lambda s: s.addr == SENTINEL)
        for s in simgr.active:
            if BASE+CHILD <= s.addr < BASE+0x2ab7e4:
                visited.add(s.addr-BASE)
        if not simgr.active:
            break
        simgr.step()
        stepped += 1
        if len(simgr.active) > MAX_ACTIVE:
            pruned += len(simgr.active)-MAX_ACTIVE
            simgr.stashes["active"] = simgr.active[:MAX_ACTIVE]
        errored = len(simgr.errored)
        if errored > 20:
            break
    finished.extend([s for s in simgr.active if s.addr == SENTINEL])
    scenarios = []
    seen = set()
    for s in finished[:MAX_ACTIVE]:
        trace = list(s.globals.get("crt_service_trace", []))
        models = []
        for name, tok in s.globals.get("crt_return_tokens", [])[:16]:
            models.append({"service": name,
                           "chosen_synthetic_return": hex(s.solver.eval(tok))})
        key = (tuple(trace), tuple((x["service"], x["chosen_synthetic_return"])
                                  for x in models))
        if key in seen:
            continue
        seen.add(key)
        scenarios.append({"imports_called": trace, "modeled_return_values": models})
    elapsed = round(time.monotonic()-started, 2)
    report = {
        "kind": "bounded_original_instruction_symbolic_path_pilot",
        "original_code_loaded_privately": True,
        "original_runtime_apis_executed": False,
        "imports_are_symbolic_stubs": True,
        "native_arm64_executed": False,
        "exe_hash_pinned": True,
        "child_rva": hex(CHILD),
        "hooked_msvcr90_symbols": sorted(set(hooked.values())),
        "hooked_symbol_count": len(hooked),
        "elapsed_seconds": elapsed,
        "basic_block_steps": stepped,
        "visited_child_block_addresses": [hex(i) for i in sorted(visited)],
        "completed_paths": len(finished),
        "unique_fixture_candidates": len(scenarios),
        "candidate_models": scenarios,
        "states_pruned": pruned,
        "errored_states": errored,
        "max_step_limit_hit": stepped >= MAX_STEPS,
        "timeout_hit": elapsed >= MAX_SECONDS,
        "limitations": [
            "Symbolic imported return values do not implement Windows APIs.",
            "The candidate model is not a validated original/ARM64 differential.",
            "This pilot does not lift or compile the original child function.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output/"crt-angr-path-pilot.json").write_text(
        json.dumps(report, indent=2)+"\n")
    summary = "\n".join([
        "# Bounded private original CRT symbolic-path pilot", "",
        "- Import hooks modeled: **"+str(len(hooked))+"**",
        "- Completed symbolic paths: **"+str(len(finished))+"**",
        "- Unique candidate return models: **"+str(len(scenarios))+"**",
        "- Bounded basic-block steps: **"+str(stepped)+"**",
        "- Unique original child block addresses visited: **"+str(len(visited))+"**",
        "- Elapsed seconds: **"+str(elapsed)+"**",
        "- Pruned symbolic states: **"+str(pruned)+"**",
        "- Errored paths: **"+str(errored)+"**", "",
        "**All imported CRT calls used symbolic test doubles. No DLL behavior, "
        "original/native equivalence, or iOS execution is claimed.**", "",
    ])
    (output/"crt-angr-path-pilot.md").write_text(summary)
    print(summary)
    # The pilot is successful only when it produces at least one actual
    # completed original-code path rather than merely loading the PE.
    exercised_imports = set(
        name for sample in scenarios for name in sample["imports_called"])
    if not finished or not visited or not scenarios or not exercised_imports:
        raise RuntimeError("angr produced no tested import-backed CRT path fixtures")


if __name__ == "__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py private-original-exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
