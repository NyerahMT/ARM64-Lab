"""Emit native-callable C modules from validated complete CFG plans.

Only in-process plans with successful differential evidence may be supplied.
Original-derived generated source and object files belong in private local
storage. This module neither changes an executable nor models platform
authentication, imports, exceptions, or game startup.
"""
from mxbikes_cfg_full_native_wave import BASE, generate_worker

def generate_module(plans, verified_rvas):
    if not isinstance(plans,list) or not 1<=len(plans)<=192:
        raise ValueError("Invalid native module size")
    expected=set(verified_rvas)
    actual={p["rva"] for p in plans}
    if len(actual)!=len(plans) or expected!=actual:
        raise ValueError("Native module entries must match differential evidence")
    if any(not p.get("complete_original_reachable_cfg") or
           not isinstance(p["rva"],int) or not 0<p["rva"]<2**32
           for p in plans):
        raise ValueError("Invalid original function plan")
    ordered=sorted(plans,key=lambda p:p["rva"])
    bodies=[generate_worker(p,f"mx_cfg_body_{p['rva']:08x}") for p in ordered]
    cases=[f" case UINT64_C({BASE+p['rva']}): return mx_cfg_body_{p['rva']:08x}(s,m);"
           for p in ordered]
    return (
        '#include "mx_cfg_native_module.h"\n'
        + "\n".join(bodies) + "\n"
        + f"unsigned mx_cfg_native_count(void){{return {len(ordered)}U;}}\n"
        + "int mx_cfg_native_dispatch(mx_cfg_native_cpu*s,mx_cfg_memory*m){\n"
        + " if(!s||!m||!m->regions||!m->count||m->count>16U)"
          "return MX_CFG_NATIVE_INVALID_STATE;\n"
        + " switch(s->rip){\n" + "\n".join(cases) + "\n"
        + " default:return MX_CFG_NATIVE_UNREGISTERED;\n }\n}\n"
    )
