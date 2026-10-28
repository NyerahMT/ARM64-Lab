#!/usr/bin/env python3
"""Identify safe-to-explore original multi-basic-block x64 functions.

Read-only unwind-backed target ranking. Displays PRIVATE mnemonic/operand
metadata and never saves machine bytes or original executable sections.
"""
from pathlib import Path
import json,struct,sys,collections
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
CODES={"mov","movzx","movsxd","lea","cmp","test","add","sub","and","or","xor","inc","dec","neg","not","shl","shr","sar","imul","push","pop","nop","ret","jz","jnz","je","jne","ja","jae","jb","jbe","jg","jge","jl","jle","js","jns","jmp","sete","setne","seta","setb"}
MINIMAL={"mov","movzx","movsxd","lea","cmp","test","add","sub","and","xor","inc","dec","ret","jz","jnz","je","jne","ja","jae","jb","jbe","jg","jge","jl","jle","jmp"}
def main():
 if len(sys.argv)!=3:raise SystemExit("usage: discover_cfg.py EXE OUTDIR")
 pe=PE(Path(sys.argv[1]))
 if pe.inventory()["sha256"]!=SHA:raise RuntimeError("Unexpected executable revision")
 d,sz=pe.directory(3)
 dec=Cs(CS_ARCH_X86,CS_MODE_64);dec.detail=True
 approved=[]; stats=collections.Counter()
 for b,e,u in struct.iter_unpack("<III",pe.read_rva(d,sz)):
  if not (0 < b < e and 12<=e-b<=220):continue
  try:
   code=pe.read_rva(b,e-b)
   ins=list(dec.disasm(code,b))
  except Exception:continue
  if not ins or sum(x.size for x in ins)!=len(code) or len(ins)>70:continue
  addresses={x.address for x in ins}
  jumps=[x for x in ins if x.group(CS_GRP_JUMP)]
  if not jumps or any(x.group(CS_GRP_CALL) for x in ins) or not any(x.group(CS_GRP_RET) for x in ins):
   continue
  targets=[]
  bad=False
  for x in jumps:
   if len(x.operands)!=1 or x.operands[0].type!=X86_OP_IMM:
    bad=True;break
   target=x.operands[0].imm
   if target not in addresses:
    bad=True;break
   targets.append(target)
  if bad:continue
  badmn=[x.mnemonic for x in ins if x.mnemonic not in CODES]
  stats["internal_branch_without_calls"]+=1
  if badmn:stats["contains_unsupported_mnemonics"]+=1
  score=len(badmn)*100+len(ins)+len(jumps)*5+(0 if ins[-1].group(CS_GRP_RET) else 40)
  approved.append({
   "begin_rva":hex(b),"end_rva":hex(e),
   "bytes":e-b,"count":len(ins),"branches":len(jumps),
   "forward_branches":sum(x.operands[0].imm>x.address for x in jumps),
   "backward_branches":sum(x.operands[0].imm<=x.address for x in jumps),
   "unsupported_mnemonics":badmn,
   "simple_supported":all(x.mnemonic in MINIMAL for x in ins),
   "score":score,
   "instructions":[{"rva":hex(x.address),"mnemonic":x.mnemonic,"operands":x.op_str} for x in ins]
  })
 approved.sort(key=lambda v:(v["score"],v["bytes"]))
 backward=sorted([q for q in approved if q["backward_branches"]],key=lambda q:(len(q["unsupported_mnemonics"]),q["count"],q["bytes"]))
 best=approved[:15]
 out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
 meta={"all_internal_branch_no_call_intervals":len(approved),"minimal_supported_count":sum(q["simple_supported"] for q in approved),
       "candidates":best,"backward_candidates":backward[:15],"backward_candidate_count":len(backward), "warning":"Linear static unwind ranges and branch validation do not independently prove callable whole functions or safe memory semantics."}
 (out/"cfg-candidates.json").write_text(json.dumps(meta,indent=2)+"\n")
 lines=["# MX Bikes original CFG candidate survey","",
        f"- Decoded bounded unwind intervals with direct internal branches and no calls: {len(approved)}",
        f"- Candidates using only minimal supported mnemonics: {meta['minimal_supported_count']}",""]
 lines += ["","## Short backward-branch regions", f"- Number of backward-branch regions: {len(backward)}", ""]
 for region in backward[:10]:
  lines.append(f"### {region['begin_rva']}: {region['count']} instructions, {region['backward_branches']} back edges")
  for instr in region["instructions"]:
   lines.append(f"- {instr['rva']}: {instr['mnemonic']} {instr['operands']}")
 for c in best[:8]:
  lines += [f"## {c['begin_rva']}, {c['count']} instructions, {c['branches']} branches (backward {c['backward_branches']}), unsupported {c['unsupported_mnemonics']}",""]
  lines += [f"- {x['rva']}: {x['mnemonic']} {x['operands']}" for x in c["instructions"]]
 lines+=["","All instruction metadata stays in private CI. No original bytes are saved.",""]
 summary="\n".join(lines)
 (out/"cfg-candidates.md").write_text(summary)
 print(summary)
if __name__=="__main__":main()
