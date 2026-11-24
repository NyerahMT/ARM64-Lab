"""Generate non-executable original image data for a private native build."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM

def init_static_refs(pe):
    base=pe.u64(pe.opt+24)
    d=Cs(CS_ARCH_X86,CS_MODE_64);d.detail=True
    refs=set()
    for i in d.disasm(pe.read_rva(0x133e80,0x133efb-0x133e80),base+0x133e80):
        if i.mnemonic=="lea":continue
        for op in i.operands:
            if op.type==X86_OP_MEM and i.reg_name(op.mem.base)=="rip":
                refs.add((i.address+i.size+op.mem.disp,op.size))
    return sorted(refs)

def prepare_data(pe,destination):
    base=pe.u64(pe.opt+24)
    size=pe.u32(pe.opt+56);align=pe.u32(pe.opt+32)
    header=pe.u32(pe.opt+60)
    if not 0<size<=128*1024*1024 or align<4096 or align&(align-1):
        raise ValueError("Unexpected image layout")
    def rounded(n):return (n+align-1)&~(align-1)
    segments=[(0,rounded(header),pe.b[:header],1)]
    if not 0<header<=len(pe.b):raise ValueError("Invalid image header")
    for _,virtual,rva,raw,offset,flags in pe.sections:
        if flags&0x20000000 or not flags&0x40000000:continue
        span=rounded(max(virtual,raw))
        if not span:continue
        if rva%align or rva+span>size or offset+raw>len(pe.b):
            raise ValueError("Invalid data section")
        segments.append((rva,span,pe.b[offset:offset+raw],3 if flags&0x80000000 else 1))
    lines=['#include "mxb_owned_startup.h"','#include <stdlib.h>','#include <string.h>']
    for j,(_,_,raw,_) in enumerate(segments):
        if not raw:continue
        lines.append(f"static const uint8_t raw_{j}[{len(raw)}]={{")
        lines.extend(",".join(map(str,raw[k:k+32]))+"," for k in range(0,len(raw),32))
        lines.append("};")
    lines.extend(["int mxb_private_data_init(MXBOwnedStartup *p,MXBGuestMemory *m){",
                  "if(!p||!m||p->image_backing)return 0;",
                  f"uint8_t *b=calloc({size}u,1);if(!b)return 0;",
                  "MXBGuestMemory staged=*m;"])
    for j,(rva,span,raw,perm) in enumerate(segments):
        if raw:lines.append(f"memcpy(b+{rva}u,raw_{j},sizeof(raw_{j}));")
        lines.append(f"if(!mxb_guest_map_gaps(&staged,UINT64_C({base+rva}),b+{rva}u,{span}u,{perm}))goto fail;")
    lines.extend(["p->image_backing=b;*m=staged;return 1;","fail:free(b);return 0;","}"])
    (destination/"mxb_private_image_data.c").write_text("\n".join(lines)+"\n")
    refs=init_static_refs(pe)
    (destination/"mxb_init_data_layout.h").write_text(
        f"#define MXB_INIT_DATA_COUNT {len(refs)}u\n"+
        "static const uint64_t mxb_init_data_addresses[]={"+",".join(f"UINT64_C({a})" for a,_ in refs)+"};\n"+
        "static const unsigned mxb_init_data_sizes[]={"+",".join(str(n) for _,n in refs)+"};\n")
    print(f"Private data image: {len(segments)} non-executable ranges, {sum(s for _,s,_,_ in segments)} mapped bytes")
