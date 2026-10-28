"""Native ARM64 differential for whole multi-block x64 CFGs; synthetic bytes."""
from pathlib import Path
import sys,unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import mxbikes_cfg_full_native_wave as cfg
from mxbikes_cfg_flag_ops import predicates

ORIGIN=0x240000
FORMS=[
    # TEST RCX/ JE -> both entire original RET branches
    bytes.fromhex("4885c97406b801000000c3b802000000c3"),
    # MOV ECX,3 / DEC ECX / JNE backwards / RET: bounded loop
    bytes.fromhex("b903000000ffc975fcc3"),
    # CMP ECX,0 / JLE signed -> both full returns
    bytes.fromhex("83f9007e06b801000000c3b802000000c3"),
    # Original Win64 balanced saved RBX frame across two paths
    bytes.fromhex("534883ec204885c974034889d84883c4205bc3"),
    # ADD ECX 5 / JAE -> both returns, full OF/PF state
    bytes.fromhex("83c1057306b801000000c3b802000000c3"),
    # Save R12; conditional 64-bit MOV R12 to Win64 stack frame; restore
    bytes.fromhex("41544883ec204885c974054c896424184883c420415cc3"),
    # TEST R12 / JE / MOV R12, RCX / POP R12 / complete RET
    bytes.fromhex("41544d85e474034989cc415cc3"),
    # Full guest-heap QWORD read/write across a conditional branch.
    bytes.fromhex("488b034885c9740448894308c3"),
    # CMP DWORD [RBX], IMM8 then conditional 32-bit guest-heap store.
    bytes.fromhex("833b077507c7430807000000c3"),
    # Sign-extend DWORD [RBX] before signed JL and 64-bit guest store.
    bytes.fromhex("4863034883f8007c0448894308c3"),
    # Full original RIP-relative static QWORD read followed by heap store.
    bytes.fromhex("488b05390000004885c9740448894308c3"),
    # Memory CMP DWORD [RIP+disp],IMM8 then branch and complete RET.
    bytes.fromhex("833d39000000007505b801000000c3"),
]

class FakePE:
    def __init__(self,rva,blob):
        self.rva=rva;self.code=blob+b"\xcc"*64
    def read_rva(self,offset,length):
        begin=offset-self.rva
        if begin<0 or begin+length>len(self.code):
            raise ValueError("unmapped original RVA")
        return self.code[begin:begin+length]

class CFGFullNativeTests(unittest.TestCase):
    def test_all_supported_jcc_flag_families(self):
        p=predicates()
        for op in ("je","jne","jle","jg","jb","jae","js","jp","jnp"):
            self.assertIn(op,p)

    def test_recover_and_validate_all_reachable_original_paths(self):
        for idx,blob in enumerate(FORMS):
            rva=ORIGIN+idx*0x100
            plan,why=cfg.recover_cfg(FakePE(rva,blob),rva,{rva})
            with self.subTest(idx=idx):
                self.assertIsNone(why)
                self.assertIsNotNone(plan)
                self.assertTrue(plan["complete_original_reachable_cfg"])
                self.assertGreaterEqual(plan["return_count"],1)
                self.assertGreaterEqual(plan["branch_count"],1)
                self.assertLessEqual(plan["max_offset"],len(blob))

    def test_translated_complete_cfg_x64_host_executed_arm64(self):
        plans=[]
        refs={}
        for idx,blob in enumerate(FORMS):
            rva=ORIGIN+idx*0x100
            pe=FakePE(rva,blob)
            plan,why=cfg.recover_cfg(pe,rva,{rva})
            self.assertIsNone(why,why)
            samples=[]
            for case in range(cfg.CASES):
                actual,reason=cfg.x64_reference(pe,plan,case)
                self.assertIsNone(reason,reason)
                samples.append(actual)
            refs[rva]=samples
            plans.append(plan)
        for start in range(0,len(plans),4):
            subset=plans[start:start+4]
            cfg.compile_batch(subset,refs)

    def test_original_image_read_is_exact_immutable_PE_data(self):
        rva=0x251000
        pe=FakePE(rva,bytes.fromhex("488b05390000004885c9740448894308c3"))
        plan,why=cfg.recover_cfg(pe,rva,{rva})
        self.assertIsNone(why,why)
        self.assertEqual(len(plan["original_immutable_data_reads"]),1)
        addr,data=plan["original_immutable_data_reads"][0]
        self.assertEqual(addr,cfg.BASE+rva+0x40)
        self.assertEqual(data,b"\xcc"*8)
        originals=[]
        for case in range(cfg.CASES):
            reference,error=cfg.x64_reference(pe,plan,case)
            self.assertIsNone(error,error)
            originals.append(reference)
        cfg.compile_batch([plan],{rva:originals})
        self.assertNotIn("original_immutable_data_reads",cfg.run.__doc__ or "")


    def test_x64_and_arm64_pointer_graph_fixture_remains_in_guest_heap(self):
        for case in range(cfg.CASES):
            heap=cfg.deterministic_pointer_fixture(case)
            self.assertEqual(len(heap),cfg.HEAP_BYTES)
            for slot in range(0,cfg.HEAP_BYTES,8):
                ptr=int.from_bytes(heap[slot:slot+8],"little")
                self.assertGreaterEqual(ptr,cfg.HEAP)
                self.assertLess(ptr+8,cfg.HEAP+cfg.HEAP_BYTES)

    def test_guest_heap_full_state_is_compared_in_native_fixture(self):
        rva=0x252000
        pe=FakePE(rva,bytes.fromhex("488b034885c9740448894308c3"))
        plan,why=cfg.recover_cfg(pe,rva,{rva})
        self.assertIsNone(why,why)
        self.assertEqual(plan["guest_heap_base_registers"],["rbx"])
        sample,err=cfg.x64_reference(pe,plan,0)
        self.assertIsNone(err)
        self.assertEqual(len(sample),6)
        self.assertEqual(len(sample[-1]),1024)
        altered=list(sample)
        bad=bytearray(altered[-1])
        bad[0]^=1
        altered[-1]=bytes(bad)
        with self.assertRaisesRegex(RuntimeError,"host_differential"):
            cfg.compile_batch([plan],{rva:[tuple(altered)]*cfg.CASES})


    def test_split_pdata_interval_follows_target_without_fake_function(self):
        blob=FORMS[0]
        rva=0x253000
        pe=FakePE(rva,blob)
        # Unlike the old linear interval translator, this does not stop after
        # first 5 source bytes (TEST and JE).
        plan,why=cfg.recover_cfg(pe,rva,{rva})
        self.assertIsNone(why)
        self.assertGreater(max(row["rva"] for row in plan["rows"]),rva+5)
        # Another known function starts where the JCC branch lands: fail.
        blocked,why=cfg.recover_cfg(pe,rva,{rva,rva+11})
        self.assertIsNone(blocked)
        self.assertEqual(why,"reached_other_original_function_entry")

    def test_expanded_guest_stack_store_and_load_verify_original_native(self):
        forms=[
            bytes.fromhex("4889842400050000c3"), # MOV [RSP+0x500],RAX
            bytes.fromhex("488b8c2400050000c3"), # MOV RCX,[RSP+0x500]
            bytes.fromhex("89842400050000c3"),   # MOV [RSP+0x500],EAX
            bytes.fromhex("48896c2418c3"),       # MOV [RSP+0x18],RBP
        ]
        self.assertEqual(cfg.STACK_WINDOW,16384)
        plans,refs=[],{}
        for k,body in enumerate(forms):
            rva=ORIGIN+0x100*k
            pe=FakePE(rva,body)
            plan,error=cfg.recover_cfg(pe,rva,{rva},require_branch=False)
            self.assertIsNone(error,error)
            expected=[]
            for case in range(cfg.CASES):
                got,reason=cfg.x64_reference(pe,plan,case)
                self.assertIsNone(reason,reason)
                self.assertEqual(len(got[-2]),cfg.STACK_WINDOW)
                expected.append(got)
            plans.append(plan);refs[rva]=expected
        cfg.compile_batch(plans,refs)

    def test_extended_reg_cmp_and_32bit_lea_full_native_differential(self):
        forms=[
            bytes.fromhex("8d4324c3"),  # LEA EAX,[RBX+0x24]
            bytes.fromhex("418d442430c3"), # LEA EAX,[R12+0x30]
            bytes.fromhex("4439e17406b801000000c3b802000000c3"),
        ]
        rows=[];samples={}
        for index,body in enumerate(forms):
            rva=ORIGIN+index*0x100
            pe=FakePE(rva,body)
            plan,error=cfg.recover_cfg(pe,rva,{rva},require_branch=False)
            self.assertIsNone(error,error)
            refs=[]
            for case in range(cfg.CASES):
                reference,reason=cfg.x64_reference(pe,plan,case)
                self.assertIsNone(reason,reason)
                refs.append(reference)
            rows.append(plan);samples[rva]=refs
        cfg.compile_batch(rows,samples)

    def test_conditional_move_flags_and_extended_regs_original_arm64(self):
        # Original x64 has both taken and untaken CMOVG across existing
        # distinct flag fixture cases, with every register and flag compared.
        forms=[
            bytes.fromhex("410f4fc4c3"),    # CMOVG EAX,R12D
            bytes.fromhex("490f4fc4c3"),    # CMOVG RAX,R12
            bytes.fromhex("4439e1410f4fc4c3"), # CMP ECX,R12D then CMOVG
        ]
        chosen=[];samples={}
        for k,blob in enumerate(forms):
            rva=ORIGIN+k*0x100
            pe=FakePE(rva,blob)
            plan,why=cfg.recover_cfg(pe,rva,{rva},require_branch=False)
            self.assertIsNone(why,why)
            refs=[]
            for case in range(cfg.CASES):
                x64,reason=cfg.x64_reference(pe,plan,case)
                self.assertIsNone(reason,reason)
                # Case 2 has ZF=1, so CMOVG is false. CMOV r32 still clears
                # its high half; the r64 form leaves the high half untouched.
                if case==2 and k in (0,1):
                    expected=(x64[0]["rax"]&0xffffffff if k==0
                              else x64[0]["rax"])
                    self.assertEqual(x64[2]["rax"],expected)
                refs.append(x64)
            chosen.append(plan);samples[rva]=refs
        cfg.compile_batch(chosen,samples)

    def test_32_and_64_bit_signed_imul_exact_native_full_return(self):
        # Zero extension, immediate sign extension, signed overflow CF/OF.
        forms=[
            bytes.fromhex("486bc107c3"),          # imul rax,rcx,7
            bytes.fromhex("4869c1ffffffffc3"),  # imul rax,rcx,-1
            bytes.fromhex("480fafc1c3"),        # imul rax,rcx
            bytes.fromhex("6bc107c3"),          # imul eax,ecx,7
            bytes.fromhex("496bc407c3"),        # imul rax,r12,7
        ]
        plans=[];refs={}
        for i,body in enumerate(forms):
            rva=ORIGIN+i*0x100
            pe=FakePE(rva,body)
            plan,reason=cfg.recover_cfg(pe,rva,{rva},require_branch=False)
            self.assertIsNone(reason,reason)
            fixtures=[]
            for case in range(cfg.CASES):
                sample,error=cfg.x64_reference(pe,plan,case)
                self.assertIsNone(error,error)
                fixtures.append(sample)
            plans.append(plan);refs[rva]=fixtures
        for i,plan in enumerate(plans):
            with self.subTest(imul_form=i):
                cfg.compile_batch([plan],refs)
        # Signed IMUL memory/indirect operand has no verified implementation.
        raw=bytes.fromhex("480faf01c3")
        plan,reason=cfg.recover_cfg(FakePE(ORIGIN,raw),ORIGIN,{ORIGIN},
                                    require_branch=False)
        self.assertIsNone(plan)
        self.assertTrue(reason.startswith("unsupported_original_opcode_imul_"))

    def test_stack_store_rejection_metadata_explains_untranslated_family(self):
        cases=[
            (bytes.fromhex("4889842400500000c3"),
             "unsupported_original_stack_store_displacement_over_16384"),
            (bytes.fromhex("4889842400300000c3"),
             "guest_stack_memory_outside_verified_window"),
            (bytes.fromhex("6448890424c3"),
             "unsupported_original_stack_store_segment_override"),
        ]
        for blob,expected in cases:
            plan,reason=cfg.recover_cfg(FakePE(ORIGIN,blob),ORIGIN,{ORIGIN},
                                        require_branch=False)
            self.assertIsNone(plan)
            self.assertEqual(reason,expected)

    def test_fail_closed_import_and_bad_branch_and_unbalanced_win64_stack(self):
        cases=[
            (bytes.fromhex("e800000000c3"),"original_call_requires_verified_runtime_link"),
            (bytes.fromhex("ffe0"),"indirect_or_unbounded_jump"),
            (bytes.fromhex("4883ec284885c97401c34883c428c3"),
             "original_control_flow_unbalanced_stack_merge"),
        ]
        for blob,expected in cases:
            plan,why=cfg.recover_cfg(FakePE(ORIGIN,blob),ORIGIN,{ORIGIN})
            self.assertIsNone(plan)
            # Unsafe path must be refused; specific static reason can vary
            # when an alternate path reaches a valid but unbalanced RET.
            if expected=="original_control_flow_unbalanced_stack_merge":
                self.assertIn(why,(
                    "original_control_flow_unbalanced_stack_merge",
                    "original_ret_stack_not_restored_on_all_paths",
                    "unsupported_original_opcode_int3",
                ))
            else:
                self.assertEqual(why,expected)

if __name__=="__main__":
    unittest.main()
