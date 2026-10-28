#ifndef MXBIKES_ORIGINAL_POSTSEEK_NATIVE_H
#define MXBIKES_ORIGINAL_POSTSEEK_NATIVE_H
/*
 * Direct native semantic translation of the SHA-pinned original original
 * Win64 game glue at RVA 0x1305D9 ... 0x130670 plus verified original
 * 17-instruction CRC loop. Win64 CRT imports resolve through the separately
 * validated bounded read-only service adapter, never actual Steam DLL code.
 *
 * Entry: original guest pc=0x1401305D9 (first fseek CALL), original
 * R12=owned file guest token. On valid file, return with pc at original
 * 0x1401306A9 (first 1000-byte checksum complete). File-size mismatch
 * takes the actual original fclose/error branch to pc=0x14013072E.
 * No unverified SteamAPI or game-engine execution is represented.
 */
#include <stdint.h>
#include "mxbikes_native_file_crc_chain.h"

#define MXB_POSTSEEK_CALL UINT64_C(0x1401305d9)
#define MXB_POSTSEEK_FIRST_CRC_EXIT UINT64_C(0x1401306a9)
#define MXB_POSTSEEK_SIZE_FAIL UINT64_C(0x14013072e)
#define MXB_POSTSEEK_EXPECTED_DLL UINT64_C(0x3d320)
#define MXB_POSTSEEK_HANDLE UINT64_C(0x730050000)

typedef struct {
 uint64_t rbp,r12,r13,r14;
 uint32_t original_crt_calls;
 uint32_t original_branch_transfers;
} mxb_postseek_extra;

/* A real original CALL pushes a guest return address. The original
 * imported IAT thunk jumps and the typed guest CRT adapter returns.
 * Keep Win64 stack and original return slot semantics, reject unmapped SP.
 */
static inline int mxb_postseek_import_return(
 mx_crt_cluster_state *state,mx_cfg_memory *guest,
 uint64_t expected_call,uint64_t original_return)
{
 if(!state||!guest||state->rip!=expected_call||
    state->rsp<8U)return 0;
 uint64_t guest_return=original_return;
 if(!mx_cfg_transfer(guest,state->rsp-8U,&guest_return,8U,1))
    return 0;
 state->rip=original_return;
 state->imports++;
 return 1;
}

static inline int mxb_postseek_saved64(mx_cfg_memory *mem,
  uint64_t rsp,uint64_t disp,uint64_t value)
{
 if(rsp>UINT64_MAX-disp)return 0;
 return mx_cfg_transfer(mem,rsp+disp,&value,8U,1);
}

/* Status 1: exact first original loop exit, status 2: authentic size-error
 * continuation, status 0: memory/ABI/service fault, guest never fakes Steam.
 */
static inline int mxb_postseek_native_first_read(
 mx_crt_cluster_state *s,mx_cfg_memory *mem,
 mxb_readonly_file *f,mxb_postseek_extra *extra)
{
 if(!s||!mem||!f||!extra||s->fault||
    s->rip!=MXB_POSTSEEK_CALL||
    !f->is_open||
    extra->r12!=MXB_POSTSEEK_HANDLE||
    s->rcx!=extra->r12||s->rdx!=0U||s->r8!=2U||
    s->rax!=MXB_POSTSEEK_HANDLE||
    s->rsp>UINT64_MAX-0x458U)return 0;
 /* 0x1305D9 call MSVCR90!fseek(FILE*, 0, SEEK_END). */
 if(!mxb_file_seek(f,0,MXB_FILE_SEEK_END)||
    !mxb_postseek_import_return(s,mem,MXB_POSTSEEK_CALL,
                                    UINT64_C(0x1401305de)))
    return 0;
 s->rax=0U;extra->original_crt_calls++;
 /* 0x1305DE mov rcx,r12; 0x1305E1 call MSVCR90!ftell. */
 s->rcx=extra->r12;
 s->rip=UINT64_C(0x1401305e1);
 if(!mxb_postseek_import_return(s,mem,
      UINT64_C(0x1401305e1),UINT64_C(0x1401305e6)))
    return 0;
 uint64_t file_size=0U;
 if(!mxb_file_tell(f,&file_size)||file_size>UINT32_MAX)return 0;
 s->rax=file_size;extra->original_crt_calls++;
 /* 0x1305E6 xor r8d,r8d; xor edx,edx; mov rcx,r12;
  * 0x1305EE mov ebx,eax; 0x1305F0 call fseek(SET).
  */
 s->r8=0U;s->rdx=0U;s->rcx=extra->r12;
 s->rbx=(uint32_t)s->rax;
 s->rip=UINT64_C(0x1401305f0);
 if(!mxb_file_seek(f,0,MXB_FILE_SEEK_SET)||
    !mxb_postseek_import_return(s,mem,
       UINT64_C(0x1401305f0),UINT64_C(0x1401305f5)))
    return 0;
 s->rax=0U;extra->original_crt_calls++;
 /* mov esi,250656; cmp ebx,esi; je valid branch. */
 s->rsi=MXB_POSTSEEK_EXPECTED_DLL;
 s->zf=(uint8_t)(s->rbx==s->rsi);
 s->sf=(uint8_t)((int32_t)(uint32_t)s->rbx <
                 (int32_t)(uint32_t)s->rsi);
 s->cf=(uint8_t)((uint32_t)s->rbx<(uint32_t)s->rsi);
 extra->original_branch_transfers++;
 if(!s->zf){
    /* Actual fail branch: 0x1305FE mov rcx,r12;
     * 0x130601 call fclose; mov eax,1; jmp 0x13072E.
     */
    s->rcx=extra->r12;
    s->rip=UINT64_C(0x140130601);
    if(!mxb_file_close(f)||
       !mxb_postseek_import_return(s,mem,
           UINT64_C(0x140130601),UINT64_C(0x140130606)))
       return 0;
    s->rax=1U;
    s->rip=MXB_POSTSEEK_SIZE_FAIL;
    extra->original_crt_calls++;
    extra->original_branch_transfers++;
    return 2;
 }
 /* 0x130610..0x13063B original saves and CRC initialization. */
 if(!mxb_postseek_saved64(mem,s->rsp,0x448U,extra->rbp)||
    !mxb_postseek_saved64(mem,s->rsp,0x458U,s->rdi)||
    !mxb_postseek_saved64(mem,s->rsp,0x428U,extra->r13)||
    !mxb_postseek_saved64(mem,s->rsp,0x420U,extra->r14))
    return 0;
 extra->rbp=UINT64_C(0x1d0f);
 extra->r13=1000U;
 extra->r14=255U;
 /* 0x130641 mov edi,esi; cmp esi,r13d; cmovg edi,r13d;
  * 0x130646 lea rcx,[rsp+0x20]; mov r9,r12;
  * 0x130652 mov edx,1; movsxd r8,edi; CALL fread.
  */
 s->rdi=s->rsi;
 s->zf=(uint8_t)((uint32_t)s->rsi==(uint32_t)extra->r13);
 s->sf=0U;s->cf=0U;
 if((int32_t)(uint32_t)s->rsi>(int32_t)(uint32_t)extra->r13)
    s->rdi=extra->r13;
 s->rcx=s->rsp+0x20U;
 s->r9=extra->r12;
 s->rdx=1U;
 s->r8=s->rdi;
 s->rip=UINT64_C(0x14013065a);
 uint64_t buffer=s->rcx;
 uint32_t copied=0U;
 if(!mxb_file_read(f,mem,buffer,(uint32_t)s->r8,&copied)||
    !mxb_postseek_import_return(s,mem,
         UINT64_C(0x14013065a),UINT64_C(0x14013065f)))
    return 0;
 s->rax=copied;extra->original_crt_calls++;
 /* Original 0x13065F MOVZX EBX,BP; TEST EDI,EDI; JE (not taken).
  * The original checksum loop counts EDI rather than fread RAX.
  */
 s->rbx=(uint16_t)extra->rbp;
 s->zf=(uint8_t)((uint32_t)s->rdi==0U);
 s->sf=0U;s->cf=0U;
 if(s->zf||copied!=(uint32_t)s->rdi)return 0;
 extra->original_branch_transfers++;
 s->rip=MXB_CRC_LOOP_VA;
 s->rcx=buffer;
 s->rdx=s->rdi;
 if(!mxb_crc_cluster_run(s,mem,extra->r14))
    return 0;
 if(s->rip!=MXB_POSTSEEK_FIRST_CRC_EXIT||
    s->rdx!=0U||s->rcx!=buffer+s->rdi)
    return 0;
 return 1;
}

/* Continue the *real original* 0x1306A9 SUB ESI,EDI / MOV BP,BX / JNE
 * back-edge over all remaining 1000-byte fread/CRC chunks, then the
 * authentic 0x1306B3 fclose CALL and 0x1306B8 return frontier.
 *
 * Must be invoked only after mxb_postseek_native_first_read returned 1,
 * with live registers and guest stack unchanged. Distinct CALL/Jcc
 * destinations and bounded guest buffer are from the SHA-verified game.
 */
#define MXB_POSTSEEK_AFTER_CLOSE UINT64_C(0x1401306b8)
static inline int mxb_postseek_native_finish_reads(
 mx_crt_cluster_state *s,mx_cfg_memory *mem,
 mxb_readonly_file *f,mxb_postseek_extra *extra)
{
 if(!s||!mem||!f||!extra||s->fault||
    s->rip!=MXB_POSTSEEK_FIRST_CRC_EXIT||
    !f->is_open||extra->r12!=MXB_POSTSEEK_HANDLE||
    extra->r13!=1000U||extra->r14!=255U||
    s->rsi!=MXB_POSTSEEK_EXPECTED_DLL||
    s->rdi!=1000U||f->position!=1000U)
    return 0;
 const uint64_t guest_buffer=s->rsp+0x20U;
 if(guest_buffer<s->rsp)return 0;
 uint32_t loops=0U;
 for(;;){
    /* Original 0x1306A9 SUB ESI,EDI (32-bit write);
     * 0x1306AB MOV BP,BX (16-bit write);
     * 0x1306AE JNE 0x130641.
     */
    if((uint32_t)s->rsi<(uint32_t)s->rdi)return 0;
    s->rsi=(uint32_t)((uint32_t)s->rsi-(uint32_t)s->rdi);
    extra->rbp=(extra->rbp&UINT64_C(0xffffffffffff0000))|
               (uint16_t)s->rbx;
    s->zf=(uint8_t)(s->rsi==0U);
    s->sf=0U;s->cf=0U;
    extra->original_branch_transfers++;
    if(s->zf)break;
    /* Original loop body 0x130641..0x13065A; signed CMOVG cap at 1000.
     * Then original fread CALL/JMP/RET, MOVZX EBX,BP, TEST EDI,
     * LEA RCX and original CRC loop to 0x1306A9.
     */
    s->rdi=s->rsi;
    s->zf=(uint8_t)((uint32_t)s->rsi==(uint32_t)extra->r13);
    s->sf=0U;s->cf=0U;
    if((int32_t)(uint32_t)s->rsi>(int32_t)(uint32_t)extra->r13)
        s->rdi=extra->r13;
    if(s->rdi==0U||s->rdi>MXB_FILE_CHUNK)return 0;
    s->rcx=guest_buffer;
    s->r9=extra->r12;
    s->rdx=1U;s->r8=s->rdi;
    s->rip=UINT64_C(0x14013065a);
    uint32_t copied=0U;
    if(!mxb_file_read(f,mem,guest_buffer,(uint32_t)s->r8,&copied)||
       !mxb_postseek_import_return(s,mem,
          UINT64_C(0x14013065a),UINT64_C(0x14013065f))||
       copied!=(uint32_t)s->rdi)
        return 0;
    s->rax=copied;
    extra->original_crt_calls++;
    s->rbx=(uint16_t)extra->rbp;
    s->zf=0U;s->sf=0U;s->cf=0U;
    s->rip=MXB_CRC_LOOP_VA;
    s->rcx=guest_buffer;
    s->rdx=s->rdi;
    if(!mxb_crc_cluster_run(s,mem,extra->r14)||
       s->rip!=MXB_POSTSEEK_FIRST_CRC_EXIT||
       s->rcx!=guest_buffer+s->rdi)
        return 0;
    loops++;
    if(loops>251U)return 0;
 }
 /* 0x1306B0 MOV RCX,R12; 0x1306B3 CALL MSVCR90!fclose.
  * Stop BEFORE the unported original callee restore at 0x1306B8.
  */
 s->rcx=extra->r12;
 s->rip=UINT64_C(0x1401306b3);
 if(!mxb_file_close(f)||
    !mxb_postseek_import_return(s,mem,
       UINT64_C(0x1401306b3),MXB_POSTSEEK_AFTER_CLOSE))
    return 0;
 s->rax=0U;
 extra->original_crt_calls++;
 return !f->is_open&&s->rip==MXB_POSTSEEK_AFTER_CLOSE;
}

/* SHA-pinned actual original post-close epilogue 0x1306B8..0x1306ED:
 * restore callee-saved registers, compare BX against fixed expected
 * CRC 0xBC72, conditionally reject, then set RCX=0xA008C and STOP at
 * the UNIMPLEMENTED SteamAPI_RestartAppIfNecessary imported CALL.
 *
 * Never invokes Steam, assumes a valid Steam client, or invents auth.
 */
#define MXB_POSTSEEK_STEAM_BOUNDARY UINT64_C(0x1401306ed)
#define MXB_POSTSEEK_EXPECTED_CRC UINT64_C(0xbc72)
static inline int mxb_postseek_native_until_steam(
 mx_crt_cluster_state *s,mx_cfg_memory *mem,mxb_postseek_extra *extra)
{
 if(!s||!mem||!extra||s->fault||
    s->rip!=MXB_POSTSEEK_AFTER_CLOSE||
    s->rsp>UINT64_MAX-0x458U)return 0;
 uint64_t restored=0U;
 if(!mx_cfg_transfer(mem,s->rsp+0x420U,&restored,8U,0))
     return 0;
 extra->r14=restored;
 if(!mx_cfg_transfer(mem,s->rsp+0x428U,&restored,8U,0))
     return 0;
 extra->r13=restored;
 if(!mx_cfg_transfer(mem,s->rsp+0x458U,&restored,8U,0))
     return 0;
 s->rdi=restored;
 if(!mx_cfg_transfer(mem,s->rsp+0x448U,&restored,8U,0))
     return 0;
 extra->rbp=restored;
 /* MOV R11D, 0xBC72; CMP BX,R11W; JNE to error path. */
 s->r11=MXB_POSTSEEK_EXPECTED_CRC;
 uint16_t observed=(uint16_t)s->rbx;
 const uint16_t reference=(uint16_t)s->r11;
 s->zf=(uint8_t)(observed==reference);
 s->sf=(uint8_t)((int16_t)(uint16_t)(observed-reference)<0);
 s->cf=(uint8_t)(observed<reference);
 extra->original_branch_transfers++;
 if(!s->zf){
    /* Original 0x130606 MOV EAX,1; JMP 0x13072E. */
    s->rax=1U;
    s->rip=MXB_POSTSEEK_SIZE_FAIL;
    extra->original_branch_transfers++;
    return 2;
 }
 /* 0x1306E8 MOV ECX,0xA008C; 0x1306ED Steam imported CALL. */
 s->rcx=UINT64_C(0xa008c);
 s->rip=MXB_POSTSEEK_STEAM_BOUNDARY;
 return 1;
}
#endif
