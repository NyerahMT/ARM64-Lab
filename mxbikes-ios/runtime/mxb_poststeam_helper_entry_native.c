#include "mxb_poststeam_helper_entry_native.h"

static void write_guest_qword(uint8_t *stack, uint64_t at, uint64_t value)
{
    for (unsigned i=0U; i<8U; ++i)
        stack[at+i]=(uint8_t)(value>>(i*8U));
}

static uint8_t even_parity(uint8_t bits)
{
    unsigned ones=0U;
    for (unsigned i=0U;i<8U;++i)
        ones+=(unsigned)((bits>>i)&1U);
    return (uint8_t)((ones&1U)==0U);
}

int mxb_poststeam_join_to_helper_entry(mxb_poststeam_joined_guest *guest)
{
    if (guest==0 || guest->timer.rip!=MXB_POSTSTEAM_TIMER_BEGIN_PC)
        return 0;
    const uint64_t rsp0=guest->rsp;
    const uint64_t base=guest->stack_base;
    if ((rsp0&UINT64_C(15))!=0U ||
        base>UINT64_MAX-MXB_POSTSTEAM_JOINED_STACK_BYTES ||
        rsp0<base || rsp0-base<UINT64_C(0x140) ||
        rsp0-base>MXB_POSTSTEAM_JOINED_STACK_BYTES-UINT64_C(0x20))
        return 0;

    /* After preflight, every write lies inside the 1024-byte guest stack.
     * The ORIGINAL CALL pushes its return address; its destination RVA
     * is authenticated independently by the private original-byte oracle.
     */
    if (!mxb_poststeam_timer_apply(&guest->timer))
        return 0;
    const uint64_t off=rsp0-base;
    const uint64_t enter_rsp=rsp0-UINT64_C(8);
    write_guest_qword(guest->stack,off-8U,MXB_POSTSTEAM_AFTER_CALL_PC);

    /* Helper first two instructions: MOV [RSP+18h],RBX and +20h,RSI. */
    write_guest_qword(guest->stack,off+0x10U,guest->rbx);
    write_guest_qword(guest->stack,off+0x18U,guest->rsi);

    /* PUSH RDI; SUB RSP,130h. */
    write_guest_qword(guest->stack,off-0x10U,guest->rdi);
    const uint64_t prologue_rsp=enter_rsp-UINT64_C(8)-UINT64_C(0x130);
    guest->rsp=prologue_rsp;

    /* MOV RAX,[original security cookie global]; XOR RAX,RSP;
     * MOV [RSP+120h],RAX. The XOR modifies CF,PF,ZF,SF,OF;
     * AF is architecturally undefined and is not an asserted output.
     */
    const uint64_t cookie_xor=guest->security_cookie ^ prologue_rsp;
    guest->timer.rax=cookie_xor;
    uint64_t flags=guest->timer.rflags &
        ~(UINT64_C(0x1)|UINT64_C(0x4)|UINT64_C(0x40)|
          UINT64_C(0x80)|UINT64_C(0x800));
    if (even_parity((uint8_t)cookie_xor))flags|=UINT64_C(0x4);
    if (cookie_xor==0U)flags|=UINT64_C(0x40);
    if ((cookie_xor>>63U)!=0U)flags|=UINT64_C(0x80);
    guest->timer.rflags=flags;
    write_guest_qword(guest->stack,off-0x20U,cookie_xor);

    /* MOV ESI,EDX; MOV EDI,ECX, both zero-extend to 64 bits. */
    guest->rsi=(uint32_t)guest->timer.rdx;
    guest->rdi=(uint32_t)guest->timer.rcx;
    guest->timer.rip=MXB_POSTSTEAM_HELPER_NEXT_PC;
    return 1;
}
