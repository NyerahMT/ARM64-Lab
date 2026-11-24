#include "mxb_poststeam_timer_native.h"

int mxb_poststeam_timer_apply(mxb_poststeam_timer_guest *guest)
{
    if (guest == 0 || guest->rip != MXB_POSTSTEAM_TIMER_BEGIN_PC)
        return 0;

    /* Original x64: MOV EDX, 1; MOV ECX, 0xD3B8.
     * Both zero-extend the full destination register. */
    guest->rdx = UINT64_C(1);
    guest->rcx = UINT64_C(0xD3B8);

    /* Original x64: MOV DWORD PTR [RIP+0xD172CA], EAX.
     * RAX and the arithmetic flags remain unchanged. */
    guest->global_time_ms = (uint32_t)guest->rax;
    guest->rip = MXB_POSTSTEAM_TIMER_NEXT_PC;
    return 1;
}
