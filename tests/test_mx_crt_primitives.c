#include <stdint.h>
#include "mx_crt_primitives.h"

int main(void) {
    uint8_t teb[128]={0},shared[64]={0};
    mx_cfg_region regions[2]={{UINT64_C(0x1000),teb,sizeof(teb)},
                              {UINT64_C(0x2000),shared,sizeof(shared)}};
    mx_cfg_memory memory={regions,2};
    mx_crt_state s={0};
    uint64_t initial=UINT64_C(0x123456789abcdef0),observed=0;
    if(!mx_cfg_transfer(&memory,0x1030,&initial,8,1))return 1;
    if(!mx_crt_gs_read64(&s,&memory,0x1000,0x30,&observed) ||
       observed!=initial || s.fault)return 2;

    initial=42;
    if(!mx_cfg_transfer(&memory,0x2008,&initial,8,1))return 3;
    s.rax=42;
    if(!mx_crt_cmpxchg64_single_thread(&s,&memory,0x2008,43,1))return 4;
    if(!mx_cfg_transfer(&memory,0x2008,&observed,8,0) ||
       observed!=43 || !s.zf || s.rax!=42)return 5;

    s.rax=7;
    if(!mx_crt_cmpxchg64_single_thread(&s,&memory,0x2008,99,1))return 6;
    if(!mx_cfg_transfer(&memory,0x2008,&observed,8,0) ||
       observed!=43 || s.zf || s.rax!=43)return 7;

    if(mx_crt_cmpxchg64_single_thread(&s,&memory,0x2008,22,0) || !s.fault)
        return 8;
    s.fault=0;
    if(mx_crt_gs_read64(&s,&memory,UINT64_MAX-1,8,&observed) || !s.fault)
        return 9;
    s.fault=0;
    if(mx_crt_cmpxchg64_single_thread(&s,&memory,0x3008,123,1) || !s.fault)
        return 10;
    return 0;
}
