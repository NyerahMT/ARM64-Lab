/* Bounded guest-memory fixture for a privately lifted CRT initializer.
 * Not a Windows memory manager. No commercial code or original bytes.
 */
#include <stdint.h>
#include <stddef.h>

#define COOKIE_OFFSET UINT64_C(0xe6f4c)
#define COOKIE_COMPLEMENT (COOKIE_OFFSET + UINT64_C(8))
#define RET_SENTINEL UINT64_C(0x12345678)
#define STACK_SAVE_RBX UINT64_C(24)
#define STACK_LOCAL UINT64_C(8)
#define STACK_PUSH_RDI UINT64_C(0xfffffffffffffff8)

typedef struct { uint64_t addr, value; uint32_t valid; } cell;
static cell map[12];
static unsigned reads, writes, calls, returns, faults;
static uint64_t return_pc, expected_cookie;

static int permitted(uint64_t a) {
    return a==0 || a==STACK_SAVE_RBX || a==STACK_LOCAL ||
           a==STACK_PUSH_RDI || a==COOKIE_OFFSET ||
           a==COOKIE_COMPLEMENT;
}
static cell *get(uint64_t addr) {
    for (unsigned i=0;i<12;i++)
        if (map[i].valid && map[i].addr==addr) return &map[i];
    return (cell*)0;
}
static int put(uint64_t addr,uint64_t val) {
    if (!permitted(addr)) {faults++;return 0;}
    cell *entry=get(addr);
    if (!entry) {
        for(unsigned i=0;i<12;i++)
            if (!map[i].valid) {entry=&map[i];break;}
    }
    if (!entry) {faults++;return 0;}
    entry->valid=1;entry->addr=addr;entry->value=val;
    return 1;
}
void mx_prepare(uint64_t seed) {
    expected_cookie=seed;
    for(unsigned i=0;i<12;i++)map[i].valid=0;
    reads=0;writes=0;calls=0;returns=0;faults=0;return_pc=0;
    (void)put(0,RET_SENTINEL);
    (void)put(COOKIE_OFFSET,seed);
    (void)put(COOKIE_COMPLEMENT,0);
}
uint64_t __remill_read_memory_64(void *memory,uint64_t address) {
    (void)memory;
    reads++;
    cell *entry=get(address);
    if (!entry) {faults++;return 0;}
    return entry->value;
}
void *__remill_write_memory_64(void *memory,uint64_t address,uint64_t value) {
    writes++;
    (void)put(address,value);
    return memory;
}
void *__remill_function_call(void *state,uint64_t pc,void *memory) {
    (void)state;(void)pc;
    calls++;faults++;
    return memory;
}
void *__remill_function_return(void *state,uint64_t pc,void *memory) {
    (void)state;
    returns++;return_pc=pc;
    return memory;
}
unsigned mx_status(void) {
    cell *cookie=get(COOKIE_OFFSET);
    cell *comp=get(COOKIE_COMPLEMENT);
    cell *saved=get(STACK_SAVE_RBX);
    cell *pushed=get(STACK_PUSH_RDI);
    if (faults || calls || returns!=1 || reads<3 || writes!=4) return 1;
    if (!cookie || !comp || !saved || !pushed) return 2;
    if (cookie->value!=expected_cookie || comp->value!=(~expected_cookie)) return 3;
    if (saved->value!=0 || pushed->value!=0) return 4;
    if (return_pc!=RET_SENTINEL) return 5;
    return 0;
}
