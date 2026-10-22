#ifndef MX_GAME_FILENAME_SCAN_H
#define MX_GAME_FILENAME_SCAN_H
/*
 * Original MX Bikes filename-parser second stage: bounded iterative joining
 * of previously verified original x64 blocks, all in ONE mapped guest process.
 * This is not a replacement for original code after the zero-byte boundary.
 *
 * Original block identities:
 * 0x15b7f5 MOV RAX,[RSP+0x28]; MOV [RSP+0x20],RAX
 * 0x15b7ff JMP 0x15b7c1
 * 0x15b7c1 ... increment/check next byte, JE 0x15b801 else 0x15b7db
 * 0x15b7db compare '\\', JE 0x15b7f5, else 0x15b7e8
 * 0x15b7e8 compare '/', JNE 0x15b7ff else 0x15b7f5
 * 0x15b801 CMP [RSP+0x20],0; JE 0x15b81b else 0x15b809
 *
 * No unbounded host string operations or opaque x64 emulation. Every guest
 * read and write is bounded through mx_cfg_memory; missing terminators fail
 * closed at the explicitly configured maximum byte count.
 */
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#include "mx_game_filename_loop_iteration.h"
#include "mx_game_path_separator_branch.h"
#include "mx_game_path_slash_loop.h"

enum {
    MX_GAME_FILENAME_SCAN_REACHED=1,
    MX_GAME_FILENAME_SCAN_INVALID=-191,
    MX_GAME_FILENAME_SCAN_MEMORY=-192,
    MX_GAME_FILENAME_SCAN_LIMIT=-193,
    MX_GAME_FILENAME_SCAN_UNEXPECTED=-194
};
typedef struct {
    mx_game_filename_iteration_layout iteration;
    mx_game_path_separator_layout separators;
    mx_game_slash_loop_layout slash;
    uint64_t separator_record_va;  /* 0x15b7f5 */
    uint64_t loop_back_va;         /* 0x15b7c1 */
    uint64_t return_with_separator_va; /* 0x15b809 */
    uint64_t return_without_separator_va; /* 0x15b81b */
    uint32_t max_bytes;
} mx_game_filename_scan_layout;
typedef struct {
    uint32_t loop_iterations;
    uint32_t separator_records;
    uint32_t ordinary_characters;
    uint8_t ended_with_separator;
    uint64_t terminator;
    uint64_t last_separator;
} mx_game_filename_scan_result;

/* Original two MOVs + JMP preserve arithmetic flags; RAX becomes the
 * current separator pointer. Preflight both stack locals before mutation.
 */
static inline int mx_game_filename_record_separator(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_filename_scan_layout*l) {
    if(!s||!m||!l||s->fault||s->rip!=l->separator_record_va||
       (s->rsp&15U)!=0U||s->rsp>UINT64_MAX-0x30U||
       !l->loop_back_va)
       return MX_GAME_FILENAME_SCAN_INVALID;
    uint64_t pointer=0U,previous=0U;
    if(!mx_cfg_transfer(m,s->rsp+0x28U,&pointer,8U,0)||
       !mx_cfg_transfer(m,s->rsp+0x20U,&previous,8U,0)||
       !pointer)
        return MX_GAME_FILENAME_SCAN_MEMORY;
    if(!mx_cfg_transfer(m,s->rsp+0x20U,&pointer,8U,1))
        return MX_GAME_FILENAME_SCAN_MEMORY;
    s->rax=pointer;
    s->rip=l->loop_back_va;
    s->instructions+=3U;
    return MX_GAME_FILENAME_SCAN_REACHED;
}

/* Starts at a verified separator-found original branch or at the original
 * loop header (for an independently verified initial non-separator prefix).
 * Stops BEFORE interpreting either original post-NUL successor.
 */
static inline int mx_game_filename_scan_to_nul(
    mx_crt_cluster_state*s,mx_cfg_memory*m,
    const mx_game_filename_scan_layout*l,
    mx_game_filename_scan_result*out) {
    if(!s||!m||!l||!out||s->fault||
       (s->rip!=l->separator_record_va&&s->rip!=l->loop_back_va)||
       l->max_bytes<1U||l->max_bytes>4096U||
       l->iteration.entry_va!=l->loop_back_va||
       l->iteration.nonzero_destination_va!=l->separators.normal_start_va||
       l->iteration.zero_destination_va!=l->separators.zero_start_va||
       l->separators.normal_taken_va!=l->separator_record_va||
       l->separators.normal_fallthrough_va!=l->slash.start_va||
       l->slash.found_separator_va!=l->separator_record_va||
       l->slash.next_loop_va!=l->loop_back_va||
       l->separators.zero_taken_va!=l->return_without_separator_va||
       l->separators.zero_fallthrough_va!=l->return_with_separator_va)
        return MX_GAME_FILENAME_SCAN_INVALID;
    mx_game_filename_scan_result observed={0};
    /* Count the initial separator if the caller stops at its JE target. */
    if(s->rip==l->separator_record_va){
        if(mx_game_filename_record_separator(s,m,l)!=
                MX_GAME_FILENAME_SCAN_REACHED)
            return MX_GAME_FILENAME_SCAN_MEMORY;
        observed.separator_records++;
    }
    for(uint32_t index=0;index<l->max_bytes;index++){
        mx_game_filename_iteration_result iteration={0};
        if(mx_game_filename_loop_iteration(s,m,
               &l->iteration,&iteration)!=MX_GAME_LOOP_ITERATION_REACHED)
            return MX_GAME_FILENAME_SCAN_MEMORY;
        observed.loop_iterations++;
        if(iteration.zero_branch){
            mx_game_path_separator_result final={0};
            if(mx_game_path_separator_branch(s,m,
                 &l->separators,&final)!=MX_GAME_SEPARATOR_FRONTIER ||
               !final.zero_path)
                return MX_GAME_FILENAME_SCAN_MEMORY;
            observed.terminator=iteration.original_next_pointer;
            if(s->rip!=l->return_with_separator_va &&
               s->rip!=l->return_without_separator_va)
                return MX_GAME_FILENAME_SCAN_UNEXPECTED;
            observed.ended_with_separator=
               (uint8_t)(s->rip==l->return_with_separator_va);
            if(!mx_cfg_transfer(m,s->rsp+0x20U,
                                &observed.last_separator,8U,0))
                return MX_GAME_FILENAME_SCAN_MEMORY;
            *out=observed;
            return MX_GAME_FILENAME_SCAN_REACHED;
        }
        mx_game_path_separator_result separator={0};
        if(mx_game_path_separator_branch(s,m,
             &l->separators,&separator)!=MX_GAME_SEPARATOR_FRONTIER ||
           separator.zero_path)
            return MX_GAME_FILENAME_SCAN_MEMORY;
        if(separator.branch_taken){
            if(mx_game_filename_record_separator(s,m,l)!=
                    MX_GAME_FILENAME_SCAN_REACHED)
                return MX_GAME_FILENAME_SCAN_MEMORY;
            observed.separator_records++;
            continue;
        }
        if(mx_game_slash_loop(s,m,&l->slash)!=MX_GAME_SLASH_LOOP_REACHED)
            return MX_GAME_FILENAME_SCAN_MEMORY;
        if(s->rip==l->separator_record_va){
            if(mx_game_filename_record_separator(s,m,l)!=
                    MX_GAME_FILENAME_SCAN_REACHED)
                return MX_GAME_FILENAME_SCAN_MEMORY;
            observed.separator_records++;
        }else if(s->rip==l->loop_back_va){
            observed.ordinary_characters++;
        }else{
            return MX_GAME_FILENAME_SCAN_UNEXPECTED;
        }
    }
    return MX_GAME_FILENAME_SCAN_LIMIT;
}
#endif
