
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#ifndef _HVCALL_H
#define _HVCALL_H

#include "common.h"

#define SYSCALL_HVC_REDIRECTOR_OFFSET SYSCALL_CODE_OFFSET(SYSCALL_HVC_REDIRECTOR)

#define INSTALL_HVSC_REDIRECT(n)																 \
	uint64_t tmp1 = lv2_peek(SYSCALL_HVC_REDIRECTOR_OFFSET);							 		 \
	uint64_t tmp2 = lv2_peek(SYSCALL_HVC_REDIRECTOR_OFFSET + 8);								 \
	uint64_t tmp3 = lv2_peek(SYSCALL_HVC_REDIRECTOR_OFFSET + 16);								 \
	uint64_t tmp4 = lv2_peek(SYSCALL_HVC_REDIRECTOR_OFFSET + 24);								 \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET +  0, 0x7C0802A6F8010010ULL);						 \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET +  8, 0x3960000044000022ULL | ((uint64_t)(n) << 32)); \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET + 16, 0xE80100107C0803A6ULL);					     \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET + 24, 0x4E80002060000000ULL);
	
#define REMOVE_HVSC_REDIRECT()							\
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET, tmp1);	    \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET + 8, tmp2);  \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET + 16, tmp3); \
	lv2_poke(SYSCALL_HVC_REDIRECTOR_OFFSET + 24, tmp4);

#define SYSCALL_HELPER(x) #x
#define SYSCALL(n) "li %%r11, " SYSCALL_HELPER(n) "; sc;"

int lv1_insert_htab_entry(uint64_t htab_id, uint64_t hpte_group, uint64_t hpte_v, uint64_t hpte_r, uint64_t bolted_flag, uint64_t flags, uint64_t * hpte_index, uint64_t * hpte_evicted_v, uint64_t * hpte_evicted_r);
int lv1_write_htab_entry(uint64_t vas_id, uint64_t hpte_index, uint64_t hpte_v, uint64_t hpte_r);
int lv1_allocate_memory(uint64_t size, uint64_t page_size_exp, uint64_t flags, uint64_t * addr, uint64_t * muid);
int lv1_write_virtual_uart( uint64_t port_number, uint64_t buffer, uint64_t bytes, uint64_t *bytes_written );
#endif