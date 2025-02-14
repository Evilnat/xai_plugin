
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#ifndef _HVCALL_H
#define _HVCALL_H

#include "common.h"

#define SYSCALL_HELPER(x) #x
#define SYSCALL(n) "li %%r11, " SYSCALL_HELPER(n) "; sc;"

extern uint64_t OFFSET_HVSC_REDIRECT;

int lv1_insert_htab_entry(uint64_t htab_id, uint64_t hpte_group, uint64_t hpte_v, uint64_t hpte_r, uint64_t bolted_flag, uint64_t flags, uint64_t * hpte_index, uint64_t * hpte_evicted_v, uint64_t * hpte_evicted_r);
int lv1_write_htab_entry(uint64_t vas_id, uint64_t hpte_index, uint64_t hpte_v, uint64_t hpte_r);
int lv1_allocate_memory(uint64_t size, uint64_t page_size_exp, uint64_t flags, uint64_t * addr, uint64_t * muid);
int lv1_write_virtual_uart( uint64_t port_number, uint64_t buffer, uint64_t bytes, uint64_t *bytes_written );
#endif
