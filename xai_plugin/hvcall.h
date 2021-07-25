
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#ifndef _HVCALL_H
#define _HVCALL_H

#include "common.h"

int lv1_insert_htab_entry(uint64_t htab_id, uint64_t hpte_group, uint64_t hpte_v, uint64_t hpte_r, uint64_t bolted_flag, uint64_t flags, uint64_t* hpte_index, uint64_t* hpte_evicted_v, uint64_t* hpte_evicted_r);
int lv1_write_htab_entry(uint64_t vas_id, uint64_t hpte_index, uint64_t hpte_v, uint64_t hpte_r);

#endif
