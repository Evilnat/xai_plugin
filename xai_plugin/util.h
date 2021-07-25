
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include "common.h"

void lv2_copy_from_user(const void* src, uint64_t dst, uint64_t size);
void lv2_copy_to_user(uint64_t src, const void* dst, uint64_t size);

int run_payload(uint64_t arg, uint64_t arg_size);

#endif
