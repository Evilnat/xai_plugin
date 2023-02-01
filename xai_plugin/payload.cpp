
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#include <string.h>
#include "payload.h"
#include "payloads.h"
#include "log.h"
#include "functions.h"
#include "common.h"
#include "cex2dex.h"

static uint64_t real_opd_offset = 0;
unsigned char payload[payload_size];

static void lv2_copy_from_user(const void* src, uint64_t dst, uint64_t size) 
{
	if (size == 0)
		return;

	const uint8_t* in = (const uint8_t*)src;

	while (size >= sizeof(uint64_t)) 
	{
		lv2_poke(dst, *(const uint64_t*)in);
		dst += sizeof(uint64_t); in += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) 
	{
		lv2_poke32(dst, *(const uint32_t*)in);
		dst += sizeof(uint32_t); in += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) 
	{
		lv2_poke16(dst, *(const uint16_t*)in);
		dst += sizeof(uint16_t); in += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (size > 0) 
	{
		lv2_poke8(dst, *(const uint8_t*)in);
		size--;
	}
}

int install_payload(void) 
{
	int target = 0;

	if(lv2_peek(CEX_OFFSET) == CEX)
	{
		target = 0;
		memcpy(payload, payload_481C_489C, payload_size);
	}
	else if(lv2_peek(DEX_OFFSET) == DEX)
	{
		target = 1;
		memcpy(payload, payload_481D_489D, payload_size);
	}

	if(payload_size <= 0)
		return -1;

	lv2_copy_from_user(payload, PAYLOAD_OFFSET, payload_size);

	lv2_poke(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
	lv2_poke(PAYLOAD_OPD_OFFSET + 8, (!target) ? TOC_OFFSET : TOC_DEX_OFFSET);

	real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
	lv2_poke(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);

	return 0;
}

int remove_payload(void) 
{
	if (real_opd_offset != 0) 
	{
		lv2_poke(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), real_opd_offset);
		real_opd_offset = 0;
	}

	return 0;
}
