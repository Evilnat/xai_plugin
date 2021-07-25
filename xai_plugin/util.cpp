
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#include "util.h"

#include <sys/syscall.h>
#include "gccpch.h"
#include "functions.h"

void lv2_copy_from_user(const void* src, uint64_t dst, uint64_t size) 
{
	if (size == 0)
		return;

	const uint8_t* in = (const uint8_t*)src;

	while (size >= sizeof(uint64_t)) 
	{
		pokeq(dst, *(const uint64_t*)in);
		dst += sizeof(uint64_t); in += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) 
	{
		pokeq32(dst, *(const uint32_t*)in);
		dst += sizeof(uint32_t); in += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) 
	{
		pokeq16(dst, *(const uint16_t*)in);
		dst += sizeof(uint16_t); in += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (size > 0) 
	{
		pokeq8(dst, *(const uint8_t*)in);
		size--;
	}
}

void lv2_copy_to_user(uint64_t src, const void* dst, uint64_t size) 
{
	if (size == 0)
		return;

	uint8_t* out = (uint8_t*)dst;

	while (size >= sizeof(uint64_t)) 
	{
		*(uint64_t*)out = peekq(src);
		src += sizeof(uint64_t); out += sizeof(uint64_t);
		size -= sizeof(uint64_t);
	}

	while (size >= sizeof(uint32_t)) 
	{
		*(uint32_t*)out = peekq32(src);
		src += sizeof(uint32_t); out += sizeof(uint32_t);
		size -= sizeof(uint32_t);
	}

	while (size >= sizeof(uint16_t)) 
	{
		*(uint16_t*)out = peekq16(src);
		src += sizeof(uint16_t); out += sizeof(uint16_t);
		size -= sizeof(uint16_t);
	}

	if (size > 0) 
	{
		*(uint8_t*)out = peekq8(src);
		size--;
	}
}

int run_payload(uint64_t arg, uint64_t arg_size) 
{
	system_call_2(SYSCALL_RUN_PAYLOAD, (uint64_t)arg, (uint64_t)arg_size);
	return_to_user_prog(int);
}
