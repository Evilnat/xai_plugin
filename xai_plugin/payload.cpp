
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#include "payload.h"
#include "payloads.h"
#include "log.h"
#include "functions.h"

static uint64_t real_opd_offset = 0;
unsigned char payload[payload_size];

int install_payload(void) 
{
	uint32_t firmware;
	check_firmware(&firmware);

	uint64_t kernel;
	check_kernel(&kernel);

	if(firmware > 0x4080 && kernel == 1)	
		memcpy(payload, payload_481C_488C, payload_size);
	else if(firmware > 0x4080 && kernel == 2)	
		memcpy(payload, payload_481D_488D, payload_size);

	if(payload_size <= 0)
		return -1;

	lv2_copy_from_user(payload, PAYLOAD_OFFSET, payload_size);

	pokeq(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
	pokeq(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET);

	real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
	pokeq(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);

	return 0;
}

int remove_payload(void) 
{
	if (real_opd_offset != 0) 
	{
		pokeq(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), real_opd_offset);
		real_opd_offset = 0;
	}

	return 0;
}
