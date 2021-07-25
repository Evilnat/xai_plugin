#include <sys/memory.h>
#include "cobra.h"

#define EINVAL (2133571399L)

int check_syscall8()
{
	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_SYSCALL, 8); 
	return_to_user_prog(int);
}

int cobra_read_config(CobraConfig *cfg)
{
	if(!cfg) 
		return EINVAL;

	memset((uint8_t*)cfg, 0, sizeof(CobraConfig));

	cfg->size = sizeof(CobraConfig);
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_READ_COBRA_CONFIG, (uint64_t)(uint32_t)cfg);
	return (int)p1;
}

int cobra_write_config(CobraConfig *cfg)
{
	if(!cfg) 
		return EINVAL;

	cfg->size = sizeof(CobraConfig);
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_WRITE_COBRA_CONFIG, (uint64_t)(uint32_t)cfg);
	return (int)p1;
}

int sys_get_version(uint32_t *version)
{
	system_call_2(8, SYSCALL8_OPCODE_GET_VERSION, (uint64_t)version);
    return_to_user_prog(uint32_t);
}

int sys_get_version2(uint16_t *version)
{
    system_call_2(8, SYSCALL8_OPCODE_GET_VERSION2, (uint32_t)version);
	//system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_COBRA_VERSION, (uint32_t)version);  	
	
    return_to_user_prog(uint16_t);
}

int check_cobra_version()
{		
	uint16_t version;
	sys_get_version2(&version);
	return version;
}
