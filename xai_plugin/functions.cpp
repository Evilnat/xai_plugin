#include <stdio.h>
#include <stdlib.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>
#include "functions.h"
#include "gccpch.h"
#include "cobra.h"
#include "log.h"
#include "cfw_settings.h"
#include "common.h"

uint64_t TOC_OFFSET = 0;
uint64_t SYSCALL_TABLE_OFFSET = 0;

int mount_dev_blind()
{
	system_call_8(837, (uint64_t)"CELL_FS_IOS:BUILTIN_FLSH1", (uint64_t)"CELL_FS_FAT", (uint64_t)"/dev_blind", 0, 0, 0, 0, 0);
	return_to_user_prog(int);
}

int umount_devblind()
{
	system_call_1(838, (uint64_t)"/dev_blind");
	return_to_user_prog(int);
}

int lv2_ss_get_cache_of_flash_ext_flag(uint8_t *flag)
{
	system_call_1(874, (uint64_t) flag);
	return_to_user_prog(int);
}

bool check_flash_type()
{
	uint8_t flag;
	lv2_ss_get_cache_of_flash_ext_flag(&flag);
	return !(flag & 0x1);
}

int sys_storage_get_device_info(uint64_t device, device_info_t *device_info)
{
    system_call_2(609, device, (uint64_t) device_info);
    return_to_user_prog(int);
}

int sys_storage_read2(int fd, uint32_t start_sector, uint32_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint32_t flags)
{
    system_call_7(602, fd, 0, start_sector, sectors, (uint64_t) bounce_buf, (uint64_t) sectors_read, flags);
    return_to_user_prog(int);
}

int sys_storage_open(uint64_t id, int *fd)
{
    system_call_4(600, id, 0, (uint64_t) fd, 0);
    return_to_user_prog(int);
}

int sys_storage_close(int fd)
{
    system_call_1(601, fd);
    return_to_user_prog(int);
}

int sys_storage_send_device_command(int device_handle, unsigned int command, void *indata, uint64_t inlen, void *outdata, uint64_t outlen)
{
	system_call_6(SYS_STORAGE_SEND_DEVICE_COMMAND, device_handle, command, (uint64_t)(uint32_t)indata, inlen, (uint64_t)(uint32_t)outdata, outlen);
    return_to_user_prog(int);
}

uint32_t celsius_to_fahrenheit(uint32_t *temp)
{
	*temp = ((uint32_t)(*temp * 9 / 5) + 32);
	return *temp;
}

int sys_game_get_temperature(int sel, uint32_t *temperature) 
{
    uint32_t temp;  
    system_call_2(383, (uint64_t) sel, (uint64_t) &temp);
    *temperature = (temp >> 24);
    return_to_user_prog(int);
}

int sys_sm_get_fan_policy(uint8_t id, uint8_t *st, uint8_t *mode, uint8_t *speed, uint8_t *unknown)
{
	system_call_5(409, (uint64_t) id, (uint64_t)(uint32_t) st, (uint64_t)(uint32_t) mode, (uint64_t)(uint32_t) speed, (uint64_t)(uint32_t) unknown);
	return_to_user_prog(int);
}

void sys_sm_set_fan_policy(uint8_t unknown , uint8_t fan_mode, uint8_t fan_speed)
{
	system_call_3(389, (uint64_t) unknown, (uint64_t) fan_mode, (uint64_t) fan_speed);
}

uint64_t lv1_peek(uint64_t addr)
{
	system_call_1(8, addr);
	return_to_user_prog(uint64_t);
}

void lv1_poke( uint64_t addr, uint64_t val) 
{
	system_call_2(9, addr, val);
}

uint64_t peekq(uint64_t addr)
{
	system_call_1(6, addr);
	return_to_user_prog(uint64_t);
}

uint8_t peekq8(uint64_t address) 
{
	return (peekq(address) >> 56) & 0xFFUL;
}

uint16_t peekq16(uint64_t address) 
{
	return (peekq(address) >> 48) & 0xFFFFUL;
}

uint32_t peekq32(uint64_t address) 
{
	return (peekq(address) >> 32) & 0xFFFFFFFFUL;
}

void pokeq( uint64_t addr, uint64_t val)
{
	system_call_2(7, addr, val);
}

void pokeq8(uint64_t addr, uint8_t value) 
{
	uint64_t old_value = peekq(addr);
	pokeq(addr, ((uint64_t)value << 56) | (old_value & 0xFFFFFFFFFFFFFFULL));
}

void pokeq16(uint64_t addr, uint16_t value) 
{
	uint64_t old_value = peekq(addr);
	pokeq(addr, ((uint64_t)value << 48) | (old_value & 0xFFFFFFFFFFFFULL));
}

void pokeq32(uint64_t address, uint32_t value) 
{
	uint64_t old_value = peekq(address);
	pokeq(address, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
}

int sys_sm_shutdown(uint16_t op)
{ 	
	system_call_3(379, (uint64_t)op, 0, 0);
	return_to_user_prog(int);
}

void xmb_reboot(uint16_t op)
{
	cellFsUnlink("/dev_hdd0/tmp/turnoff");
	sys_sm_shutdown(op);
}

uint32_t GetApplicableVersion(void *data)
{
	system_call_8(863, 0x6011, 1,(uint64_t)data, 0, 0, 0, 0, 0);
	return_to_user_prog(uint32_t);
}

void wait(int sleep_time)
{
	sys_timer_sleep(sleep_time);	
}

int get_cobra_fw_version()
{
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_FW_VERSION);
	return_to_user_prog(int);
}

int sys_ss_get_console_id(void *idps)
{ 	
	system_call_1(870, (uint64_t)idps);
	return_to_user_prog(int);
}

int sys_ss_get_open_psid(void *psid)
{
	system_call_1(872, (uint64_t)psid);
	return_to_user_prog(int);
}

int sys_sm_control_led(uint8_t led_id,uint8_t led_action)
{ 	
	system_call_2(386, (uint64_t)led_id,(uint64_t)led_action);
	return_to_user_prog(int);
}

uint8_t lv2_get_platform_info(uint32_t *version)
{
    system_call_1(387, (uint32_t)version);
	*version = *version >> 12;
	return_to_user_prog(int);
}

int check_kernel()
{
	int type;

	if(peekq32(CEX_OFFSET) == CEX)
		type = 1;
	else if(peekq32(DEX_OFFSET) == DEX)
		type = 2;

	return type;
}

int check_firmware()
{
	uint32_t firmware;
	lv2_get_platform_info(&firmware);

	int kernel = check_kernel();	

	// For 4.81 CEX - 4.88 CEX
	TOC_OFFSET = TOC_OFFSET_CEX;
	SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_CEX;

	// For 4.84 DEX/DREX
	if(firmware == 0x4084 && kernel == 2)	
	{
		TOC_OFFSET = TOC_OFFSET_DEX;
		SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_DEX;
	}
}

int check_syscalls()
{
	if(peekq(SYSCALL_TABLE_OFFSET) == DISABLED)
		return 0;
	
	return 1;
}