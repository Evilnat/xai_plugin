#include <stdio.h>
#include <stdlib.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>
#include "functions.h"
#include "gccpch.h"
#include "cobra.h"
#include "log.h"
#include "cfw_settings.h"
#include "otheros.h"

int mount_dev_blind()
{
	system_call_8(837, (uint64_t)"CELL_FS_IOS:BUILTIN_FLSH1", (uint64_t)"CELL_FS_FAT", (uint64_t)DEV_BLIND, 0, 0, 0, 0, 0);
	return_to_user_prog(int);
}

int umount_dev_blind()
{
	system_call_1(838, (uint64_t)DEV_BLIND);
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

int lv2_storage_get_device_info(uint64_t dev_id, struct storage_device_info *info)
{
	system_call_2(609, dev_id, (uint64_t) info);
	return_to_user_prog(int);
}

int lv2_storage_open(uint64_t dev_id, uint32_t *dev_handle)
{
	system_call_4(600, dev_id, 0, (uint64_t) dev_handle, 0);
	return_to_user_prog(int);
}

int lv2_storage_close(uint32_t dev_handle)
{
	system_call_1(601, dev_handle);
	return_to_user_prog(int);
}

int lv2_storage_read(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, const void *buf, uint32_t *unknown2, uint64_t flags)
{
	system_call_7(602, dev_handle, unknown1, start_sector, sector_count, (uint64_t ) buf, (uint64_t) unknown2, flags);
	return_to_user_prog(int);
}

int lv2_storage_write(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, const void *buf, uint32_t *unknown2, uint64_t flags)
{
	system_call_7(603, dev_handle, unknown1, start_sector, sector_count, (uint64_t ) buf, (uint64_t) unknown2, flags);
	return_to_user_prog(int);
}


int sys_storage_get_device_info(uint64_t device, storage_device_info *device_info)
{
    system_call_2(609, device, (uint64_t) device_info);
    return_to_user_prog(int);
}

int sys_storage_get_device_info2(uint64_t device, device_info_t *device_info)
{
    system_call_2(609, device, (uint64_t) device_info);
    return_to_user_prog(int);
}

int sys_storage_open(uint64_t dev_id, int *dev_handle)
{
    system_call_4(600, dev_id, 0, (uint64_t) dev_handle, 0);
    return_to_user_prog(int);
}

int sys_storage_close(int fd)
{
    system_call_1(601, fd);
    return_to_user_prog(int);
}

int sys_storage_read(uint32_t dev_handle, uint64_t start_sector, uint64_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint64_t flags)
{
    system_call_7(602, dev_handle, 0, start_sector, sectors, (uint64_t)bounce_buf, (uint64_t)sectors_read, flags);
    return_to_user_prog(int);
}

int sys_storage_read2(int fd, uint32_t start_sector, uint32_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint32_t flags)
{
    system_call_7(602, fd, 0, start_sector, sectors, (uint64_t) bounce_buf, (uint64_t) sectors_read, flags);
    return_to_user_prog(int);
}

int sys_storage_write(int dev_handle, uint64_t start_sector, uint64_t sector_count, uint8_t *buf, uint32_t *sectors_written, uint64_t flags)
{
	system_call_7(603, dev_handle, 0, start_sector, sector_count, (uint64_t )buf, (uint64_t)sectors_written, flags);
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

// LV1 Peek/Poke
uint64_t lv1_peek(uint64_t addr)
{
	system_call_1(8, addr);
	return_to_user_prog(uint64_t);
}

uint32_t lv1peek32(uint64_t addr) 
{
	return (lv1_peek(addr) >> 32) & 0xFFFFFFFFUL;
}

void lv1_poke(uint64_t addr, uint64_t value) 
{
	system_call_2(9, addr, value);
}

void lv1_poke32(uint64_t addr, uint32_t value)
{
	uint64_t old_value = lv1_peek(addr);
	lv1_poke(addr, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
}

// LV2 Peek/Poke
uint64_t lv2_peek(uint64_t addr)
{
	system_call_1(6, addr);
	return_to_user_prog(uint64_t);
}

uint8_t lv2_peek8(uint64_t addr) 
{
	return (lv2_peek(addr) >> 56) & 0xFFUL;
}

uint16_t lv2_peek16(uint64_t addr) 
{
	return (lv2_peek(addr) >> 48) & 0xFFFFUL;
}

uint32_t lv2_peek32(uint64_t addr) 
{
	return (lv2_peek(addr) >> 32) & 0xFFFFFFFFUL;
}

void lv2_poke(uint64_t addr, uint64_t val)
{
	system_call_2(7, addr, val);
}

void lv2_poke8(uint64_t addr, uint8_t value) 
{
	uint64_t old_value = lv2_peek(addr);
	lv2_poke(addr, ((uint64_t)value << 56) | (old_value & 0xFFFFFFFFFFFFFFULL));
}

void lv2_poke16(uint64_t addr, uint16_t value) 
{
	uint64_t old_value = lv2_peek(addr);
	lv2_poke(addr, ((uint64_t)value << 48) | (old_value & 0xFFFFFFFFFFFFULL));
}

void lv2_poke32(uint64_t address, uint32_t value) 
{
	uint64_t old_value = lv2_peek(address);
	lv2_poke(address, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
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

int check_cobra_and_syscall()
{
	uint16_t cobra_version = check_cobra_version();

	if(check_syscall8() != 0 || cobra_version == 0)
	{
		ShowMessage("msg_cobra_not_supported", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	return 0;
}

int get_cobra_fw_version()
{
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_FW_VERSION);
	return_to_user_prog(int);
}

int sys_ss_appliance_info_manager_get_ps_code(uint8_t *pscode)
{
	system_call_2(867, (uint64_t)0x19004, (uint64_t)pscode);
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

uint8_t check_firmware(uint32_t *version)
{
    system_call_1(387, (uint32_t)version);
	*version = *version >> 12;
	return_to_user_prog(int);
}

int sys_sm_get_system_info(system_info *unknown0)
{
	system_call_1(387, (uint64_t)unknown0);
	return_to_user_prog(int);
}

uint32_t lv2_ss_update_mgr_if(uint32_t packet_id, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
	system_call_7(863, packet_id, arg1, arg2, arg3, arg4, arg5, arg6);
	return_to_user_prog(uint32_t);
}

int sys_sm_request_error_log(uint8_t offset, uint8_t *unknown0, uint32_t *unknown1, uint32_t *unknown2)
{
	system_call_4(390, (uint64_t)offset, (uint64_t)unknown0, (uint64_t)unknown1, (uint64_t)unknown2);
	return_to_user_prog(int);
}

uint32_t sys_sm_request_be_count(uint32_t *status, uint32_t *total_time_in_sec, uint32_t *power_on_counter, uint32_t *power_off_counter)
{
	system_call_4(391, (uint32_t)status, (uint32_t)total_time_in_sec, (uint32_t)power_on_counter, (uint32_t)power_off_counter);
	return_to_user_prog(uint32_t);
}

int sys_sm_get_hw_config(uint8_t *res, uint64_t *hw_config)
{
	system_call_2(393, (uint64_t)res, (uint64_t)hw_config);
	return_to_user_prog(int);	
}

int sys_sm_request_scversion(uint64_t *SoftID, uint64_t *old_PatchID, uint64_t *new_PatchID)
{
	system_call_3(394, (uint64_t)SoftID, (uint64_t)old_PatchID, (uint64_t)new_PatchID);
	return_to_user_prog(int);	
}

int check_syscalls()
{
	if(lv2_peek(SYSCALL_TABLE) == DISABLED)
		return 1;
	
	return 0;
}

void buzzer(uint8_t mode)
{	
	system_call_3(392, 0x1007, 0xA, mode);
}

int check_flash_free_space()
{
	uint64_t total_free, avail_free;
	system_call_3(840, (uint64_t)(uint32_t)DEV_BLIND, (uint64_t)(uint32_t)&total_free, (uint64_t)(uint32_t)&avail_free);
	return avail_free;
}
