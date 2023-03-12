/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Thanks to zecoxao for providing me the SRC
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <cell/fs/cell_fs_file_api.h>
#include "log.h"
#include "functions.h"
#include "cfw_settings.h"

int fd;
char output[120];
static wchar_t wchar_string[120]; // Global variable for swprintf
uint64_t ori_patch1, ori_auth_check, ori_write_eeprom;

// peek and poke dynamically lv1 - no more toc/fw check needed ^_^
uint64_t auth_check = 0x16FB64; // auth_check poke-offset CEX/DEX 4.75
uint64_t write_eeprom = 0xFEBD4; // eeprom_write_access poke-offset CEX/DEX 4.75
uint64_t patch1 = 0xFC4D8;


static void restore_patches()
{
	lv1_poke(patch1, ori_patch1);
	lv1_poke(auth_check, ori_auth_check);
	lv1_poke(write_eeprom, ori_write_eeprom);	
}

static int patch_hv_checks()
{	
	ori_patch1 = lv1_peek(patch1);
	ori_auth_check = lv1_peek(auth_check);
	ori_write_eeprom = lv1_peek(write_eeprom);
	
	lv1_poke(patch1, 0x2F8000032F800003ULL);
	
	if(lv1_peek(auth_check) != 0x2F800000409E0050ULL)
	{ 
		auth_check = 0;

		for(uint64_t addr = 0xA000; addr < 0x800000ULL; addr += 4)
		{
			if(lv1_peek(addr) == 0x4BFFFF8888010070ULL)
			{ 
				auth_check = addr + 8;
				ori_auth_check = lv1_peek(auth_check);
				break;
			}
		}

		if(!auth_check)
			goto error;
	}

	if(auth_check && lv1_peek(auth_check) == 0x2F800000409E0050ULL)
		lv1_poke(auth_check, 0x2F80000048000050ULL);
		
	if(lv1_peek(write_eeprom) != 0xE81800082FA00000ULL)
	{ 
		write_eeprom = 0;
		
		for(uint64_t addr = 0xA000; addr < 0x800000ULL; addr += 4)
		{ 
			if(lv1_peek(addr) == 0x2F8000FF419E0088ULL)
			{ 
				write_eeprom = addr + 28;
				ori_write_eeprom = lv1_peek(write_eeprom);
				break;
			}
		}

		if(!write_eeprom)
			goto error;
	}

	if(write_eeprom && lv1_peek(write_eeprom) == 0xE81800082FA00000ULL)
		lv1_poke(write_eeprom, 0x380000002FA00000ULL);

	return 0;

error:
	restore_patches();

	return 1;
}

static int dump_eeprom_data(uint32_t offset, char *location)
{
	CellFsStat stat;
	char file_path[120];
	int result, i = 0;
	int usb_found = 0;
	uint8_t value;
	uint64_t write;

	sprintf_(file_path, "%s/0x%X.bin", (int)location, offset);	

	if(cellFsOpen(file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)
		return 1;

	cellFsChmod(file_path, 0666);

	log("Dumping %X.bin...\n", (int)offset);

	for(i = offset; i < offset + 0x100; i++)
	{
		result = lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_READ_EEPROM, i, (uint64_t) &value, 0, 0, 0, 0);

		if (result) 	
		{
			log("lv1_ss_update_mgr_if(READ_EPROM) failed (0x%08x)\n", result);
			goto error;
		}

		if(cellFsWrite(fd, &value, 1, &write) != CELL_FS_SUCCEEDED)
			goto error;
	}

	log("DONE\n");
	cellFsClose(fd);

	return 0;

error:
	log("ERROR!\n");
	cellFsClose(fd);
	return 1;
}


int dump_eeprom()
{
	CellFsStat stat;
	uint8_t value;
	char file[120], port[120], location[120];
	int result, i = 0;
	int string, usb_found = 0;

	if(check_syscalls())
	{
		ShowMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}		

	ShowMessage("msg_dump_eeprom_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	

	cellFsMkdir(TMP_FOLDER, 0777);
	sprintf_(location, TMP_FOLDER, NULL);

	// Detecting USB	
	for(int i = 0; i < 127; i++) 
	{
		sprintf_(port, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(port, &stat))
		{
			sprintf_(location, "/dev_usb%03d", i);
			usb_found = 1;
			break;
		}
	}		
 
	if(patch_hv_checks())
		goto error;
	
	if(dump_eeprom_data(0x2F00, location) != CELL_FS_SUCCEEDED)
		goto error;

	if(dump_eeprom_data(0x3000, location) != CELL_FS_SUCCEEDED)
		goto error;

	if(dump_eeprom_data(0x48000, location) != CELL_FS_SUCCEEDED)
		goto error;

	if(dump_eeprom_data(0x48800, location) != CELL_FS_SUCCEEDED)
		goto error;

	if(dump_eeprom_data(0x48C00, location) != CELL_FS_SUCCEEDED)
		goto error;

	if(dump_eeprom_data(0x48D00, location) != CELL_FS_SUCCEEDED)
		goto error;

	restore_patches();			

	buzzer(SINGLE_BEEP);

	string = RetrieveString("msg_dump_eeprom_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)location);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;

error: 
	restore_patches();	

	buzzer(TRIPLE_BEEP);
	ShowMessage("msg_dump_eeprom_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}
