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

/*
 *	This file contains data for different versions of FW
 *	It is possible that support for some more may need to be added
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <cell/fs/cell_fs_file_api.h>
#include "eeprom.h"
#include "log.h"
#include "functions.h"
#include "cfw_settings.h"
#include "cex2dex.h"

int fd;
char output[120];
static wchar_t wchar_string[120]; // Global variable for swprintf

static uint64_t auth_check_offset, um_read_eeprom_offset, um_write_eeprom_offset;
static uint64_t um_nspmo_eeprom_offset, scm_read_eeprom_offset, scm_write_eeprom_offset;

// LV1 Patches for read/write EEPROM (Thanks to M4j0R)
static patches_eeprom patch_hv_checks[6] =
{	
	{ 0, 0x48000050ULL, 0x409E0050ULL },
	{ 0, 0x60000000ULL, 0x419D0054ULL },
	{ 0, 0x60000000ULL, 0x419D02B4ULL },
	{ 0, 0x38000000ULL, 0xE8180008ULL },
	{ 0, 0x4800003CULL, 0x409D0074ULL },
	{ 0, 0x4800003CULL, 0x409D0074ULL },
};

uint64_t findValueinLV1(uint64_t min_offset, uint64_t max_offset, uint64_t value)
{
	for(uint64_t offset = min_offset; offset < max_offset; offset += 4)
	{
		if(lv1_peek(offset) == value)
			return offset;
	}

	return 0;
}

static int dump_eeprom_data(uint32_t offset, char *location)
{
	CellFsStat stat;
	char file_path[120];
	int result;
	uint8_t value;
	uint64_t write;

	sprintf_(file_path, "%s/0x%X.bin", (int)location, offset);	

	if(cellFsOpen(file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)
		return 1;

	cellFsChmod(file_path, 0666);

	log("Dumping %X.bin...\n", (int)offset);

	for(int i = offset; i < offset + 0x100; i++)
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

	cellFsClose(fd);

	return 0;

error:
	log("ERROR!\n");
	cellFsClose(fd);
	return 1;
}

static void restoreLV1patches()
{
	for(int i = 0; i <= 5; i++)
		lv1_poke32(patch_hv_checks[i].offset, patch_hv_checks[i].ori);
}

static int makeLV1patches()
{
	char patch_state[120];
	uint64_t ori_value;

	// Search offset in LV1
	auth_check_offset = findValueinLV1(0x150000, 0x180000, 0x4BFFFF8888010070ULL);

	um_read_eeprom_offset = findValueinLV1(0xFB000, 0xFF000, 0x3D29FFFB380973CFULL);
	if(!um_read_eeprom_offset)
		um_read_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x3D29FFFB380973CFULL);

	um_write_eeprom_offset = findValueinLV1(0xFA000, 0xFF000, 0x380973BD3BE00009ULL);
	if(!um_write_eeprom_offset)
		um_write_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x380973BD3BE00009ULL);

	um_nspmo_eeprom_offset = findValueinLV1(0xFA000, 0xFF000, 0x7FC3F3784802D40DULL);
	if(!um_nspmo_eeprom_offset)
		um_nspmo_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x7FC3F3784802D40DULL);

	scm_read_eeprom_offset = findValueinLV1(0xB8000, 0xBB000, 0x4800C955817C0000ULL);
	if(!scm_read_eeprom_offset)
		scm_read_eeprom_offset = findValueinLV1(0x1B0000, 0x1F0000, 0x4800C955817C0000ULL);

	scm_write_eeprom_offset = findValueinLV1(0xB8000, 0xBB000, 0x4800C679817C0000ULL);	
	if(!scm_write_eeprom_offset)
		scm_write_eeprom_offset = findValueinLV1(0x1B0000, 0x1F0000, 0x4800C679817C0000ULL);	

	if(!auth_check_offset || !um_read_eeprom_offset || !um_write_eeprom_offset || 
		!um_nspmo_eeprom_offset || !scm_read_eeprom_offset || !scm_write_eeprom_offset)
		return 1;

	patch_hv_checks[0].offset = auth_check_offset + 0x0C;
	patch_hv_checks[1].offset = um_read_eeprom_offset + 0x4C;
	patch_hv_checks[2].offset = um_write_eeprom_offset + 0x0C;
	patch_hv_checks[3].offset = um_nspmo_eeprom_offset + 8;
	patch_hv_checks[4].offset = scm_read_eeprom_offset + 0x10;
	patch_hv_checks[5].offset = scm_write_eeprom_offset + 0x10;

	for(int i = 0; i <= 5; i++)
	{
		ori_value = lv1_peek32(patch_hv_checks[i].offset);

		sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n", 
			(int)patch_hv_checks[i].offset, (int)ori_value, (int)patch_hv_checks[i].patch);

		log(patch_state);

		lv1_poke32(patch_hv_checks[i].offset, patch_hv_checks[i].patch);
	}

	return 0;
}

int dump_eeprom()
{
	char usb_location[120], location[120];
	int ret;
	int string, usb_port;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}		

	showMessage("msg_dump_eeprom_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	

	cellFsMkdir(TMP_FOLDER, 0777);
	sprintf_(location, TMP_FOLDER, NULL);

	ret = makeLV1patches();

	if(ret != SUCCEEDED)
	{
		log("Error patching LV1\nPlease contact Evilnat to add support for this FW\n");
		goto error;
	}

	// Detecting USB
	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(location, "/dev_usb%03d", usb_port, NULL);		
	
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

	restoreLV1patches();

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(usb_location, "/dev_usb%03d", usb_port);

	buzzer(SINGLE_BEEP);

	string = RetrieveString("msg_dump_eeprom_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(usb_port != -1 ? usb_location : location));
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;

error: 
	if(ret == SUCCEEDED)
		restoreLV1patches();

	buzzer(TRIPLE_BEEP);
	showMessage("msg_dump_eeprom_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}
