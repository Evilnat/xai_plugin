/*
	Imported by Evilnat for xai_plugin from Rebug Toolbox
	With some changes added
	https://github.com/Joonie86/Rebug-Toolbox
*/

#include <stdlib.h>
#include <string.h>
#include <sys/timer.h>
#include <cell/fs/cell_fs_file_api.h>
#include "common.h"
#include "log.h"
#include "functions.h"
#include "cfw_settings.h"
#include "gccpch.h"
#include "qa.h"
#include "erk.h"
#include "cex2dex.h"

static uint8_t eid0_key_seed[] = 
{
	0xAB, 0xCA, 0xAD, 0x17, 0x71, 0xEF, 0xAB, 0xFC,
	0x2B, 0x92, 0x12, 0x76, 0xFA, 0xC2, 0x13, 0x0C, 
	0x37, 0xA6, 0xBE, 0x3F, 0xEF, 0x82, 0xC7, 0x9F, 
	0x3B, 0xA5, 0x73, 0x3F, 0xC3, 0x5A, 0x69, 0x0B, 
	0x08, 0xB3, 0x58, 0xF9, 0x70, 0xFA, 0x16, 0xA3, 
	0xD2, 0xFF, 0xE2, 0x29, 0x9E, 0x84, 0x1E, 0xE4, 
	0xD3, 0xDB, 0x0E, 0x0C, 0x9B, 0xAE, 0xB5, 0x1B, 
	0xC7, 0xDF, 0xF1, 0x04, 0x67, 0x47, 0x2F, 0x85
};

static uint8_t eid0_section_key_seed[] = 
{
	0x2E, 0xD7, 0xCE, 0x8D, 0x1D, 0x55, 0x45, 0x45,
	0x85, 0xBF, 0x6A, 0x32, 0x81, 0xCD, 0x03, 0xAF
};

static uint8_t null_iv[] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Real DEX donor (Thanks to zecoxao)
uint8_t donor_idps[0x10] =
{
	0x00, 0x00, 0x00, 0x01, 0x00, 0x82, 0x00, 0x01, 0x04, 0x00, 0x23, 0xBB, 0x5E, 0xDF, 0x37, 0x05
};

uint8_t donor_data[0x28] =
{
	0x22, 0x61, 0xC8, 0xA5, 0x43, 0x4D, 0x91, 0xF5, 0x76, 0xB5, 0x19, 0x1D, 0xDC, 0xC6, 0x6B, 0x9A, 
	0x26, 0x5F, 0x29, 0xDB, 0xA0, 0xBD, 0xBF, 0x2B, 0x01, 0xEF, 0xD9, 0x5B, 0xAE, 0xC7, 0xF0, 0xCF, 
	0xC1, 0x5E, 0xA4, 0x4B, 0x1F, 0x47, 0x91, 0xC3
};

uint8_t donor_R[0x14] = 
{
	0x9E, 0xE8, 0xE5, 0x62, 0xD0, 0xD1, 0xCE, 0x50, 0xE3, 0x2A, 0x8F, 0x40, 0x2A, 0x51, 0xAC, 0x54, 
	0x8E, 0xDB, 0x8E, 0xD1
};

uint8_t donor_S[0x14] = 
{
	0x2F, 0x43, 0xB2, 0xD3, 0xB9, 0x2A, 0x5A, 0xC6, 0x69, 0x2A, 0x35, 0x24, 0xB8, 0x87, 0x7F, 0x91, 
	0x96, 0x2C, 0xD0, 0x94
};

uint8_t donor_pub[0x28] =
{
	0x94, 0xD1, 0x00, 0xBE, 0x6E, 0x24, 0x99, 0x1D, 0x65, 0xD9, 0x3F, 0x3D, 0xA9, 0x38, 0x85, 0x8C, 
	0xEC, 0x2D, 0x13, 0x30, 0x51, 0xF4, 0x7D, 0xB4, 0x28, 0x7A, 0xC8, 0x66, 0x31, 0x71, 0x9B, 0x31, 
	0x57, 0x3E, 0xF7, 0xCC, 0xE0, 0x71, 0xCA, 0x8A
};

uint8_t donor_enc_priv_key[0x20] = 
{
	0xA1, 0x52, 0xA2, 0x1B, 0x0B, 0xEB, 0x2E, 0x97, 0x58, 0x79, 0xBA, 0x7B, 0x08, 0xA1, 0x48, 0x1A, 
	0x2A, 0x29, 0xC5, 0x78, 0x78, 0x44, 0xCE, 0xFC, 0xFA, 0x13, 0x17, 0x29, 0xD0, 0xE7, 0x99, 0x7D
};

uint8_t donor_omac[0x10] =
{
	0xA0, 0xC8, 0xC5, 0x71, 0x6B, 0xC1, 0xC9, 0xAE, 0x9B, 0x18, 0xB5, 0x51, 0x48, 0x3A, 0xB1, 0xC0
};

uint64_t donor_padding = 0x00;

int true_dex, true_dex_dex_idps;

uint8_t section0_eid0_dec[0xc0];
uint8_t section0_eid0_enc_modded[0xc0];

uint32_t readlen = 0;
uint32_t writelen = 0;

static int indiv_gen(uint8_t *seed0, uint8_t *indiv, uint8_t *erk) 
{
    uint32_t i, rounds = 0x100 / 0x40;
    uint8_t iv[0x10];

    memset(indiv, 0, 0x100);
	
    //Copy seeds.
    if (seed0 != NULL)
        memcpy(indiv, seed0, 0x40);

    //Generate.
    for (i = 0; i < rounds; i++, indiv += 0x40) 
    {
		memcpy(iv, erk + 0x20, ISO_ROOT_IV_SIZE);		
		if(AesCbcCfbEncrypt(indiv, indiv, INDIV_CHUNK_SIZE, erk, KEY_BITS(ISO_ROOT_KEY_SIZE), iv) != SUCCEEDED)
			return 1;
    }		

	return 0;
}

int receive_eid_idps(int eid, uint8_t output[0x10]) 
{
	// 0x00: EID0
	// 0x01: EID5

	int dev_id;
	
	uint64_t disc_size = 0;		
	device_info_t disc_info;

	uint64_t start_flash_sector = 0;
	uint64_t device = FLASH_DEVICE_NOR;
	uint16_t offset = 0;

	if(!eid)
	{
		offset = 0x70;
		start_flash_sector = 0x178;		

		if(!check_flash_type())
		{
			start_flash_sector = 0x204;
			device = FLASH_DEVICE_NAND;
		}
	}
	else
	{
		offset = 0x1D0;
		start_flash_sector = 0x181;		

		if(!check_flash_type())
		{
			start_flash_sector = 0x20D;
			device = FLASH_DEVICE_NAND;
		}
	}

	if(!offset || !start_flash_sector || !device)
		return 1;

	if(sys_storage_open(device, &dev_id))
		return 1;

	if(sys_storage_get_device_info2(device, &disc_info))
		return 1;

	disc_size = disc_info.sector_size * disc_info.total_sectors;
	uint32_t buf_size = disc_info.sector_size*1;
	uint8_t* rb = (unsigned char *) memalign__(128, buf_size);
	memset(rb, 0, buf_size);	

	if(disc_size)
	{
		if(sys_storage_read2(dev_id, start_flash_sector, 1, rb, &readlen, FLASH_FLAGS))
		{
			sys_storage_close(dev_id);
			free__(rb);
			return 1;
		}		
		
		memcpy(output, (void*)&rb[offset], 0x10);	

		if(output[0] != 0x00 && output[1] != 0x00 && output[2] != 0x00 && output[3] != 0x01 && output[4] != 0x00 && output[6] != 0x00)
			return 1;
	}
	
	sys_storage_close(dev_id);
	free__(rb);

	return 0;
}

int getTargetID(int mode)
{
	int dev_id, targetid, string;
	wchar_t wchar_string[120];

	uint8_t idps[IDPS_SIZE];
	uint8_t read_buffer[0x200];	

	uint64_t start_flash_sector = 0x178;
	uint64_t device = FLASH_DEVICE_NOR;

	if(!check_flash_type())
	{
		start_flash_sector = 0x204;
		device = FLASH_DEVICE_NAND;
	}
	
	if(sys_storage_open(device, &dev_id))
		goto error;

	if(sys_storage_read2(dev_id, start_flash_sector, 1, read_buffer, &readlen, FLASH_FLAGS))
		goto error;

	sys_storage_close(dev_id);

	if(mode)
	{
		targetid = read_buffer[0x75];
		free__(read_buffer);
		return targetid;
	}

	if(receive_eid_idps(EID5, idps))
		goto error;

	string = RetrieveString("msg_show_eid_target", (char*)XAI_PLUGIN);	

	swprintf_(wchar_string, 120, (wchar_t*)string, (uint8_t)read_buffer[0x75], 
		(read_buffer[0x75] == 0x82 ? (int)"Debug" : (int)"Retail"), 
		(uint8_t)idps[5], 
		(idps[5] == 0x82 ? (int)"Debug" : (int)"Retail"));

	free__(read_buffer);

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	return 0;

error:
	sys_storage_close(dev_id);
	free__(read_buffer);
	showMessage("msg_show_eid_target_error", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	
	return 1;
}

void get_ps3_info()
{
	CellFsStat stat;

	int dev_id, string;
	wchar_t wchar_string[120];
	char target[120], vsh[120], xmb_plugin[120], sysconf_plugin[120], idps_char[120];
	uint8_t idps0[IDPS_SIZE], idps5[IDPS_SIZE];

	uint8_t platform_info[0x18];	

	if(lv2_peek(CEX_OFFSET) == CEX || lv2_peek(CEX_490_OFFSET) == CEX || lv2_peek(DEX_OFFSET) == CEX)
		strncpy(target, "CEX", 3);
	else if(lv2_peek(DEX_OFFSET) == DEX)
		strncpy(target, "DEX", 3);
	else
		strncpy(target, "???", 3);
		
	if(cellFsStat(VSH_SELF_CD ".dex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(vsh, "CEX", 3);
	else if(cellFsStat(VSH_SELF_CD ".cex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(vsh, "DEX", 3);
	else
		strncpy(vsh, "???", 3);

	if(cellFsStat(XMB_PLUGIN_CD ".dex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(xmb_plugin, "CEX", 3);
	else if(cellFsStat(XMB_PLUGIN_CD ".cex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(xmb_plugin, "DEX", 3);
	else
		strncpy(xmb_plugin, "???", 3);

	if(cellFsStat(SYSCONF_PLUGIN_CD ".dex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(sysconf_plugin, "CEX", 3);
	else if(cellFsStat(SYSCONF_PLUGIN_CD ".cex", &stat) == CELL_FS_SUCCEEDED)
		strncpy(sysconf_plugin, "DEX", 3);
	else
		strncpy(sysconf_plugin, "???", 3);

	system_call_1(387, (uint64_t)platform_info);

	if(receive_eid_idps(EID0, idps0))
		goto error;

	if(receive_eid_idps(EID5, idps5))
		goto error;

	if(memcmp(idps0, idps5, 0x10) == SUCCEEDED)
		strncpy(idps_char, "Original", 8);
	else if(memcmp(idps0, donor_idps, 0x10) == SUCCEEDED)
		strncpy(idps_char, "Real DEX", 8);
	else if(idps0[5] == 0x82 && idps5[5] != 0x82)
		strncpy(idps_char, "Converted", 9);
	else
		strncpy(idps_char, "Patched", 7);

	string = RetrieveString("msg_ps3_information", (char*)XAI_PLUGIN);	

	swprintf_(wchar_string, 240, (wchar_t*)string, platform_info[0], platform_info[1], platform_info[2] >> 4, (int)target, 
		(int)idps_char,
		idps0[5] == 0x82 ? (int)"DEX" : (int)"CEX",
		(int)vsh,
		(int)xmb_plugin,
		(int)sysconf_plugin);	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	return;

error:
	showMessage("msg_ps3_information_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return;
}

static int checkCurrentKernel()
{
	int external_cobra = 2;
	uint8_t idps0[IDPS_SIZE];
	CellFsStat statinfo;	

	// Check if external kernel was loaded to avoid bricks
	for(uint64_t offset = 0xA000; offset < 0x900000; offset = offset + 8)
	{
		// /flh/os/lv2_kernel.self
		if(lv1_peek(offset) == 0x5053335F4C504152ULL && lv1_peek8(offset + 0x20) == 0x2F) // PS3_LPAR | '/'
		{
			if(lv1_peek(offset + 0x20) == 0x2F666C682F6F732FULL &&  
				lv1_peek(offset + 0x28) == 0x6C76325F6B65726EULL && 
				lv1_peek(offset + 0x30) == 0x656C2E73656C6600ULL)
			{
				external_cobra = 1;		
				break;
			}
			// /local_sys0/lv2_kernel.self
			else if(lv1_peek(offset + 0x20) == 0x2F6C6F63616C5F73ULL &&  
				lv1_peek(offset + 0x28) == 0x7973302F6C76325FULL && 
				lv1_peek(offset + 0x30) == 0x6B65726E656C2E73ULL && 
				lv1_peek(offset + 0x38) == 0x656C660000000000ULL)
			{
				external_cobra = 0;
				break;
			}
		}	
	}

	if(!external_cobra) // External Cobra detected
		return 3;

	if(external_cobra == 2) // Unable to find value
		return 0;

	if(lv2_peek(CEX_OFFSET) == CEX && lv2_peek(0x80000000002FCB68ULL) == 0x323032322F30322FULL ||
		lv2_peek(CEX_490_OFFSET) == CEX && lv2_peek(0x80000000002FCB58ULL) == 0x323032322F31322FULL ||
		lv2_peek(CEX_OFFSET) == CEX && lv2_peek(0x80000000002FCB68ULL) == 0x323032332F31322FULL)
	{
		log("checkCurrentKernel(): CEX Kernel detected\n");		
		return 1;
	}
	else if(lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032332F30312FULL || // 2023/01/
			lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032342F30322FULL)   // 2024/02/
	{
		log("checkCurrentKernel(): DEX Kernel detected\n");
		return 2;
	}

	return 0;
}

int dumpFlash()
{
	char file[120];
	char filename[120];
	char usb_file[120];
	char dump_file[120];
	char type[120];
	wchar_t wchar_string[120];

	int result, fd, fd_usb;
	int usb_port = 0;
	int start_sector, sector_count;

	struct storage_device_info info;

	uint8_t platform_info[0x18];
	uint8_t buf[FLASH_SECTOR_SIZE * SECTORS];
	uint8_t *dump = NULL;	
	uint32_t dev_handle, sectors_read = 0;	
	uint64_t flash_device;
	uint64_t seek, seek2;
	uint64_t nr, nrw;	

	CellFsStat statinfo;		

	int offset, max_offset;
	int start_offset, fseek_offset;	
	int final_offset, max_sector;	

	int string = RetrieveString("msg_dumping_flash", (char*)XAI_PLUGIN);			
	
	flash_device = FLASH_DEVICE_NOR;
	strcpy(dump_file, NOR_DUMP);
	strcpy(type, "NOR");		
	final_offset = 0x1000000ULL;
	max_sector = 0x8000;
	start_sector = VFLASH_START_SECTOR;
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)"NOR");	

	// Checking if FLASH is NOR or NAND
	if(!check_flash_type())
	{
		// Check if CFW Syscalls are disabled
		if(checkSyscalls(LV1))
		{
			showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return 1;
		}

		flash_device = FLASH_DEVICE_NAND;
		strcpy(dump_file, NAND_DUMP);
		strcpy(type, "NAND");
		final_offset = 0x10000000ULL;
		max_sector = 0x80000;
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)"NAND");	
	}

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);		
	
	system_call_1(387, (uint64_t)platform_info);
	sprintf_(filename, dump_file, platform_info[0], platform_info[1], platform_info[2] >> 4);	
	sprintf_(file, "/dev_hdd0/tmp/%s", (int)filename, NULL);	
	
	// Open storage device
	if(lv2_storage_open(flash_device, &dev_handle))
		goto done;	

	// Getting storage info
	if (lv2_storage_get_device_info(flash_device, &info))
		goto done;

	// Creating file in dev_hdd0
	if(cellFsOpen(file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)		
		goto done;	

	cellFsChmod(file, 0666);

	// NAND
	if(max_sector == 0x80000)
		cellFsLseek(fd, 0x40000, SEEK_SET, &seek);		

	sector_count = info.capacity;

	while (sector_count >= SECTORS) 
	{
		if(lv2_storage_read(dev_handle, 0, start_sector, SECTORS, buf, &sectors_read, FLASH_FLAGS))
			goto done;	

		if(cellFsWrite(fd, buf, SECTORS * FLASH_SECTOR_SIZE, &nrw) != CELL_FS_SUCCEEDED)
			goto done;	

		start_sector += SECTORS;
		sector_count -= SECTORS;
	}

	// NAND
	if(max_sector == 0x80000)
	{
		uint64_t current_offset = 0;

		// Dumping sysrom on NAND		
		for(uint64_t offset = DUMP_OFFSET; offset < DUMP_OFFSET + DUMP_SIZE; offset += 8) 
		{			
			uint64_t val = lv1_peek(offset);			 
	
			cellFsLseek(fd, current_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, &val, 8, &nrw) != CELL_FS_SUCCEEDED)
				goto done;				

			cellFsLseek(fd, 0xF000000 + current_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, &val, 8, &nrw) != CELL_FS_SUCCEEDED)			
				goto done;				

			current_offset += 8;
		}

		uint64_t blank = 0xFFFFFFFFFFFFFFFFULL;		

		// Unknown/FF-region		
		cellFsLseek(fd, 0xEFC0000, SEEK_SET, &seek);

		for(int i = 0; i < 0x40000; i += 8)
		{
			if(cellFsWrite(fd, &blank, 8, &nrw) != CELL_FS_SUCCEEDED)			
				goto done;			
		}

		// Unreferenced area		
		cellFsLseek(fd, 0xF040000, SEEK_SET, &seek);

		for(int i = 0; i < 0xFC0000; i += 8)
		{
			if(cellFsWrite(fd, &blank, 8, &nrw) != CELL_FS_SUCCEEDED)
				goto done;	
		}
	}

	// Copy to USB if is detected
	usb_port = get_usb_device();

	if(usb_port != -1)
	{
		offset = 0;
		max_offset = 0x40000;

		fseek_offset = 0;	
		start_offset = 0;

		sprintf_(usb_file, "/dev_usb%03d/%s", usb_port, (int)filename);

		if(cellFsOpen(usb_file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd_usb, 0, 0) != CELL_FS_SUCCEEDED)		
			goto done;		

		cellFsChmod(usb_file, 0666);

		dump = (uint8_t *)malloc__(0x40000);

		if(!dump)
			goto done;

		memset(dump, 0, 0x40000);

		for(uint64_t offset = 0; offset < max_offset; offset += 8)
		{
			cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
			cellFsLseek(fd_usb, fseek_offset, SEEK_SET, &seek2);

			if(cellFsRead(fd, dump, 0x40000, &nr) != CELL_FS_SUCCEEDED)
			{
				free__(dump);				
				goto done;
			}

			if(cellFsWrite(fd_usb, dump, 0x40000, &nrw) != SUCCEEDED)
			{
				free__(dump);				
				goto done;
			}

			// Done dumping
			if(max_offset == final_offset)
				break;

			fseek_offset += 0x40000;
			start_offset = start_offset + 0x40000;
			max_offset = max_offset + 0x40000;		

			memset(dump, 0, 0x40000);
		}

		free__(dump);
		cellFsClose(fd_usb);
		cellFsUnlink(file);
	}

	cellFsClose(fd);
	lv2_storage_close(dev_handle);

	string = RetrieveString("msg_dump_flash_ok", (char*)XAI_PLUGIN);

	if(usb_port != -1)
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)type, (int)usb_file);	
	else
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)type, (int)file);	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			
	
	buzzer(SINGLE_BEEP);

	return 0;

done:
	cellFsClose(fd);
	cellFsClose(fd_usb);
	lv2_storage_close(dev_handle);

	if(cellFsStat(file, &statinfo) == CELL_FS_SUCCEEDED)
		cellFsUnlink(file);

	if(cellFsStat(usb_file, &statinfo) == CELL_FS_SUCCEEDED)
		cellFsUnlink(usb_file);

	string = RetrieveString("msg_dumpFlash_error", (char*)XAI_PLUGIN);
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)type);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);		

	buzzer(TRIPLE_BEEP);

	return 1;
}

static int setFlashKernelData(uint8_t _mode) 
{
	// 0 = CEX -> DEX
	// 1 = DEX -> CEX

	const char *msg, *result;
	int dev_id, rr, string;
	uint64_t start_flash_sector = 0x3E00;
	uint32_t readlen = 0;
	uint64_t disc_size = 0;
	device_info_t disc_info;

	uint64_t device = FLASH_DEVICE_NAND;

	if(check_flash_type()) 
		device = FLASH_DEVICE_NOR;

	rr = sys_storage_open(device, &dev_id);

	if(!rr) 
		rr = sys_storage_get_device_info2(device, &disc_info);

	disc_size = disc_info.sector_size * disc_info.total_sectors;

	uint32_t buf_size = disc_info.sector_size * 3;
	uint8_t* read_buffer = (unsigned char *) memalign__(128, buf_size);
	uint8_t found = 0, found_ported_dex = 0, found_retail = 0;
	uint8_t ros = 0;

	if(disc_size && !rr)
	{
		for(uint8_t m = 0; m < 2; m++)
		{
			found = 0;
			found_ported_dex = 0;
			found_retail = 0;

			if(m == 0)
			{
				start_flash_sector = 0x600;

				if(!check_flash_type()) 
					start_flash_sector = 0x400;
			}
			else if(m == 1)
			{
				start_flash_sector = 0x3E00;

				if(!check_flash_type()) 
					start_flash_sector = 0x3C00;
			}
			else 
				break;

			rr = sys_storage_read2(dev_id, start_flash_sector, 3, read_buffer, &readlen, FLASH_FLAGS);

			if(readlen == 3 && !rr)
			{
				for(uint32_t n = 0; n < (readlen * disc_info.sector_size) - 8; n += 8)
				{
					if( read_buffer[n + 0] == 'l' &&
						read_buffer[n + 1] == 'v' &&
						read_buffer[n + 2] == '2' &&
						read_buffer[n + 7] == 'n')
					{
						if(read_buffer[n + 3] == 'P') 
							found_ported_dex = 1;
						if(read_buffer[n + 3] == 'R') 
							found_retail = 1;
					}
				}

				if((found_retail && found_ported_dex) || (!found_ported_dex && !found_retail))
				{
					found = 0;
					continue;
				}

				for(uint32_t n = 0; n < (readlen * disc_info.sector_size) - 8; n += 8)
				{
					if(!_mode && found_ported_dex) // CEX -> DEX
					{						
						//lv2_kernel.self => lv2Rkernel.self
						//lv2Pkernel.self => lv2_kernel.self		
						if( read_buffer[n + 0]== 'l' && 
							read_buffer[n + 2]== '2' &&
							read_buffer[n + 3]== '_' && 
							read_buffer[n + 7]== 'n')
						{
							read_buffer[n + 3] = 'R';
							found++;
							n += 8;
						}

						if( read_buffer[n + 0]== 'l' &&
							read_buffer[n + 2]== '2' &&
							read_buffer[n + 3]== 'P' &&
							read_buffer[n + 7]== 'n'
							)
						{
							read_buffer[n + 3] = '_';
							found++;
							n += 8;
						}
					}
					else if(_mode && found_retail) // DEX -> CEX
					{						
						//lv2_kernel.self => lv2Pkernel.self
						//lv2Rkernel.self => lv2_kernel.self
						if( read_buffer[n + 0] == 'l' &&
							read_buffer[n + 2] == '2' &&
							read_buffer[n + 3] == '_' &&
							read_buffer[n + 7] == 'n')
						{
							read_buffer[n + 3] = 'P';
							found++;
							n += 8;
						}

						if( read_buffer[n + 0] == 'l' &&
							read_buffer[n + 2] == '2' &&
							read_buffer[n + 3] == 'R' &&
							read_buffer[n + 7] == 'n')
						{
							read_buffer[n + 3] = '_';
							found++;
							n += 8;
						}
					}
					
					if(found == 2) 
						break;
				}
			}

			if(found == 2)
			{
				log("Replacing sector in flash at 0x%X\n", (int)start_flash_sector * 0x200);

				rr = sys_storage_write(dev_id, start_flash_sector, 3, read_buffer, &readlen, FLASH_FLAGS);

				if(readlen == 3 && !rr)
					ros++;
			}
		}

		if(ros)
			return 0;
		else
			return 1;
	}

	sys_storage_close(dev_id);
	free__(read_buffer);

	return 1;
}

void cex2dex(int mode)
{
	// 0 = CEX
	// 1 = DEX

	int dev_id, targetID, ret;	
	int file_found = 0, usb_port;
	char file[120];

	uint8_t idps0[IDPS_SIZE], idps[IDPS_SIZE];
	uint8_t indiv[0x100];
	uint8_t key[0x10];	
	uint8_t read_buffer[0x200], backup_buffer[0x200];
	uint8_t eid_root_key[EID_ROOT_KEY_SIZE];

	uint64_t start_flash_sector;
	uint64_t device;

	CellFsStat statinfo;	

	close_xml_list();

	sys_timer_usleep(10000);

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2) || checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}
	
	if(receive_eid_idps(EID0, idps0))
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(memcmp(idps0, donor_idps, 0x10) == SUCCEEDED)
	{
		showMessage("msg_sup_dex_not_available", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return;
	}

	// Search eid_root_key
	usb_port = get_usb_device();

	sprintf_(file, "/dev_usb%03d/eid_root_key", usb_port);

	if(cellFsStat(file, &statinfo) != CELL_FS_SUCCEEDED)
	{
		if(!cellFsStat(EID_ROOT_KEY_HDD0, &statinfo))
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		else
		{
			// Dump ERK
			int dumped = 1;
			showMessage("msg_dumping_erk", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			dumped = dump_eid_root_key(eid_root_key);

			if(dumped)
			{
				showMessage("msg_dump_erk_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
				return;
			}

			saveFile(EID_ROOT_KEY_HDD0, eid_root_key, EID_ROOT_KEY_SIZE);
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		}		
	}	
	
	if(receive_eid_idps(EID5, idps))
		goto done;

	if(readfile(file, eid_root_key, EID_ROOT_KEY_SIZE))
		goto done;

	if(indiv_gen(eid0_key_seed, indiv, eid_root_key) != SUCCEEDED)
		goto done;

	if(AesCbcCfbEncrypt(key, eid0_section_key_seed, 0x10, indiv + 0x20, 0x100, null_iv) != SUCCEEDED)
		goto done;

	start_flash_sector = 0x178;
	device = FLASH_DEVICE_NOR;

	if(!check_flash_type())
	{
		start_flash_sector = 0x204;
		device = FLASH_DEVICE_NAND;
	}	

	if(!start_flash_sector || !device)
		goto done;
	
	if(sys_storage_open(device, &dev_id))
		goto done;

	if(sys_storage_read2(dev_id, start_flash_sector, 1, read_buffer, &readlen, FLASH_FLAGS))
		goto done;

	// Creating backup of original flash data
	memcpy(backup_buffer, read_buffer, 0x200);

	// Checking if partial IDPS from flash is valid
	if(read_buffer[0x70] != 0x00 || read_buffer[0x71] != 0x00 || read_buffer[0x72] != 0x00 || 
		read_buffer[0x73] != 0x01 || read_buffer[0x74] != 0x00 || read_buffer[0x76] != 0x00)
	{
		sys_storage_close(dev_id);
		goto done;
	}

	if(idps[0x00] != 0x00 || idps[0x01] != 0x00 || idps[0x02] != 0x00 || 
		idps[0x03] != 0x01 || idps[0x04] != 0x00 || idps[0x06] != 0x00)
	{
		sys_storage_close(dev_id);
		goto done;
	}	

	if(mode)
	{
		// DEX TargetID is already set
		if(read_buffer[0x75] == 0x82)
		{			
			showMessage("msg_convert_already_dex", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			return;
		}

		read_buffer[0x75] = 0x82;
	}
	else
	{
		// CEX TargetID is already set
		if(read_buffer[0x75] != 0x82)
		{			
			showMessage("msg_convert_already_cex", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			return;
		}

		if(idps[0x5] == 0x82)
			true_dex = 1;
		else
			true_dex = 0;

		if((read_buffer[0x75] == 0x82) && (!true_dex))
			read_buffer[0x75] = idps[0x5];
		else if((read_buffer[0x75] == 0x82) && (true_dex))
		{
			read_buffer[0x75] = 0x84;
			true_dex_dex_idps = 1;
		}
	}
	showMessage("msg_swap_kernel_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	ret = checkCurrentKernel();

	if(!ret)
	{
		log("Unable to get current kernel, aborting...\n");
		goto done;
	}
	else if(ret == 3)
	{
		log("Detected external kernel, aborting...\n");
		showMessage("msg_swap_kernel_cannot", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		goto done;
	}

	uint8_t indiv_clone[0x40];
	memcpy(indiv_clone, indiv, 0x40);

	if(AesCbcCfbDecrypt(section0_eid0_dec, read_buffer + 0x90, 0xC0, key, 0x80, indiv_clone + 0x10) != SUCCEEDED)
		goto done;

	uint8_t omac_verify[0x10];
	aes_omac1(omac_verify, section0_eid0_dec, 0xa8, key, 128);

	uint8_t digest_default[0x10];
	digest_default[0x00] = section0_eid0_dec[0xa8];
	digest_default[0x01] = section0_eid0_dec[0xa9];
	digest_default[0x02] = section0_eid0_dec[0xaa];
	digest_default[0x03] = section0_eid0_dec[0xab];
	digest_default[0x04] = section0_eid0_dec[0xac];
	digest_default[0x05] = section0_eid0_dec[0xad];

	// Checking digest
	if(omac_verify[0x00] != digest_default[0x00] || omac_verify[0x01] != digest_default[0x01] ||
		omac_verify[0x02] != digest_default[0x02] || omac_verify[0x03] != digest_default[0x03] ||
		omac_verify[0x04] != digest_default[0x04] || omac_verify[0x05] != digest_default[0x05])	
			goto done;	

	if(mode)
		section0_eid0_dec[0x5] = 0x82;
	else
	{
		if((section0_eid0_dec[0x5] == 0x82) && (!true_dex))
			section0_eid0_dec[0x5] = idps[0x5];
		else if(true_dex && true_dex_dex_idps)
			section0_eid0_dec[0x5] = 0x84;
	}

	// Checking if it is the same TargetID avoiding brick
	if(read_buffer[0x75] != section0_eid0_dec[0x5])
		goto done;

	uint8_t digest[0x10];
	aes_omac1(digest, section0_eid0_dec, 0xa8, key, 128);

	memcpy(section0_eid0_dec + 0xa8, digest, 0x10);

	if(AesCbcCfbEncrypt(section0_eid0_enc_modded, section0_eid0_dec, 0xC0, key, 0x80, indiv + 0x10) != SUCCEEDED)
		goto done;

	memcpy(read_buffer + 0x90, section0_eid0_enc_modded, 0xc0);

	if(sys_storage_write(dev_id, start_flash_sector, 1, read_buffer, &writelen, FLASH_FLAGS))
		goto done;

	targetID = getTargetID(1);

	if(targetID != 0x82)
	{
		ret = checkCurrentKernel();

		if(ret == 2)
		{
			log("Found CEX TargetID, swapping kernel to CEX...\n");

			if(setFlashKernelData(DEX_TO_CEX) != 0)
			{
				log("Error while swapping DEX kernel, restoring flash IDPS...\n");
				sys_storage_write(dev_id, start_flash_sector, 1, backup_buffer, &writelen, FLASH_FLAGS);
				goto done;
			}
		}
	}

	sys_storage_close(dev_id);

	cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);	

	if(mode)
	{
		if(!cellFsStat(XMB_SPRX_DEX, &statinfo) && cellFsStat(XMB_SPRX_CEX, &statinfo))
		{
			log("Setting DEX xmb_plugin.sprx...\n");

			if(!cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_CEX))
				cellFsRename(XMB_SPRX_DEX, XMB_SPRX_DEFAULT);
		}

		if(!cellFsStat(SOFTWARE_UPDATE_SPRX_DEX, &statinfo) && cellFsStat(SOFTWARE_UPDATE_SPRX_CEX, &statinfo))
		{
			log("Setting DEX software_update_plugin.sprx...\n");

			if(!cellFsRename(SOFTWARE_UPDATE_SPRX_DEFAULT, SOFTWARE_UPDATE_SPRX_CEX))
				cellFsRename(SOFTWARE_UPDATE_SPRX_DEX, SOFTWARE_UPDATE_SPRX_DEFAULT);
		}

		showMessage("msg_convert_dex_done", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	
	}
	else
	{
		if(!cellFsStat(XMB_SPRX_CEX, &statinfo) && cellFsStat(XMB_SPRX_DEX, &statinfo))
		{
			log("Setting CEX xmb_plugin.sprx...\n");

			if(!cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_DEX))
				cellFsRename(XMB_SPRX_CEX, XMB_SPRX_DEFAULT);
		}

		if(!cellFsStat(SOFTWARE_UPDATE_SPRX_CEX, &statinfo) && cellFsStat(SOFTWARE_UPDATE_SPRX_DEX, &statinfo))
		{
			log("Setting CEX software_update_plugin.sprx...\n");

			if(!cellFsRename(SOFTWARE_UPDATE_SPRX_DEFAULT, SOFTWARE_UPDATE_SPRX_DEX))
				cellFsRename(SOFTWARE_UPDATE_SPRX_CEX, SOFTWARE_UPDATE_SPRX_DEFAULT);
		}

		showMessage("msg_convert_cex_done", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	cellFsUtilUnMount(DEV_BLIND, 0);
	sys_timer_usleep(10000);

	wait(3);
	rebootXMB(SYS_SOFT_REBOOT);

	return;

done:
	sys_storage_close(dev_id);
	showMessage("msg_convert_cex_dex_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	sys_timer_usleep(10000);

	return;
}

void swapKernel()
{
	int external_cobra = 0;
	uint8_t idps0[IDPS_SIZE];
	CellFsStat statinfo;
	close_xml_list();

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(receive_eid_idps(EID0, idps0))
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(memcmp(idps0, donor_idps, 0x10) == SUCCEEDED)
	{
		showMessage("msg_sup_dex_not_available", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return;
	}

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2) || checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int targetID = getTargetID(1);

	if(targetID == 0x82)
	{
		showMessage("msg_swap_kernel_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

		// Check if external kernel was loaded to avoid bricks
		for(uint64_t offset = 0xA000; offset < 0x900000; offset = offset + 8)
		{
			// /flh/os/lv2_kernel.self
			if(lv1_peek(offset) == 0x5053335F4C504152ULL && lv1_peek8(offset + 0x20) == 0x2F) // PS3_LPAR | '/'
			{
				if(lv1_peek(offset + 0x20) == 0x2F666C682F6F732FULL &&  
					lv1_peek(offset + 0x28) == 0x6C76325F6B65726EULL && 
					lv1_peek(offset + 0x30) == 0x656C2E73656C6600ULL)
				{
					external_cobra = 1;		
					break;
				}
				// /local_sys0/lv2_kernel.self
				else if(lv1_peek(offset + 0x20) == 0x2F6C6F63616C5F73ULL &&  
					lv1_peek(offset + 0x28) == 0x7973302F6C76325FULL && 
					lv1_peek(offset + 0x30) == 0x6B65726E656C2E73ULL && 
					lv1_peek(offset + 0x38) == 0x656C660000000000ULL)
				{
					external_cobra = 0;
					break;
				}
			}
		}

		if(!external_cobra)
		{
			showMessage("msg_swap_kernel_cannot", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return;
		}

		if(lv2_peek(CEX_OFFSET) == CEX && lv2_peek(0x80000000002FCB68ULL) == 0x323032322F30322FULL ||
			lv2_peek(CEX_490_OFFSET) == CEX && lv2_peek(0x80000000002FCB58ULL) == 0x323032322F31322FULL ||
			lv2_peek(CEX_OFFSET) == CEX && lv2_peek(0x80000000002FCB68ULL) == 0x323032332F31322FULL)
		{
			log("CEX detected, swapping to DEX...\n");

			if(!setFlashKernelData(CEX_TO_DEX))	
			{
				cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

				if(!cellFsStat(VSH_SELF_DEX, &statinfo) && cellFsStat(VSH_SELF_CEX, &statinfo))
				{
					log("Setting DEX vsh.self...\n");

					if(!cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_CEX))
						cellFsRename(VSH_SELF_DEX, VSH_SELF_DEFAULT);
				}

				cellFsUtilUnMount(DEV_BLIND, 0);

				showMessage("msg_swap_kernel_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);		
				wait(3);
				rebootXMB(SYS_SOFT_REBOOT);
			}
			else
				showMessage("msg_swap_kernel_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		}
		else if(lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032332F30312FULL || // 2023/01/
				lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032342F30322FULL)   // 2024/02/
		{
			log("DEX detected, swapping to CEX...\n");

			if(!setFlashKernelData(DEX_TO_CEX))
			{
				showMessage("msg_swap_kernel_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
				wait(3);
				rebootXMB(SYS_SOFT_REBOOT);
			}
			else
				showMessage("msg_swap_kernel_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		}
		else
			showMessage("msg_swap_kernel_unknown", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
	}
	else
		showMessage("msg_swap_kernel_dex_needed", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

int spoof_with_eid5()
{
	uint64_t current_idps[2];
	uint8_t idps[IDPS_SIZE];
	uint64_t start_offset = 0x80000000003D0000ULL;
	uint64_t end_offset = 0x8000000000500000ULL;	
	wchar_t wchar_string[120];
	int done = 0;

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
	int ret = sys_ss_get_console_id(current_idps);

	if(ret == EPERM)
		ret = GetIDPS(current_idps);

	if(ret != CELL_OK)
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}	

	if(receive_eid_idps(EID5, idps))
		return 1;

	for(uint64_t offset = start_offset; offset < end_offset; offset += 4)
	{
		if(lv2_peek(offset) == current_idps[0] && lv2_peek(offset + 8) == current_idps[1])
		{			
			lv2_poke8(offset + 5, idps[5]);

			// Checking if patches are done
			if(lv2_peek8(offset + 5) != idps[5])
			{
				showMessage("msg_spoof_target_id_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return 1;
			}

			done++;
		}
	}

	if(done < 2)
	{
		showMessage("msg_spoof_target_id_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	int string = RetrieveString("msg_spoof_target_id_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)idps[5]);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;
}

int toggle_xmbplugin()
{
	CellFsStat stat;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(!cellFsStat(XMB_SPRX_DEX, &stat) && cellFsStat(XMB_SPRX_CEX, &stat))
	{
		cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_CEX);
		cellFsRename(XMB_SPRX_DEX, XMB_SPRX_DEFAULT);
		showMessage("msg_toggle_xmbplugin_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(XMB_SPRX_CEX, &stat) && cellFsStat(XMB_SPRX_DEX, &stat))
	{
		cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_DEX);
		cellFsRename(XMB_SPRX_CEX, XMB_SPRX_DEFAULT);
		showMessage("msg_toggle_xmbplugin_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		showMessage("msg_toggle_xmbplugin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

int toggle_vsh()
{
	CellFsStat stat;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(getTargetID(1) == 0x82 && lv2_peek(DEX_OFFSET) == DEX && 
		(lv2_peek(0x800000000031F028ULL) == 0x323032332F30312FULL || lv2_peek(0x800000000031F028ULL) == 0x323032332F30332FULL || lv2_peek(0x800000000031F028ULL) == 0x323032342F30322FULL))
	{
		showMessage("msg_toggle_vsh_canceled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return 1;
	}

	if(!cellFsStat(VSH_SELF_DEX, &stat) && cellFsStat(VSH_SELF_CEX, &stat))
	{
		cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_CEX);
		cellFsRename(VSH_SELF_DEX, VSH_SELF_DEFAULT);
		showMessage("msg_toggle_vsh_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(VSH_SELF_CEX, &stat) && cellFsStat(VSH_SELF_DEX, &stat))
	{
		cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_DEX);
		cellFsRename(VSH_SELF_CEX, VSH_SELF_DEFAULT);
		showMessage("msg_toggle_vsh_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		showMessage("msg_toggle_vsh_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

int toggle_sysconf()
{
	CellFsStat stat;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(!cellFsStat(SYSCONF_SPRX_DEX, &stat) && cellFsStat(SYSCONF_SPRX_CEX, &stat))
	{
		cellFsRename(SYSCONF_SPRX_DEFAULT, SYSCONF_SPRX_CEX);
		cellFsRename(SYSCONF_SPRX_DEX, SYSCONF_SPRX_DEFAULT);
		showMessage("msg_toggle_sysconf_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(SYSCONF_SPRX_CEX, &stat) && cellFsStat(SYSCONF_SPRX_DEX, &stat))
	{
		cellFsRename(SYSCONF_SPRX_DEFAULT, SYSCONF_SPRX_DEX);
		cellFsRename(SYSCONF_SPRX_CEX, SYSCONF_SPRX_DEFAULT);
		showMessage("msg_toggle_sysconf_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		showMessage("msg_toggle_sysconf_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

int enable_dex_support()
{
	char file[120], eid0_backup[120];
	int usb_port, dev_id, ret;

	CellFsStat statinfo;

	uint8_t iv[0x10];
	uint8_t eid_keyset[0x40];			

	uint8_t eid_key[0x28];
	uint8_t eid_iv[0x14];
	uint8_t eid_section_key[0x10];

	uint64_t start_flash_sector = 0x178;
	uint64_t device = FLASH_DEVICE_NOR;	

	uint8_t eid_buffer[0x200], eid_backup[0x200];
	uint8_t eid_root_key[EID_ROOT_KEY_SIZE];
	uint8_t cmac_hash[0x10];
	uint8_t donor_buf[0xC0];
	uint8_t encrypted_donor_buf[0xC0];
	uint8_t idps_eid0[0x10], idps_eid5[0x10];

	close_xml_list();

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2) || checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(receive_eid_idps(EID0, idps_eid0) || receive_eid_idps(EID5, idps_eid5))
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}	

	if(idps_eid5[7] > 0x0B)
	{
		showMessage("msg_sup_dex_incompatible", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	
		return 1;
	}

	if(idps_eid0[5] == 0x82 && memcmp(idps_eid0, donor_idps, 0x10))
	{
		showMessage("msg_sup_dex_cex_needed", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return 1;
	}

	// Search eid_root_key
	usb_port = get_usb_device();	
	
	sprintf_(file, "/dev_usb%03d/eid_root_key", usb_port);
	if(cellFsStat(file, &statinfo) != CELL_FS_SUCCEEDED)
	{
		if(cellFsStat(EID_ROOT_KEY_HDD0, &statinfo) == CELL_FS_SUCCEEDED)
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		else
		{
			// Dump ERK
			int dumped = 1;
			showMessage("msg_dumping_erk", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			dumped = dump_eid_root_key(eid_root_key);

			if(dumped)
			{
				showMessage("msg_dump_erk_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
				return 1;
			}

			saveFile(EID_ROOT_KEY_HDD0, eid_root_key, EID_ROOT_KEY_SIZE);
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		}	
	}

	// Read eid_root_key
	if(readfile(file, eid_root_key, EID_ROOT_KEY_SIZE) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_erk_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		log("Unable to read eid_root_key file\n");
		goto error;
	}

	memcpy(iv, eid_root_key + 0x20, ISO_ROOT_IV_SIZE);			

	if(AesCbcCfbEncrypt(eid_keyset, eid0_key_seed, 0x40, eid_root_key, 0x100, iv) != SUCCEEDED)
	{
		log("Unable to encrypt eid_keyset\n");
		goto error;
	}

	memcpy(eid_key, eid_keyset + 0x20, 0x20);
	memcpy(eid_iv, eid_keyset + 0x10, 0x10);	

	if(AesCbcCfbEncrypt(eid_section_key, eid0_section_key_seed, 0x10, eid_key, 0x100, null_iv) != SUCCEEDED)
	{
		log("Unable to encrypt eid_section_key\n");
		goto error;	
	}

	if(!check_flash_type())
	{
		start_flash_sector = 0x204;
		device = FLASH_DEVICE_NAND;
	}	

	if(!start_flash_sector || !device)
	{
		log("Empty address or device\n");
		goto error;
	}
	
	if(sys_storage_open(device, &dev_id))
	{
		log("Unable to open storage device\n");
		goto error;
	}

	if(sys_storage_read2(dev_id, start_flash_sector, 1, eid_buffer, &readlen, FLASH_FLAGS))
	{
		log("Unable to read flash storage\n");
		goto error;
	}

	// Creating backup of original EID0 data
	memcpy(eid_backup, eid_buffer, 0x200);

	if(!memcmp(eid_buffer + 0x70, donor_idps, 0x10))		
	{
		sys_storage_close(dev_id);
		showMessage("msg_sup_dex_already_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return 1;
	}

	showMessage("msg_swap_kernel_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	ret = checkCurrentKernel();

	if(!ret)
	{
		log("Unable to get current kernel, aborting...\n");
		goto error;
	}
	else if(ret == 3)
	{
		log("Detected external kernel, aborting...\n");
		showMessage("msg_swap_kernel_cannot", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		goto error;
	}

	// Checking if partial IDPS is valid
	// TargetID must not be 0x82
	if(eid_buffer[0x70] != 0x00 || eid_buffer[0x71] != 0x00 || eid_buffer[0x72] != 0x00 || 
		eid_buffer[0x73] != 0x01 || eid_buffer[0x74] != 0x00 || eid_buffer[0x75] == 0x82)
	{
		showMessage("msg_idps_not_valid", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	sprintf_(eid0_backup, EID0_BACKUP, usb_port);
	
	// Makes 2nd backup on /dev_hdd0/tmp in case it was necessary
	if(cellFsStat(EID0_BACKUP_TMP, &statinfo) != CELL_FS_SUCCEEDED)
		saveFile(EID0_BACKUP_TMP, eid_buffer, 0x200);

	if(saveFile(eid0_backup, eid_buffer, 0x200) != CELL_FS_SUCCEEDED)
	{
		log("Unable to make a backup of EID0 setcion to USB device\n");
		goto error;
	}

	// Creating donor structure	
	memcpy(donor_buf, donor_idps, sizeof(donor_idps));
	memcpy(donor_buf + 0x10, donor_data, sizeof(donor_data));
	memcpy(donor_buf + 0x38, donor_R, sizeof(donor_R));
	memcpy(donor_buf + 0x4C, donor_S, sizeof(donor_S));
	memcpy(donor_buf + 0x60, donor_pub, sizeof(donor_pub));
	memcpy(donor_buf + 0x88, donor_enc_priv_key, sizeof(donor_enc_priv_key));
	memcpy(donor_buf + 0xA8, donor_omac, sizeof(donor_omac));
	memcpy(donor_buf + 0xB8, &donor_padding, sizeof(donor_padding));
	
	aes_omac1(cmac_hash, donor_buf, 0xA8, eid_section_key, 128);	
	memcpy(donor_buf + 0xA8, cmac_hash, 0x10);
	
	if(AesCbcCfbEncrypt(encrypted_donor_buf, donor_buf, 0xC0, eid_section_key, 0x80, eid_iv) != SUCCEEDED)
	{
		log("Unable encrypt patched EID0 section\n");
		goto error;
	}

	memcpy(eid_buffer + 0x70, donor_idps, 0x10);
	memcpy(eid_buffer + 0x90, encrypted_donor_buf, 0xC0);

	// Checking if all is ok
	if(memcmp(donor_buf, donor_idps, 0x10)                ||
	   memcmp(donor_buf + 0x10, donor_data, 0x28)         ||
	   memcmp(donor_buf + 0x38, donor_R, 0x14)            ||
	   memcmp(donor_buf + 0x4C, donor_S, 0x14)            ||
	   memcmp(donor_buf + 0x60, donor_pub, 0x28)          ||
	   memcmp(donor_buf + 0x88, donor_enc_priv_key, 0x20) ||
	   memcmp(donor_buf + 0xA8, cmac_hash, 0x10)          ||
	   memcmp(donor_buf + 0xB8, &donor_padding, 0x08))
	{
		log("Error found on patched EID0 section, aborting!\n");
		goto error;
	}

	if(sys_storage_write(dev_id, start_flash_sector, 1, eid_buffer, &writelen, FLASH_FLAGS))
	{
		showMessage("msg_sup_dex_flash_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(eid_buffer[0x75] == 0x82)
	{
		if(ret == 1)
		{
			log("Found DEX TargetID, swapping kernel to DEX...\n");

			if(setFlashKernelData(CEX_TO_DEX) != 0)
			{
				log("Error while swapping DEX kernel, restoring flash IDPS...\n");
				sys_storage_write(dev_id, start_flash_sector, 1, eid_backup, &writelen, FLASH_FLAGS);	
				goto error;
			}
		}
	}

	sys_storage_close(dev_id);

	cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

	if(!cellFsStat(SOFTWARE_UPDATE_SPRX_DEX, &statinfo) && cellFsStat(SOFTWARE_UPDATE_SPRX_CEX, &statinfo))
	{
		log("Setting DEX software_update_plugin.sprx...\n");

		if(!cellFsRename(SOFTWARE_UPDATE_SPRX_DEFAULT, SOFTWARE_UPDATE_SPRX_CEX))
			cellFsRename(SOFTWARE_UPDATE_SPRX_DEX, SOFTWARE_UPDATE_SPRX_DEFAULT);
	}

	cellFsUtilUnMount(DEV_BLIND, 0);

	showMessage("msg_sup_dex_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	

	wait(3);
	rebootXMB(SYS_SOFT_REBOOT);	

	return 0;

error:
	sys_storage_close(dev_id);
	showMessage("msg_sup_dex_enable_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	sys_timer_usleep(10000);

	return 1;
}

int disable_dex_support()
{
	char file[120], eid_root_key_file[120];	
	int usb_found = 0 , usb_port = 0;
	int dev_id, ret;

	uint64_t start_flash_sector = 0x178;
	uint64_t device = FLASH_DEVICE_NOR;	

	uint8_t eid0_buf[0x200], eid_backup[0x200];;
	uint8_t eid_root_key[EID_ROOT_KEY_SIZE];
	uint8_t idps0[IDPS_SIZE];
	uint8_t key[0x10];	
	uint8_t indiv[0x100];
	uint8_t indiv_clone[0x40];

	CellFsStat stat;

	close_xml_list();

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2) || checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(receive_eid_idps(EID0, idps0))
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(memcmp(idps0, donor_idps, 0x10))
	{
		showMessage("msg_sup_dex_not_converted", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return 1;
	}
	
	usb_port = get_usb_device();

	if(usb_port == -1)
	{
		showMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}

	// Getting eid_root_key from USB device/internal HDD
	sprintf_(eid_root_key_file, "/dev_usb%03d/eid_root_key", usb_port);
	if(cellFsStat(eid_root_key_file, &stat) != CELL_FS_SUCCEEDED)
	{
		if(cellFsStat(EID_ROOT_KEY_HDD0, &stat) == CELL_FS_SUCCEEDED)
			sprintf_(eid_root_key_file, EID_ROOT_KEY_HDD0, NULL);
		else
		{
			// Dump ERK
			int dumped = 1;
			showMessage("msg_dumping_erk", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			dumped = dump_eid_root_key(eid_root_key);

			if(dumped)
			{
				showMessage("msg_dump_erk_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
				return 1;
			}

			saveFile(EID_ROOT_KEY_HDD0, eid_root_key, EID_ROOT_KEY_SIZE);
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		}	
	}

	if(readfile(eid_root_key_file, eid_root_key, EID_ROOT_KEY_SIZE))
		goto done;

	// Getting backup of EID0 from USB device
	sprintf_(file, EID0_BACKUP, usb_port);
	if(readfile(file, eid0_buf, 0x200) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_sup_dex_eid0_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(indiv_gen(eid0_key_seed, indiv, eid_root_key) != SUCCEEDED)
		goto done;

	if(AesCbcCfbEncrypt(key, eid0_section_key_seed, 0x10, indiv + 0x20, 0x100, null_iv) != SUCCEEDED)
		goto done;
	
	memcpy(indiv_clone, indiv, 0x40);

	if(AesCbcCfbDecrypt(section0_eid0_dec, eid0_buf + 0x90, 0xC0, key, 0x80, indiv_clone + 0x10) != SUCCEEDED)
		goto done;

	// Checking if partial IDPS is valid
	// TargetID must not be 0x82
	if(eid0_buf[0x70] != 0x00 || eid0_buf[0x71] != 0x00 || eid0_buf[0x72] != 0x00 || 
		eid0_buf[0x73] != 0x01 || eid0_buf[0x74] != 0x00 || eid0_buf[0x75] == 0x82 || eid0_buf[0x76] != 0x00)
	{
		showMessage("msg_idps_not_valid", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	if(!check_flash_type())
	{
		start_flash_sector = 0x204;
		device = FLASH_DEVICE_NAND;
	}	

	if(!start_flash_sector || !device)
		goto done;

	showMessage("msg_swap_kernel_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	ret = checkCurrentKernel();

	if(!ret)
	{
		log("Unable to get current kernel, aborting...\n");
		goto done;
	}
	else if(ret == 3)
	{
		log("Detected external kernel, aborting...\n");
		showMessage("msg_swap_kernel_cannot", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		goto done;
	}
	
	if(sys_storage_open(device, &dev_id))
		goto done;

	if(sys_storage_read2(dev_id, start_flash_sector, 1, eid_backup, &readlen, FLASH_FLAGS))
	{
		log("Unable to read flash storage\n");
		goto done;
	}

	if(sys_storage_write(dev_id, start_flash_sector, 1, eid0_buf, &writelen, FLASH_FLAGS))
	{
		showMessage("msg_sup_dex_flash_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(eid0_buf[0x75] != 0x82)
	{
		if(ret == 2)
		{
			log("Found CEX TargetID, swapping kernel to CEX...\n");
	
			if(setFlashKernelData(DEX_TO_CEX) != 0)
			{
				log("Error while swapping CEX kernel, restoring flash IDPS...\n");
				sys_storage_write(dev_id, start_flash_sector, 1, eid_backup, &writelen, FLASH_FLAGS);
				goto done;
			}
		}
	}

	sys_storage_close(dev_id);

	cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

	if(!cellFsStat(SOFTWARE_UPDATE_SPRX_CEX, &stat) && cellFsStat(SOFTWARE_UPDATE_SPRX_DEX, &stat))
	{
		log("Setting CEX software_update_plugin.sprx...\n");

		if(!cellFsRename(SOFTWARE_UPDATE_SPRX_DEFAULT, SOFTWARE_UPDATE_SPRX_DEX))
			cellFsRename(SOFTWARE_UPDATE_SPRX_CEX, SOFTWARE_UPDATE_SPRX_DEFAULT);
	}

	cellFsUtilUnMount(DEV_BLIND, 0);

	showMessage("msg_sup_dex_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	

	wait(3);
	rebootXMB(SYS_SOFT_REBOOT);

	return 0;

done:
	sys_storage_close(dev_id);
	showMessage("msg_sup_dex_disable_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	sys_timer_usleep(10000);

	return 1;
}
