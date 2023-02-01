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
#include "savegames.h"
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

int true_dex, true_dex_dex_idps;

uint8_t section0_eid0_dec[0xc0];
uint8_t section0_eid0_enc_modded[0xc0];

uint64_t start_flash_sector, device;
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

int recieve_eid5_idps(uint8_t output[0x10]) 
{
	int dev_id;
	
	uint64_t disc_size = 0;		
	device_info_t disc_info;	
	uint16_t offset = 0x1D0;

	start_flash_sector = 0x181;
	device = FLASH_DEVICE_NOR;

	if(!check_flash_type())
	{
		start_flash_sector = 0x20D;
		device = FLASH_DEVICE_NAND;
	}

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
	}
	
	sys_storage_close(dev_id);
	free__(rb);

	return 0;
}

int check_targetid(int mode)
{
	int dev_id, targetid, string;
	wchar_t wchar_string[120];

	uint8_t idps[IDPS_SIZE];
	uint8_t read_buffer[0x200];	

	start_flash_sector = 0x178;
	device = FLASH_DEVICE_NOR;

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

	if(recieve_eid5_idps(idps))
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
	ShowMessage("msg_show_eid_target_error", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	
	return 1;
}

void get_ps3_info()
{
	CellFsStat stat;

	int dev_id, string;
	wchar_t wchar_string[120];

	uint8_t platform_info[0x18];	
	uint8_t read_buffer[0x200];		

	start_flash_sector = 376;
	device = FLASH_DEVICE_NOR;

	if(!check_flash_type())
	{
		start_flash_sector = 516;
		device = FLASH_DEVICE_NAND;
	}	

	system_call_1(387, (uint64_t)platform_info);

	if(sys_storage_open(device, &dev_id))
		goto error;

	if(sys_storage_read2(dev_id, start_flash_sector, 1, read_buffer, &readlen, FLASH_FLAGS))
		goto error;

	if(sys_storage_close(dev_id))
		goto error;    

	string = RetrieveString("msg_ps3_information", (char*)XAI_PLUGIN);	

	/*swprintf_(wchar_string, 120, (wchar_t*)string, platform_info[0], platform_info[1], platform_info[2] >> 4, 
		lv2_peek(CEX_OFFSET) == DISABLED ? (int)"???" : (lv2_peek(CEX_OFFSET) == CEX ? (int)"CEX" : (int)"DEX"), 
		lv2_peek(CEX_OFFSET) == DISABLED ? (int)"???" : (lv2_peek(CEX_OFFSET) == CEX ? (int)"CEX" : (int)"DEX"),
		read_buffer[0x75] == 0x82 ? (int)"DEX" : (int)"CEX");	*/

	swprintf_(wchar_string, 120, (wchar_t*)string, platform_info[0], platform_info[1], platform_info[2] >> 4, 
		lv2_peek(CEX_OFFSET) == DISABLED ? (int)"???" : (lv2_peek(CEX_OFFSET) == CEX ? (int)"CEX" : (int)"DEX"), 
		lv2_peek(CEX_OFFSET) == DISABLED ? (int)"???" : (lv2_peek(CEX_OFFSET) == CEX ? (int)"CEX" : (int)"DEX"),
		read_buffer[0x75] == 0x82 ? (int)"DEX" : (int)"CEX",
		cellFsStat("/dev_flash/vsh/module/vsh.self.dex", &stat) == CELL_FS_SUCCEEDED ? (int)"CEX" : (int)"DEX",
		cellFsStat("/dev_flash/vsh/module/xmb_plugin.sprx.dex", &stat) == CELL_FS_SUCCEEDED ? (int)"CEX" : (int)"DEX",
		cellFsStat("/dev_flash/vsh/module/sysconf_plugin.sprx.dex", &stat) == CELL_FS_SUCCEEDED ? (int)"CEX" : (int)"DEX");	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	return;

error:
	ShowMessage("msg_ps3_information_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return;
}

int dump_flash()
{
	char file[120];
	char filename[120];
	char usb_file[120];
	char dump_file[120];
	char type[120];
	wchar_t wchar_string[120];

	int result, fd, fd_usb;
	int usb_found = 0, usb_port = 0;
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
	int final_offset;	

	int string = RetrieveString("msg_dumping_flash", (char*)XAI_PLUGIN);			
	
	flash_device = FLASH_DEVICE_NOR;
	strcpy(dump_file, NOR_DUMP);
	strcpy(type, "NOR");		
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)"NOR");	

	// Checking if FLASH is NOR or NAND
	if(!check_flash_type())
	{
		flash_device = FLASH_DEVICE_NAND;
		strcpy(dump_file, NAND_DUMP);
		strcpy(type, "NAND");
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

	start_sector = VFLASH_START_SECTOR;
	sector_count = info.capacity;

	// Creating file in dev_hdd0
	if(cellFsOpen(file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)		
		goto done;	

	cellFsChmod(file, 0666);

	// Read storage
	while (sector_count >= SECTORS) 
	{
		if(lv2_storage_read(dev_handle, 0, start_sector, SECTORS, buf, &sectors_read, FLASH_FLAGS))
			goto done;	

		if(cellFsWrite(fd, buf, SECTORS * FLASH_SECTOR_SIZE, &nrw) != CELL_FS_SUCCEEDED)
			goto done;	

		start_sector += SECTORS;
		sector_count -= SECTORS;
	}

	// Copy to USB if is detected
	char port[120];
	for(int i = 0; i < 127; i++) 
	{
		sprintf_(port, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(port, &statinfo))
		{
			usb_port = i;
			usb_found = 1;
			break;
		}
	}		

	if(usb_found)
	{
		offset = 0;
		max_offset = 0x40000;

		fseek_offset = 0;	
		start_offset = 0;

		final_offset = 0x1000000ULL;

		sprintf_(usb_file, "/dev_usb%03d/%s", usb_port, (int)filename);

		if(cellFsOpen(usb_file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd_usb, 0, 0) != CELL_FS_SUCCEEDED)		
			goto done;		

		cellFsChmod(usb_file, 0666);

		dump = (uint8_t *)malloc__(0x40000);
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

	if(usb_found)
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

	string = RetrieveString("msg_dump_flash_error", (char*)XAI_PLUGIN);
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)type);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);		

	buzzer(TRIPLE_BEEP);

	return 1;
}

static int search_flash(uint8_t _mode) 
{
	// 0 = CEX -> DEX, 1 = DEX -> CEX

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

// 0 = CEX
// 1 = DEX
void cex2dex(int mode)
{
	int dev_id, targetID;	
	int file_found = 0, usb_port;
	char file[120];

	uint8_t idps[IDPS_SIZE];
	uint8_t indiv[0x100];
	uint8_t key[0x10];	
	uint8_t read_buffer[0x200];
	uint8_t *eid_root_key;

	CellFsStat statinfo;	

	close_xml_list();

	sys_timer_usleep(10000);

	// Search eid_root_key
	for(int i = 0; i < 127; i++) 
	{
		sprintf_(file, "/dev_usb%03d/eid_root_key", i, NULL);

		if(!cellFsStat(file, &statinfo))
		{
			file_found = 1;
			break;
		}
	}

	if(!file_found)
	{
		if(!cellFsStat(EID_ROOT_KEY_HDD0, &statinfo))
			sprintf_(file, EID_ROOT_KEY_HDD0, NULL);
		else
		{
			ShowMessage("msg_erk_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return;
		}		
	}	
	
	if(recieve_eid5_idps(idps))
		goto done;

	eid_root_key = (uint8_t *)malloc__(EID_ROOT_KEY_SIZE);	
	readfile(file, eid_root_key, EID_ROOT_KEY_SIZE);

	if(indiv_gen(eid0_key_seed, indiv, eid_root_key) != SUCCEEDED)
	{
		free__(eid_root_key);
		goto done;
	}

	free__(eid_root_key);

	if(AesCbcCfbEncrypt(key, eid0_section_key_seed, 0x10, indiv + 0x20, 0x100, null_iv) != SUCCEEDED)
		goto done;

	start_flash_sector = 0x178;
	device = FLASH_DEVICE_NOR;

	if(!check_flash_type())
	{
		start_flash_sector = 0x204;
		device = FLASH_DEVICE_NAND;
	}	
	
	if(sys_storage_open(device, &dev_id))
		goto done;

	if(sys_storage_read2(dev_id, start_flash_sector, 1, read_buffer, &readlen, FLASH_FLAGS))
		goto done;

	// Checking if partial IDPS from flash is valid
	if(read_buffer[0x70] != 0x00 && read_buffer[0x71] != 0x00 && read_buffer[0x72] != 0x00 && 
		read_buffer[0x73] != 0x01 && read_buffer[0x74] != 0x00 && read_buffer[0x76] != 0x00)
	{
		sys_storage_close(dev_id);
		goto done;
	}

	if(idps[0x00] != 0x00 && idps[0x01] != 0x00 && idps[0x02] != 0x00 && 
		idps[0x03] != 0x01 && idps[0x04] != 0x00 && idps[0x06] != 0x00)
	{
		sys_storage_close(dev_id);
		goto done;
	}	

	if(mode)
	{
		// DEX TargetID is already set
		if(read_buffer[0x75] == 0x82)
		{			
			ShowMessage("msg_convert_already_dex", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			return;
		}

		read_buffer[0x75] = 0x82;
	}
	else
	{
		// CEX TargetID is already set
		if(read_buffer[0x75] != 0x82)
		{			
			ShowMessage("msg_convert_already_cex", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
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

	sys_storage_close(dev_id);

	targetID = check_targetid(1);

	if(targetID != 0x82)
	{
		log("Found CEX TargetID, swapping kernel to CEX...\n");
		search_flash(DEX_TO_CEX);
	}

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

		ShowMessage("msg_convert_dex_done", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	
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

		ShowMessage("msg_convert_cex_done", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	cellFsUtilUnMount(DEV_BLIND, 0);
	sys_timer_usleep(10000);

	return;

done:
	sys_storage_close(dev_id);
	ShowMessage("msg_convert_cex_dex_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	sys_timer_usleep(10000);

	return;
}

void swap_kernel()
{
	CellFsStat statinfo;
	close_xml_list();

	// Check if CFW Syscalls are disabled
	if(check_syscalls())
	{
		ShowMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int targetID = check_targetid(1);

	if(targetID == 0x82)
	{
		if(lv2_peek(CEX_OFFSET) == CEX && lv2_peek(0x80000000002FCB68ULL) == 0x323032322F30322FULL)
		{
			log("CEX detected, swapping to DEX...\n");

			if(!search_flash(CEX_TO_DEX))	
			{
				cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

				if(!cellFsStat(VSH_SELF_DEX, &statinfo) && cellFsStat(VSH_SELF_CEX, &statinfo))
				{
					log("Setting DEX vsh.self...\n");

					if(!cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_CEX))
						cellFsRename(VSH_SELF_DEX, VSH_SELF_DEFAULT);
				}

				cellFsUtilUnMount(DEV_BLIND, 0);

				ShowMessage("msg_swap_kernel_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);		
				wait(3);
				xmb_reboot(SYS_SOFT_REBOOT);
			}
			else
				ShowMessage("msg_swap_kernel_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		}
		else if(lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032332F30312FULL)
		{
			log("DEX detected, swapping to CEX...\n");

			if(!search_flash(DEX_TO_CEX))
			{
				ShowMessage("msg_swap_kernel_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
				wait(3);
				xmb_reboot(SYS_SOFT_REBOOT);
			}
			else
				ShowMessage("msg_swap_kernel_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		}
		else
			ShowMessage("msg_swap_kernel_unknown", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	}
	else
		ShowMessage("msg_swap_kernel_dex_needed", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
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
	if(check_syscalls())
	{
		ShowMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
	int ret = sys_ss_get_console_id(current_idps);

	if(ret == EPERM)
		ret = GetIDPS(current_idps);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}	

	if(recieve_eid5_idps(idps))
		return 1;

	for(uint64_t offset = start_offset; offset < end_offset; offset += 4)
	{
		if(lv2_peek(offset) == current_idps[0] && lv2_peek(offset + 8) == current_idps[1])
		{			
			lv2_poke8(offset + 5, idps[5]);

			// Checking if patches are done
			if(lv2_peek8(offset + 5) != idps[5])
			{
				ShowMessage("msg_spoof_target_id_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return 1;
			}

			done++;
		}
	}

	if(done < 2)
	{
		ShowMessage("msg_spoof_target_id_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	int string = RetrieveString("msg_spoof_target_id_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)idps[5]);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;
}

int toggle_xmbplugin() // DONE
{
	CellFsStat stat;

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(!cellFsStat(XMB_SPRX_DEX, &stat) && cellFsStat(XMB_SPRX_CEX, &stat))
	{
		cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_CEX);
		cellFsRename(XMB_SPRX_DEX, XMB_SPRX_DEFAULT);
		ShowMessage("msg_toggle_xmbplugin_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(XMB_SPRX_CEX, &stat) && cellFsStat(XMB_SPRX_DEX, &stat))
	{
		cellFsRename(XMB_SPRX_DEFAULT, XMB_SPRX_DEX);
		cellFsRename(XMB_SPRX_CEX, XMB_SPRX_DEFAULT);
		ShowMessage("msg_toggle_xmbplugin_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		ShowMessage("msg_toggle_xmbplugin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

int toggle_vsh()
{
	CellFsStat stat;

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(check_targetid(1) == 0x82 && lv2_peek(DEX_OFFSET) == DEX && lv2_peek(0x800000000031F028ULL) == 0x323032332F30312FULL)
	{
		ShowMessage("msg_toggle_vsh_canceled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);		
		return 1;
	}

	if(!cellFsStat(VSH_SELF_DEX, &stat) && cellFsStat(VSH_SELF_CEX, &stat))
	{
		cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_CEX);
		cellFsRename(VSH_SELF_DEX, VSH_SELF_DEFAULT);
		ShowMessage("msg_toggle_vsh_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(VSH_SELF_CEX, &stat) && cellFsStat(VSH_SELF_DEX, &stat))
	{
		cellFsRename(VSH_SELF_DEFAULT, VSH_SELF_DEX);
		cellFsRename(VSH_SELF_CEX, VSH_SELF_DEFAULT);
		ShowMessage("msg_toggle_vsh_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		ShowMessage("msg_toggle_vsh_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

int toggle_sysconf()
{
	CellFsStat stat;

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	if(!cellFsStat(SYSCONF_SPRX_DEX, &stat) && cellFsStat(SYSCONF_SPRX_CEX, &stat))
	{
		cellFsRename(SYSCONF_SPRX_DEFAULT, SYSCONF_SPRX_CEX);
		cellFsRename(SYSCONF_SPRX_DEX, SYSCONF_SPRX_DEFAULT);
		ShowMessage("msg_toggle_sysconf_dex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(!cellFsStat(SYSCONF_SPRX_CEX, &stat) && cellFsStat(SYSCONF_SPRX_DEX, &stat))
	{
		cellFsRename(SYSCONF_SPRX_DEFAULT, SYSCONF_SPRX_DEX);
		cellFsRename(SYSCONF_SPRX_CEX, SYSCONF_SPRX_DEFAULT);
		ShowMessage("msg_toggle_sysconf_cex", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
		ShowMessage("msg_toggle_sysconf_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}
