/*
	Imported by Evilnat for xai_plugin from sguerrini97 Github repository
	https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/setup_flash_for_otheros
*/

#include <stdio.h>
#include <string.h>
#include <sys/timer.h>
#include <cell/fs/cell_fs_file_api.h>
#include "otheros.h"
#include "savegames.h"
#include "functions.h"
#include "log.h"
#include "cfw_settings.h"

int setup_vflash()
{
	int start_sector, sector_count;
	uint8_t buf[VFLASH_SECTOR_SIZE * VFLASH_SECTOR_COUNT];
	uint32_t dev_handle = 0, unknown;	
	uint64_t *ptr;

	close_xml_list();

	if(lv2_storage_open(VFLASH_DEV_ID, &dev_handle))
		goto error;	

	start_sector = VFLASH_START_SECTOR;
	sector_count = VFLASH_SECTOR_COUNT;

	if(lv2_storage_read(dev_handle, 0, start_sector, sector_count, buf, &unknown, VFLASH_FLAGS))
		goto error;

	sys_timer_usleep(10000);

	// Check partition table magic 
	if((*((uint64_t *) buf + 2) != PARTITION_TABLE_MAGIC1) ||
		(*((uint64_t *) buf + 3) != PARTITION_TABLE_MAGIC2)) 	
		goto error;

	// Patch sector count of VFLASH 6th region
	ptr = (uint64_t *) (buf + VFLASH_PARTITION_TABLE_6ND_REGION_OFFSET + 0x8ull);
	*ptr = VFLASH_6TH_REGION_NEW_SECTOR_COUNT;

	// Patch start sector of VFLASH 7th region
	ptr = (uint64_t *) (buf + VFLASH_PARTITION_TABLE_7TH_REGION_OFFSET);
	*ptr = VFLASH_7TH_REGION_NEW_START_SECTOR;

	if(lv2_storage_write(dev_handle, 0, start_sector, sector_count, buf, &unknown, VFLASH_FLAGS))
		goto error;	

	sys_timer_usleep(10000);	
	lv2_storage_close(dev_handle);

	ShowMessage("msg_otheros_resize_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);

	return 0;

error:
	lv2_storage_close(dev_handle);
	ShowMessage("msg_otheros_resize_vflash_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}

int setup_flash()
{	
	int start_sector, sector_count;
	uint8_t buf[FLASH_SECTOR_SIZE * FLASH_SECTOR_COUNT];
	uint32_t unknown, dev_handle = 0;	
	uint64_t *ptr;

	close_xml_list();

	if(lv2_storage_open(FLASH_DEV_ID, &dev_handle))
		goto error;	

	start_sector = FLASH_START_SECTOR;
	sector_count = FLASH_SECTOR_COUNT;

	if(lv2_storage_read(dev_handle, 0, start_sector, sector_count, buf, &unknown, NFLASH_FLAGS))
		goto error;	

	sys_timer_usleep(10000);

	// Check partition table magic 
	if((*((uint64_t *) buf + 2) != PARTITION_TABLE_MAGIC1) || (*((uint64_t *) buf + 3) != PARTITION_TABLE_MAGIC2)) 
		goto error;	

	// Patch FLASH 6th region
	ptr = (uint64_t *) (buf + FLASH_PARTITION_TABLE_6ND_REGION_OFFSET);

	*ptr++ = FLASH_6TH_REGION_NEW_START_SECTOR;
	*ptr++ = FLASH_6TH_REGION_NEW_SECTOR_COUNT;
	*ptr++ = FLASH_REGION_LPAR_AUTH_ID;
	*ptr++ = FLASH_REGION_ACL;

	// Patch FLASH 7th region
	ptr = (uint64_t *) (buf + FLASH_PARTITION_TABLE_7TH_REGION_OFFSET);

	*ptr++ = FLASH_7TH_REGION_NEW_START_SECTOR;
	*ptr++ = FLASH_7TH_REGION_NEW_SECTOR_COUNT;
	*ptr++ = FLASH_REGION_LPAR_AUTH_ID;
	*ptr++ = FLASH_REGION_ACL;

	if(lv2_storage_write(dev_handle, 0, start_sector, sector_count, buf, &unknown, NFLASH_FLAGS))
		goto error;

	sys_timer_usleep(10000);
	lv2_storage_close(dev_handle);

	ShowMessage("msg_otheros_resize_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);

	return 0;

error:
	lv2_storage_close(dev_handle);
	ShowMessage("msg_otheros_resize_flash_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}

int install_petitboot()
{
	int fd;
	int file_sectors, start_sector, sector_count;	
	
	CellFsStat stat;
	uint8_t buf[VFLASH5_SECTOR_SIZE * 16];
	uint32_t dev_handle = 0, unknown;
	uint64_t file_size, nr;	

	struct storage_device_info info;
	struct os_area_header *hdr;
	struct os_area_params *params;
	struct os_area_db *db;	

	char filename[120];
	int file_found = 0;

	close_xml_list();

	int flashType = check_flash_type();

	for(int i = 0; i < 127; i++) 
	{
		if(flashType)
			sprintf_(filename, "/dev_usb%03d/%s", i, (int)PETITBOOT_NOR);
		else
			sprintf_(filename, "/dev_usb%03d/%s", i, (int)PETITBOOT_NAND);

		if(!cellFsStat(filename, &stat))
		{
			file_found = 1;
			break;
		}
	}

	if(!file_found)
	{
		if(flashType)
			ShowMessage("msg_otheros_nor_file_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		else
			ShowMessage("msg_otheros_nand_file_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		return 1;
	}

	ShowMessage("msg_otheros_petitboot_installing", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	if(cellFsStat(filename, &stat) == CELL_FS_SUCCEEDED)
	{
		if(cellFsOpen(filename, CELL_FS_O_RDONLY, &fd, 0, 0) == CELL_FS_SUCCEEDED)
		{
			file_size = stat.st_size;
			file_sectors = (file_size + VFLASH5_SECTOR_SIZE - 1) / VFLASH5_SECTOR_SIZE;
			
			if(file_sectors > (VFLASH5_SECTORS - VFLASH5_HEADER_SECTORS - VFLASH5_OS_DB_AREA_SECTORS))
				goto error;
		
			if(lv2_storage_get_device_info(VFLASH5_DEV_ID, &info))
				goto error;

			if(info.capacity < (VFLASH5_HEADER_SECTORS + VFLASH5_OS_DB_AREA_SECTORS + file_sectors)) 	
				goto error;

			if(lv2_storage_open(VFLASH5_DEV_ID, &dev_handle))
				goto error;			

			// Write os header and db area
			start_sector = 0;
			sector_count = VFLASH5_HEADER_SECTORS + VFLASH5_OS_DB_AREA_SECTORS;

			memset(buf, 0, sizeof(buf));
			hdr = (struct os_area_header *) buf;
			params = (struct os_area_params *) (buf + OS_AREA_SEGMENT_SIZE);
			db = (struct os_area_db *) (buf + VFLASH5_HEADER_SECTORS * OS_AREA_SEGMENT_SIZE);

			strncpy((char *) hdr->magic, HEADER_MAGIC, sizeof(hdr->magic));
			hdr->version = HEADER_VERSION;
			hdr->db_area_offset = VFLASH5_HEADER_SECTORS; // in sectors 
			hdr->ldr_area_offset = VFLASH5_HEADER_SECTORS + VFLASH5_OS_DB_AREA_SECTORS; // in sectors 
			hdr->ldr_format = HEADER_LDR_FORMAT_RAW; // we do not use gzip format !!! 
			hdr->ldr_size = file_size;

			params->boot_flag = PARAM_BOOT_FLAG_GAME_OS;
			params->num_params = 0;

			db->magic = DB_MAGIC;
			db->version = DB_VERSION;
			db->index_64 = 24;
			db->count_64 = 57;
			db->index_32 = 544;
			db->count_32 = 57;
			db->index_16 = 836;
			db->count_16 = 57;

			if(lv2_storage_write(dev_handle, 0, start_sector, sector_count, buf, &unknown, 0))
				goto error;

			start_sector += VFLASH5_HEADER_SECTORS + VFLASH5_OS_DB_AREA_SECTORS;
			
			while (file_sectors)
			{
				sector_count = MIN(file_sectors, 16);

				if(cellFsRead(fd, buf, sector_count * VFLASH5_SECTOR_SIZE, &nr) != CELL_FS_SUCCEEDED)
					goto error;

				if(lv2_storage_write(dev_handle, 0, start_sector, sector_count, buf, &unknown, 0))
					goto error;	

				sys_timer_usleep(10000);

				file_sectors -= sector_count;
				start_sector += sector_count;	
			}

			lv2_storage_close(dev_handle);	

			ShowMessage("msg_otheros_petitboot_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);

			return 0;
		}	
	}

error:
	lv2_storage_close(dev_handle);	
	ShowMessage("msg_otheros_petitboot_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	return 1;
}

// 0 = GameOS
// 1 = OtherOS
int set_flag(int flag)
{
	wchar_t wchar_string[120];

	int string;
	int start_sector, sector_count;		
	uint8_t buf[VFLASH5_SECTOR_SIZE * 16];

	uint32_t unknown;
	uint32_t dev_handle = 0;
	
	struct os_area_header *hdr;
	struct os_area_params *params;
	struct storage_device_info info;	

	if(flag > 1 && flag < 0)
	{
		ShowMessage("msg_otheros_flag_invalid", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		return 1;
	}

	if(lv2_storage_get_device_info(VFLASH5_DEV_ID, &info))
		goto error;

	if(info.capacity < VFLASH5_HEADER_SECTORS)
		goto error;

	if(lv2_storage_open(VFLASH5_DEV_ID, &dev_handle))
		goto error;

	// write os header and params
	start_sector = 0;
	sector_count = VFLASH5_HEADER_SECTORS;

	memset(buf, 0, sizeof(buf));
	hdr = (struct os_area_header *) buf;
	params = (struct os_area_params *) (buf + OS_AREA_SEGMENT_SIZE);

	if(lv2_storage_read(dev_handle, 0, start_sector, sector_count, buf, &unknown, 0))
		goto error;	

	if(strncmp((const char *) hdr->magic, HEADER_MAGIC, sizeof(hdr->magic))) 
		goto error;

	if(hdr->version != HEADER_VERSION) 
		goto error;

	if(!flag && params->boot_flag == flag)
	{
		string = RetrieveString("msg_otheros_flag_already_set", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)(flag ? "OtherOS" : "GameOS"));	
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);

		lv2_storage_close(dev_handle);
		return 0;
	}

	// Setting new flag
	log("set_flag: setting flag %X\n", flag);

	params->boot_flag = flag;

	if(lv2_storage_write(dev_handle, 0, start_sector, sector_count, buf, &unknown, 0))
		goto error;

	lv2_storage_close(dev_handle);

	if(flag)
	{
		ShowMessage("msg_otheros_flag_oo", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);				
		wait(3);
		xmb_reboot(SYS_LV2_REBOOT);
	}
	else
		ShowMessage("msg_otheros_flag_go", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	
	return 0;

error:
	string = RetrieveString("msg_otheros_flag_error", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(flag ? "OtherOS" : "GameOS"));	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	
	lv2_storage_close(dev_handle);
	return 1;
}
