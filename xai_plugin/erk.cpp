/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
	https://github.com/Joonie86/erk_dumper
*/

#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sysutil/sysutil_gamecontent.h>
#include "payload.h"
#include "payloads.h"
#include "mm.h"
#include "cfw_settings.h"
#include "gccpch.h"
#include "log.h"
#include "erk.h"
#include "hvcall.h"

static wchar_t wchar_string[120]; // Global variable for swprintf
unsigned char payload[payload_size];
uint64_t toc = 0;

static uint8_t eid_root_key[EID_ROOT_KEY_SIZE];

uint64_t htab_ori, map1_ori, map2_ori, spe_ori;
uint64_t permission_ori, OPD1_ori, OPD2_ori;

// It seems that all metldr dumps have these same 0x80 bytes
// The dumper dumps junk code, it can be modified to dump it correctly, but this is faster 
static uint8_t firstSection[0x80] = 
{
	0x42, 0x03, 0x18, 0x0E, 0x35, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x11, 0x42, 0x03, 0x18, 0x0E,
	0x42, 0x95, 0xF8, 0x0F, 0x58, 0x03, 0xC7, 0x10, 0x21, 0x00, 0x02, 0x10,
	0x24, 0x00, 0x07, 0x11, 0x1C, 0x04, 0x07, 0x0E, 0x30, 0x00, 0x83, 0x80,
	0x40, 0x80, 0x00, 0x00, 0x40, 0x80, 0x00, 0x01, 0x40, 0x80, 0x00, 0x02,
	0x40, 0x80, 0x00, 0x04, 0x40, 0x80, 0x00, 0x05, 0x40, 0x80, 0x00, 0x06,
	0x40, 0x80, 0x00, 0x07, 0x40, 0x80, 0x00, 0x08, 0x40, 0x80, 0x00, 0x09,
	0x40, 0x80, 0x00, 0x0A, 0x40, 0x80, 0x00, 0x0B, 0x40, 0x80, 0x00, 0x0C,
	0x40, 0x80, 0x00, 0x0D, 0x40, 0x80, 0x00, 0x0E, 0x40, 0x80, 0x00, 0x0F,
	0x40, 0x80, 0x00, 0x10, 0x40, 0x80, 0x00, 0x11, 0x40, 0x80, 0x00, 0x12,
	0x40, 0x80, 0x00, 0x13, 0x40, 0x80, 0x00, 0x14
};

uint64_t patches[8] = 
{
	// Allow mapping of HTAB with write protection 
	HTAB_PROTECTION_OFFSET, HTAB_PROTECTION_PATCH,

	// Allow mapping of any needed memory area
	MAP1_OFFSET, MAP1_PATCH,
	MAP2_OFFSET, MAP2_PATCH,

	// Allow setting all bits of SPE register MFC_SR1 
	SPE_REGISTER_OFFSET, SPE_REGISTER_PATCH
};

static int make_patches(void) 
{
	// Getting original values
	htab_ori = lv1_peek(HTAB_PROTECTION_OFFSET);
	map1_ori = lv1_peek(MAP1_OFFSET);
	map2_ori = lv1_peek(MAP2_OFFSET);
	spe_ori = lv1_peek(SPE_REGISTER_OFFSET);
	permission_ori = lv2_peek(PERMISSION_OFFSET);
	OPD1_ori = lv2_peek(OPD_OFFSET + 0);
	OPD2_ori = lv2_peek(OPD_OFFSET + 8);	

	for(int i = 0; i < 7; i += 2)
	{
		lv1_poke(patches[i], patches[i + 1]);

		if(lv1_peek(patches[i]) != patches[i + 1])		
			return 2;		
	}

	/* permission patch */
	lv2_poke(PERMISSION_OFFSET, PERMISSION_PATCH);

	/* remove page protection bits from htab entries */
	patch_htab_entries(0);

	return 0;
}

static int restore_patches(void)
{
	lv1_poke(HTAB_PROTECTION_OFFSET, htab_ori);
	lv1_poke(MAP1_OFFSET, map1_ori);
	lv1_poke(MAP2_OFFSET, map2_ori);
	lv1_poke(SPE_REGISTER_OFFSET, spe_ori);
	lv2_poke(PERMISSION_OFFSET, permission_ori);
	lv2_poke(OPD_OFFSET + 0, OPD1_ori);
	lv2_poke(OPD_OFFSET + 8, OPD2_ori);

	return 0;
}

static int run_payload(uint64_t arg, uint64_t arg_size) 
{
	system_call_2(SYSCALL_RUN_PAYLOAD, (uint64_t)arg, (uint64_t)arg_size);
	return_to_user_prog(int);
}

// Thanks to Mathieulh, flatz, CMX, zecoxao and M4j0r
int dump_eid_root_key(uint8_t output[0x30], int mode)
{
	int result = 1, port = 0, dev_id;
	int payload_installed = 0;
	int patches_installed = 0;
	char dump_file_path[120];

	uint8_t *metldr_data = NULL;
	uint8_t *final_output = NULL;
	uint8_t flash_dump[0x200];

	uint32_t readlen, metldr_size, final_size;

	uint64_t start_flash_sector;
	uint64_t device;

	if(lv2_peek(CEX_OFFSET) == CEX)
	{
		OFFSET_HVSC_REDIRECT = REDIRECT_OFFSET;
		memcpy(payload, payload_481C_489C, payload_size);
		toc = TOC_OFFSET;
		log("CEX FW detected\n");
	}
	else if(lv2_peek(CEX_OFFSET - 0x10) == CEX)
	{
		OFFSET_HVSC_REDIRECT = REDIRECT_490_OFFSET;
		memcpy(payload, payload_490C, payload_size);
		toc = TOC_490_OFFSET;
		log("CEX FW detected\n");
	}
	else if(lv2_peek(DEX_OFFSET) == DEX)
	{
		OFFSET_HVSC_REDIRECT = REDIRECT_DEX_OFFSET;
		memcpy(payload, payload_481D_489D, payload_size);
		toc = TOC_DEX_OFFSET;
		log("DEX FW detected\n");
	}
	else if(lv2_peek(DEH_OFFSET) == DEH)
	{
		OFFSET_HVSC_REDIRECT = REDIRECT_DEH_OFFSET;
		memcpy(payload, payload_484DEH, payload_size);
		toc = TOC_DEH_OFFSET;
		log("DEH FW detected\n");
	}
	else
		return -1;

	lv2_copy_from_user(payload, PAYLOAD_OFFSET, payload_size);

	result = make_patches();
	if (result != 0) 
		goto error;

	patches_installed = 1;

	result = install_payload();
	if (result != 0) 
		goto error;

	payload_installed = 1;

	metldr_data = (uint8_t *)malloc__(METLDR_SIZE);
	if(!metldr_data)
	{
		log("Unable to malloc data\n");
		goto error;
	}	

	memset(metldr_data, 0, METLDR_SIZE);

	if(mode == METLDR)
	{
		log("Dumping metldr...\n");		

		// Getting metldr size from NAND/NOR
		start_flash_sector = 4;
		device = FLASH_DEVICE_NOR;

		if(!check_flash_type())
			device = FLASH_DEVICE_NAND;

		if(!start_flash_sector || !device)
			goto error;

		if(sys_storage_open(device, &dev_id))
			goto error;

		if(sys_storage_read2(dev_id, start_flash_sector, 1, flash_dump, &readlen, FLASH_FLAGS))
		{
			log("Unable to read flash storage\n");
			goto error;
		}

		sys_storage_close(dev_id);

		// Getting metldr size from flash
		memcpy(&metldr_size, flash_dump + 0x40, 4);
		metldr_size = metldr_size * 0x10;
		log("metldr size: 0x%X\n", (int)metldr_size);
		log("metldr flash address: 0x%X\n", (int)start_flash_sector * 0x200);
		log("metldr flash size address: 0x%X\n", (int)start_flash_sector * 0x200 + 0x40);
	
		result = run_payload((uintptr_t)metldr_data, EID_ROOT_KEY_SIZE);
		if (result != 0) 
			goto error;	

		final_size = metldr_size + 0x400;

		final_output = (uint8_t *)malloc__(final_size);
		if(!final_output)
		{
			log("Unable to malloc data\n");
			goto error;
		}		

		// Cleaning garbage data
		memcpy(metldr_data + 0x400, firstSection, 0x80);
		memset(final_output, 0, final_size);
		memcpy(final_output + 0x400, metldr_data + 0x400, metldr_size);

		sprintf_(dump_file_path, "/dev_hdd0/tmp/%s", (int)METLDR_FILE_NAME);

		result = saveFile(dump_file_path, final_output, final_size);
		if (result != 0) 
			goto error;	

		port = get_usb_device();

		if(port != -1)
		{
			sprintf_(dump_file_path, "/dev_usb%03d/%s", port, (int)METLDR_FILE_NAME);	
			saveFile(dump_file_path, final_output, final_size);
		}

		buzzer(SINGLE_BEEP);
		int string = RetrieveString("msg_dump_metldr_ok", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)dump_file_path);	
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
	else
	{
		log("Dumping eid_root_key...\n");

		result = run_payload((uintptr_t)metldr_data, EID_ROOT_KEY_SIZE);
		if (result != 0) 
			goto error;	

		memcpy(output, metldr_data, EID_ROOT_KEY_SIZE);
	}

	result = 0;

	log("Done\n");

error:
	if(payload_installed) 
		remove_payload();

	if(patches_installed)
		restore_patches();

	free__(metldr_data);
	free__(final_output);

	return result;
}

void dumperk(int mode) 
{
	int dumped = 1, port = 0;
	char dump_file_path[CELL_GAME_PATH_MAX];
	wchar_t wchar_string[120];
	uint8_t dumped_erk[0x30];
		
	dumped = dump_eid_root_key(dumped_erk, mode);	

	if(!dumped)
	{
		if(mode == ERK)
		{
			sprintf_(dump_file_path, "/dev_hdd0/tmp/%s", (mode == ERK ? (int)EID_ROOT_KEY_FILE_NAME : (int)METLDR_FILE_NAME));

			if(saveFile(dump_file_path, dumped_erk, EID_ROOT_KEY_SIZE) != CELL_FS_SUCCEEDED)
			{
				showMessage("msg_dump_erk_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}		

			port = get_usb_device();

			if(port != -1)
			{
				sprintf_(dump_file_path, "/dev_usb%03d/%s", port, (mode == ERK ? (int)EID_ROOT_KEY_FILE_NAME : (int)METLDR_FILE_NAME));	
				saveFile(dump_file_path, dumped_erk, EID_ROOT_KEY_SIZE);
			}

			buzzer(SINGLE_BEEP);
			int string = RetrieveString("msg_dump_erk_ok", (char*)XAI_PLUGIN);	
			swprintf_(wchar_string, 120, (wchar_t*)string, (int)dump_file_path);	
			PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		
		}
	}
	else
		showMessage((mode == ERK ? "msg_dump_erk_fail" : "msg_dump_metldr_fail"), (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
}
