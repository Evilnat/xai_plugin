/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
	https://github.com/Joonie86/erk_dumper
*/

#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sysutil/sysutil_gamecontent.h>
#include "payload.h"
#include "mm.h"
#include "cfw_settings.h"
#include "log.h"
#include "erk.h"

static uint8_t eid_root_key[EID_ROOT_KEY_SIZE];

uint64_t htab_ori, map1_ori, map2_ori, spe_ori;
uint64_t permission_ori, OPD1_ori, OPD2_ori;

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

int run_payload(uint64_t arg, uint64_t arg_size) 
{
	system_call_2(SYSCALL_RUN_PAYLOAD, (uint64_t)arg, (uint64_t)arg_size);
	return_to_user_prog(int);
}

int dump_eid_root_key(const char* file_path) 
{
	int fd;
	int result;

	FILE* fp;

	int payload_installed = 0;
	int patches_installed = 0;

	result = make_patches();
	if (result != 0) 
		goto error;

	patches_installed = 1;

	result = install_payload();
	if (result != 0) 
		goto error;

	payload_installed = 1;

	memset(eid_root_key, 0, EID_ROOT_KEY_SIZE);

	result = run_payload((uintptr_t)eid_root_key, EID_ROOT_KEY_SIZE);
	if (result != 0) 
		goto error;	
	
	result = cellFsOpen(file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0);	
	if (result != 0) 
		goto error;	

	cellFsChmod(file_path, 0666);

	uint64_t nrw;
	cellFsWrite(fd, eid_root_key, EID_ROOT_KEY_SIZE, &nrw);
	cellFsClose(fd);

	result = 0;

error:
	if (payload_installed) 
		remove_payload();

	if(patches_installed)
		restore_patches();

	return result;
}

void dumperk(void) 
{
	int dumped = 1;
	CellFsStat st;
	char usb[120];
	char dump_file_path[CELL_GAME_PATH_MAX];
	wchar_t wchar_string[120];

	sprintf_(dump_file_path, "/dev_hdd0/tmp/%s", (int)EID_ROOT_KEY_FILE_NAME);

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &st))
		{
			sprintf_(dump_file_path, "%s/%s", (int)usb, (int)EID_ROOT_KEY_FILE_NAME);
			break;
		}
	}

	dumped = dump_eid_root_key(dump_file_path);

	if(!dumped)
	{
		buzzer(SINGLE_BEEP);
		int string = RetrieveString("msg_dump_erk_ok", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)dump_file_path);	
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		
	}
	else
		ShowMessage("msg_dump_erk_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
}
