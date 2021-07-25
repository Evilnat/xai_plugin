#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cell/pad.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>
#include <sys/memory.h>
#include "log.h"
#include "cfw_settings.h"
#include "download_plugin.h"
#include "game_ext_plugin.h"
#include "explore_plugin.h"
#include "cobra.h"
#include "functions.h"
#include "gccpch.h"
#include "des.h"
#include "erk.h"

extern "C" int _videorec_export_function_video_rec(void);
extern "C" int _videorec_export_function_klicensee(void);
extern "C" int _videorec_export_function_secureid(void);
extern "C" int _videorec_export_function_sfoverride(void);

uint8_t fake_accountid[0x10] = 
{
    0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
};

uint8_t empty[0x10] = 
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int bdvd_fd;
char pkg_path[255];
wchar_t wchar_string[120]; // Global variable for swprintf

xBDVD *iBdvd;
eid2_struct eid2;
download_if *download_interface;
game_ext_plugin_interface *game_ext_interface;
explore_plugin_interface *explore_interface;

static uint8_t cconfig[sizeof(CobraConfig)];
static CobraConfig *cobra_config = (CobraConfig*) cconfig;

int cellFsUtilUnMount(const char *device_path, int r4)
{
	return cellFsUtilUmount(device_path, r4);
}

int cellFsUtilMount(const char *device_name, const char *device_fs, const char *device_path, int r6, int write_prot, int r8, int *r9)
{
	return cellFsUtilityMount(device_name, device_fs, device_path, r6, write_prot, r8, r9);
}

int AesCbcCfbEncrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv)
{
	return cellCryptoPuAesCbcCfb128Encrypt(out, in, length, user_key, bits, iv);
}

int AesCbcCfbDecrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv)
{
	return cellCryptoPuAesCbcCfb128Decrypt(out, in, length, user_key, bits, iv);
}

int handler1_enabled()
{
	return vshmain_5F5729FB(0xC);
}

int handler1_disabled()
{
	return vshmain_74A54CBF(0xC);
}

uint8_t handler2()
{
	return getLoadedPlugins()[0x3C];
}

int* load_module(char *path)
{
	int fd;
	loadModule(&fd, path, 0, 0, 0);
	return (int*)fd;
}

int Job_start(void *job, int(*handler1)(), void *param1, int r6, int r7, uint8_t(*handler2)())
{
	return startJob(job, handler1, param1, r6, r7, handler2);
}

static int GetIDPS(void *idps)
{
	return cellSsAimGetDeviceId(idps);
}

static int GetPSID(void *psid)
{
	return cellSsAimGetOpenPSID(psid);
}

void close_xml_list()
{
	explore_interface = (explore_plugin_interface *)GetPluginInterface("explore_plugin", 1);
	explore_interface->DoUnk6("close_list", 0, 0);	
}

void load_cfw_functions()
{
	(void*&)(getDiscHashKey) = (void*)((int)getNIDfunc("vsh", 0x2B58A92C)); 
	(void*&)(authDisc) = (void*)((int)getNIDfunc("vsh", 0xE20104BE)); 
	(void*&)(cellFsUtilityMount) = (void*)((int)getNIDfunc("vsh", 0xE44F29F4));
	(void*&)(cellFsUtilUmount) = (void*)((int)getNIDfunc("vsh", 0x33ACD759));
	(void*&)(cellSsAimGetDeviceId) = (void*)((int)getNIDfunc("vsh", 0x3B4A1AC4));
	(void*&)(cellSsAimGetOpenPSID) = (void*)((int)getNIDfunc("vsh", 0x9AD2E524));	
	(void*&)(Authenticate_BD_Drive) = (void*)((int)getNIDfunc("vsh", 0x26709B91));
	
	(void*&)(loadModule) = (void*)((int)getNIDfunc("paf", 0xCF068D31));
	(void*&)(ejectDisc) = (void*)((int)getNIDfunc("paf", 0x55F2C2A6));
	(void*&)(startJob) = (void*)((int)getNIDfunc("paf", 0x350B4536));
	(void*&)(getLoadedPlugins) = (void*)((int)getNIDfunc("paf", 0xAF58E756));
	
	(void*&)(cellCryptoPuAesCbcCfb128Encrypt) = (void*)((int)getNIDfunc("sdk", 0x7B79B6C5));
	(void*&)(cellCryptoPuAesCbcCfb128Decrypt) = (void*)((int)getNIDfunc("sdk", 0xB45387CD));	
	
	(void*&)(update_mgr_read_eprom) = (void*)((int)getNIDfunc("vshmain", 0x2C563C92));	// packet id 0x600B
	(void*&)(update_mgr_write_eprom) = (void*)((int)getNIDfunc("vshmain", 0x172B05CD));	// packet id 0x600C
	(void*&)(vshmain_74A54CBF) = (void*)((int)getNIDfunc("vshmain", 0x74A54CBF));	
	(void*&)(vshmain_5F5729FB) = (void*)((int)getNIDfunc("vshmain", 0x5F5729FB));	
	
	(void*&)(xBDVDGetInstance) = (void*)((int)getNIDfunc("x3", 0x9C246A91));
	iBdvd = (xBDVD*)xBDVDGetInstance();
		
	(void*&)(xSettingRegistryGetInterface) = (void*)((int)getNIDfunc("xsetting", 0xD0261D72));
	(void*&)(xSettingSystemInfoGetInterface) = (void*)((int)getNIDfunc("xsetting", 0xAF1F161));
	(void*&)(xUserGetInterface) = (void*)((int)getNIDfunc("xsetting", 0xCC56EB2D));	

	(void*&)(NotifyWithTexture) = (void*)((int)getNIDfunc("vshcommon", 0xA20E43DB)); 
	(void*&)(FindTexture) = (void*)((int)getNIDfunc("paf", 0x3A8454FC)); 
	(void*&)(mbstowcs2) = (void*)((int)getNIDfunc("stdc", 0xFCAC2E8E));

	(void*&)(free_) = (void*)((int)getNIDfunc("allocator", 0x77A602DD));
	(void*&)(malloc_) = (void*)((int)getNIDfunc("allocator", 0x759E0635));	

	(void*&)(FindPlugin) = (void*)((int)getNIDfunc("paf", 0xF21655F3));
	(void*&)(wcstombs2) = (void*)((int)getNIDfunc("stdc", 0xB680E240)); 

	(void*&)(FindString) = (void*)((int)getNIDfunc("paf", 0x89B67B9C));

	(void*&)(sys_io_unknown) = (void*)((int)getNIDfunc("sys_io", 0x7009B738));
}

int RetrieveString(const char *string, const char *plugin)
{
	int plugin_uint = FindPlugin((char*)plugin);
	int wstring = FindString(plugin_uint, string);
	return wstring;
}

void PrintString(wchar_t *string, const char *plugin, const char *tex_icon)
{
	int teximg, dummy = 0;

	int plugin_uint = FindPlugin((char*)plugin);

	char conv_str[120];
	wcstombs2((char *)conv_str, (wchar_t *)string, 120 + 1);

	log(conv_str);
	log("\n");

	FindTexture(&teximg, plugin_uint, tex_icon);
	NotifyWithTexture(0, tex_icon, 0, &teximg, &dummy, "", "", 0, (wchar_t*)string, 0, 0, 0);	
}

void ShowMessage(const char *string, const char *plugin, const char *tex_icon)
{
	int teximg, dummy = 0;

	int plugin_uint = FindPlugin((char*)plugin);
	int wstring = FindString(plugin_uint, string);

	char conv_str[120];
	wcstombs2((char *)conv_str, (wchar_t *)wstring, 120 + 1);

	log(conv_str);
	log("\n");

	FindTexture(&teximg, plugin_uint, tex_icon);
	NotifyWithTexture(0, tex_icon, 0, &teximg, &dummy, "", "", 0, (wchar_t*)wstring, 0, 0, 0);	
}

int create_rifs()
{
	int fd, string, usb_port;
	CellFsStat statinfo;
	uint64_t read;
	CellFsDirent dir;
	bool usb_found = false;
	char USB[120], rap_file[120];
	char rif_file[120], contentID[36];

	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	for(int i = 0; i < 127; i++)
	{
		sprintf_(USB, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(USB, &statinfo))
		{
			usb_found = true;
			usb_port = i;
		}
	}

	if(!usb_found)
	{
		ShowMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(USB, "/dev_usb%03d/exdata", usb_port, NULL);

	sprintf_(rif_file, "/dev_hdd0/home/%08d/exdata", userID, NULL);
	if(cellFsStat(rif_file, &statinfo) != 0)
		cellFsMkdir(rif_file, 0777);

	sprintf_(rif_file, "/dev_hdd0/home/%08d/exdata/act.dat", userID, NULL);
	if(cellFsStat(rif_file, &statinfo) != 0)
	{
		ShowMessage("msg_account_act_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
		return 1;
	}

	if(!cellFsOpendir(USB, &fd))
	{
		int rifs_created = 0;

		while(!cellFsReaddir(fd, &dir, &read))
		{		
			if(read == 0)
				break;	

			sprintf_(rap_file, "%s/%s", (int)USB, (int)dir.d_name);
			int path_len = strlen(rap_file);	

			if (!strcmp(dir.d_name, ".") || !strcmp(dir.d_name, "..") || dir.d_type == 1)
				continue;			

			if(strcasecmp(rap_file + path_len - 4, ".rap") != 0 || path_len != 59)
				continue;					

			strncpy(contentID, rap_file + 19, 40);
			contentID[36] = '\0';

			sprintf_(rif_file, "/dev_hdd0/home/%08d/exdata/%s.rif", userID, (int)contentID);

			system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CREATE_RIF, (uint64_t)rif_file); 

			if(cellFsStat(rif_file, &statinfo) != 0)
			{
				cellFsClosedir(fd);

				string = RetrieveString("msg_rif_create_error", (char*)XAI_PLUGIN);	
				swprintf_(wchar_string, 120, (wchar_t*)string, (int)dir.d_name);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);

				if(rifs_created > 1)
				{
					string = RetrieveString("msg_rifs_created", (char*)XAI_PLUGIN);	
					swprintf_(wchar_string, 120, (wchar_t*)string, rifs_created);
					PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				}
				else
					ShowMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	

				return 1;
			}

			rifs_created++;
		}

		if(rifs_created)
		{
			cellFsClosedir(fd);

			if(rifs_created > 1)
			{
				string = RetrieveString("msg_rifs_created", (char*)XAI_PLUGIN);	
				swprintf_(wchar_string, 120, (wchar_t*)string, rifs_created);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			}
			else
				ShowMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	

			return 0;
		}
	}

	ShowMessage("msg_rap_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	cellFsClosedir(fd);
	return 1;	
}

int patch_savedata()
{
	int fd, string, usb_port;
	uint64_t read;
	CellFsDirent dir;
	CellFsStat statinfo;
	bool usb_found = false;
	char string_sfo[120], string_pfd[120];
	char USB[120], source[120];	

	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	for(int i = 0; i < 127; i++)
	{
		sprintf_(USB, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(USB, &statinfo))
		{
			usb_found = true;
			usb_port = i;
		}
	}

	if(!usb_found)
	{
		ShowMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}
	
	ShowMessage("msg_savedata_converting_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	sprintf_(USB, "/dev_usb%03d/PS3/SAVEDATA", usb_port, NULL);

	if(!cellFsOpendir(USB, &fd))
	{
		int saves_converted = 0;

		while(!cellFsReaddir(fd, &dir, &read))
		{
			if(read == 0)
				break;			

			sprintf_(string_sfo, "%s/%s/PARAM.SFO", (int)USB, (int)dir.d_name);
			sprintf_(string_pfd, "%s/%s/PARAM.PFD", (int)USB, (int)dir.d_name);

			if (!strcmp(dir.d_name, ".") || !strcmp(dir.d_name, ".."))
				continue;					

			if(cellFsStat(string_sfo, &statinfo) != 0 || cellFsStat(string_pfd, &statinfo) != 0)	
				continue;    						

			sprintf_(source, "%s/%s", (int)USB, (int)dir.d_name);		

			system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CONVERT_SAVEDATA, (uint64_t)source);  
			int ret = (int)(p1);

			if(ret != 0)
			{
				switch(ret)
				{							
					case 1:	
						string = RetrieveString("msg_savedata_userid_fail", (char*)XAI_PLUGIN);	
						break;
					case 2:	
						string = RetrieveString("msg_savedata_accountid_fail", (char*)XAI_PLUGIN);	
						break;
					case 3:	
						string = RetrieveString("msg_savedata_read_sfo_fail", (char*)XAI_PLUGIN);	
						break;
					case 4:
						string = RetrieveString("msg_savedata_sfo_not_valid", (char*)XAI_PLUGIN);	
						break;
					case 5:	
						string = RetrieveString("msg_savedata_read_pfd_fail", (char*)XAI_PLUGIN);	
						break;
					case 6:	
						string = RetrieveString("msg_savedata_pfd_not_valid", (char*)XAI_PLUGIN);	
						break;
					case 7:	
						string = RetrieveString("msg_savedata_write_fail", (char*)XAI_PLUGIN);	
						break;
					default:
						string = RetrieveString("msg_savedata_unable_convert", (char*)XAI_PLUGIN);	
						break;
				}

				cellFsClosedir(fd);

				swprintf_(wchar_string, 120, (wchar_t*)string, (int)dir.d_name);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);

				if(saves_converted > 1)
					string = RetrieveString("msg_savedata_converted2", (char*)XAI_PLUGIN);	
				else
					string = RetrieveString("msg_savedata_converted", (char*)XAI_PLUGIN);	

				swprintf_(wchar_string, 120, (wchar_t*)string, saves_converted);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);

				return 1;
			}		

			saves_converted++;
		}

		if(saves_converted)
		{
			cellFsClosedir(fd);

			if(saves_converted > 1)
				string = RetrieveString("msg_savedata_converted2", (char*)XAI_PLUGIN);	
			else
				string = RetrieveString("msg_savedata_converted", (char*)XAI_PLUGIN);	

			swprintf_(wchar_string, 120, (wchar_t*)string, saves_converted);
			PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			return 0;	
		}
	}
	else
	{
		string = RetrieveString("msg_savedata_unable_open_dir", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)USB);
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}	

	ShowMessage("msg_savedata_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	cellFsClosedir(fd);
	return 1;	
}

int getAccountID()
{
	int fd;	
	int string;
    uint64_t dummy, read, seek;
	uint16_t offset = 0;

	char entry[120];
	char *buffer = (char *)malloc_(0x2A);	

	ShowMessage("msg_accountid_searching", (char*)XAI_PLUGIN, (char*)TEX_INFO2);	

	if(cellFsOpen(XREGISTRY_FILE, CELL_FS_O_RDWR, &fd, 0, 0) != 0)
	{
		ShowMessage("msg_xreg_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		free_(buffer);
		return -1;    
	}

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	
	sprintf_(entry, "/setting/user/%08d/npaccount/accountid", userID, NULL);

	// Search offset from key table
	for(int i = 0; i < 0x10000; i++)
	{		
		cellFsLseek(fd, i, SEEK_SET, &seek);
		cellFsRead(fd, buffer, 0x2A + 1, &read);

		// Found offset
		if(strcmp(buffer, entry) == 0) 
		{
			uint8_t *data = NULL;
			offset = i - 0x15;			

			// Search value from value table
			for(int i = 0x10000; i < 0x15000; i++)
			{
				data = (uint8_t *) malloc_(0x17);

				cellFsLseek(fd, i, SEEK_SET, &seek);
				cellFsRead(fd, data, 0x17, &read);
				
				// Found value
				if (memcmp(data, &offset, 2) == 0 && data[4] == 0x00 && data[5] == 0x11 && data[6] == 0x02) 
				{	 
					uint8_t account_id[0x10];
					char acc_char[16], output[120];		

					memcpy(&account_id, data + 7, 16);

					for(int i = 0; i < 16; i++)
							acc_char[i] = account_id[i];

					acc_char[0x10] = '\0';		

					if(memcmp(data + 7, fake_accountid, 0x10) == 0)					
					{						
						string = RetrieveString("msg_accountid_fake", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string, (int)acc_char);	
					}
					else if(memcmp(data + 7, empty, 0x10) == 0)		
					{				
						string = RetrieveString("msg_accountid_empty", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string);	
					}
					else			
					{		
						string = RetrieveString("msg_accountid_result", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string, (int)acc_char);
					}

					free_(buffer);
					free_(data);
					PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);			
					return 0;
				}

				free_(data);
			}
		}
	}

	free_(buffer);
	cellFsClose(fd);	

	ShowMessage("msg_accountid_unable_find", (char*)XAI_PLUGIN, (char*)TEX_ERROR);

	return -1;
}

void changeAccountID(bool force)
{
	if(force)
		close_xml_list();

	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();

	system_call_4(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_FAKE_ACCOUNTID, (uint64_t)userID, force); 
	int ret = (int)(p1);

	if(!ret)
	{
		ShowMessage("msg_accountid_set_fake", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		wait(3);
		xmb_reboot(SYS_HARD_REBOOT);
	}
	else if(ret == 1)
		ShowMessage("msg_accountid_not_empty", (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	else if(ret == 2)
		ShowMessage("msg_accountid_error_autologin", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
		ShowMessage("msg_accountid_unable_find", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
}

void backup_license()
{
	int ret, fda, fdb;
	bool found = false;
	char output[120], backup[120], act[120];
	CellFsStat stat;

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(act, ACT_DAT_PATH, userID, NULL);

	if(cellFsStat(act, &stat) != CELL_FS_SUCCEEDED)
	{
		ShowMessage("msg_account_act_not_found",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);	
		return;
	}

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(backup, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(backup, &stat))
		{
			found = true;
			sprintf_(backup, "%s/act.dat", (int)backup, NULL);
			break;
		}
	}

	if(!found)
		sprintf_(backup, "/dev_hdd0/tmp/act.dat", NULL, NULL);	

	uint8_t buf[0x1038];
	uint64_t nr, nrw;

	if(cellFsOpen(act, CELL_FS_O_RDONLY, &fda, 0, 0) != CELL_FS_SUCCEEDED)
	{
		ShowMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(cellFsOpen(backup, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fdb, 0, 0) != CELL_FS_SUCCEEDED)	
	{
		cellFsClose(fda);
		ShowMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);	
		return;
	}

	if(cellFsRead(fda, buf, 0x1038, &nr) == CELL_FS_SUCCEEDED)	
	{
		if(cellFsWrite(fdb, buf, 0x1038, &nrw) == CELL_FS_SUCCEEDED)
		{
			cellFsChmod(backup, 0666);

			int string = RetrieveString("msg_backup_created", (char*)XAI_PLUGIN);	
			swprintf_(wchar_string, 120, (wchar_t*)string, (int)backup);	
			PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		}
		else
			ShowMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);					
	}
	else
		ShowMessage("msg_act_unable_read",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);		

	cellFsClose(fda);
	cellFsClose(fdb);
}

void remove_license()
{
	CellFsStat stat;
	int ret;
	char act[120];

	close_xml_list();
	
	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(act, ACT_DAT_PATH, userID, NULL);

	if(cellFsStat(act, &stat) == CELL_FS_SUCCEEDED)
	{
		if(cellFsUnlink(act) == CELL_FS_SUCCEEDED)		
			ShowMessage("msg_account_act_deleted", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
		else
			ShowMessage("msg_account_act_delete_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	}
	else
		ShowMessage("msg_account_act_not_found", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	
}

int create_syscalls()
{
	CellFsStat stat;
	system_call_2(808, (uint64_t)"/dev_flash/vsh/module/software_update_plugin.sprx", (uint64_t)&stat);

	if(peekq(SYSCALL_TABLE) != DISABLED)
		ShowMessage("msg_create_syscalls_ok", (char *)XAI_PLUGIN, (char*)TEX_SUCCESS);
	else
		ShowMessage("msg_create_syscalls_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);

    return 0;
}

int dump_lv(int lv)
{
	int final_offset;
	int mem = 0, max_offset = 0x40000;
	int fd, fseek_offset = 0, start_offset = 0;

	char usb[120], dump_file_path[120], lv_file[120];
	const char *dumping, *lv_dump, *lv_dumped, *lv_error;

	uint8_t platform_info[0x18];
	uint64_t nrw, seek, offset_dumped;
	CellFsStat st;	

	if(peekq(SYSCALL_TABLE) == DISABLED)
	{
		ShowMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
    system_call_1(387, (uint64_t)platform_info);

	if(lv == LV2)
	{
		final_offset = 0x800000;
		dumping = "msg_lv2_dumping";	
		lv_dumped = "msg_lv2_dumped";
		lv_error = "msg_lv2_dump_error";
		lv_dump = LV2_DUMP;
	}
	else 
	{
		final_offset = 0x1000000;
		dumping = "msg_lv1_dumping";	
		lv_dumped = "msg_lv1_dumped";
		lv_error = "msg_lv1_dump_error";
		lv_dump = LV1_DUMP;
	}

	ShowMessage(dumping, (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	sprintf_(lv_file, lv_dump, platform_info[0], platform_info[1], platform_info[2] >> 4);	
	sprintf_(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &st))
		{
			sprintf_(dump_file_path, "%s/%s", (int)usb, (int)lv_file);
			break;
		}
	}

	if(cellFsOpen(dump_file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
	{
		ShowMessage(lv_error, (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	cellFsChmod(dump_file_path, 0666);

	// Quickest method to dump LV2 and LV1 through xai_plugin
	// Default method will take at least two minutes to dump LV2, and even more for LV1
	uint8_t *dump = (uint8_t *)malloc_(0x40000);
	memset(dump, 0, 0x40000);			

	for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
	{
		if(lv == LV2)
			offset_dumped = peekq(0x8000000000000000ULL + offset);
		else
			offset_dumped = lv1_peek(0x8000000000000000ULL + offset);

		memcpy(dump + mem, &offset_dumped, 8);

		mem += 8;

		if(offset == max_offset - 8)
		{
			cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, dump, 0x40000, &nrw) != SUCCEEDED)
			{
				free_(dump);				
				cellFsClose(fd);
				cellFsUnlink(dump_file_path);

				ShowMessage(lv_error, (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				return 1;
			}

			// Done dumping
			if(max_offset == final_offset)
				break;

			fseek_offset += 0x40000;
			memset(dump, 0, 0x40000);
			mem = 0;

			start_offset = start_offset + 0x40000;
			max_offset = max_offset + 0x40000;
		}		
	}

	free_(dump);
	cellFsClose(fd);

	int string = RetrieveString(lv_dumped, (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)dump_file_path);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;
}

int dumpERK()
{
	uint32_t firmware;
	check_firmware(&firmware);

	uint64_t kernel;
	check_kernel(&kernel);

	if(firmware < 0x4080 && kernel == 1 || firmware < 0x4080 && kernel == 2)
	{
		ShowMessage("msg_unsupported_firmware", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	if(peekq(SYSCALL_TABLE) == DISABLED)
	{
		ShowMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	ShowMessage("msg_dumping_erk", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	dumperk();	
}

int removeSysHistory()
{
	int user_id = 0;
	char xml_delete[100], dat_delete[100];
    char CI_delete[100], MI_delete[100], PTL_delete[100];
	CellFsStat stat;

	static uint16_t syscalls[17] = 
	{ 
		1022, 204, 203, 202, 201, 200, 9, 10, 11, 15, 20, 35, 36, 38, 6, 8, 7
	};

	if(peekq(SYSCALL_TABLE) == DISABLED)
	{
		ShowMessage("msg_syscalls_already_disabled", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return 1;
	}

	uint64_t syscall_not_impl = peekq(SYSCALL_TABLE);

	if(check_cobra_version())
	{
		//Cobra (17 syscalls)
		for(uint8_t i = 0; i < 17; i++)			
		{
			system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_DISABLE_SYSCALL, (uint64_t)syscalls[i]); 				
		}
	}

	// Normal (17 syscalls)
	for(uint8_t i = 0; i < 17; i++)
		pokeq(SYSCALL_TABLE + 8 * syscalls[i], syscall_not_impl);

	if(peekq(SYSCALL_TABLE) != DISABLED)
	{
		ShowMessage("msg_syscalls_disabling_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 1;
	}	

	// Deleting history files
	while(user_id != 200)
    {        
        sprintf_(xml_delete, "/dev_hdd0/home/%08d/webbrowser/history.xml", user_id);
        sprintf_(dat_delete, "/dev_hdd0/home/%08d/etc/boot_history.dat"  , user_id);        
        sprintf_(CI_delete, "/dev_hdd0/home/%08d/community/CI.TMP", user_id);
        sprintf_(MI_delete, "/dev_hdd0/home/%08d/community/MI.TMP", user_id);
        sprintf_(PTL_delete, "/dev_hdd0/home/%08d/community/PTL.TMP", user_id);

		cellFsUnlink(xml_delete);
		cellFsUnlink(dat_delete);
		cellFsUnlink(CI_delete);
		cellFsUnlink(MI_delete);
		cellFsUnlink(PTL_delete);

        if(!cellFsStat(xml_delete, &stat) || !cellFsStat(dat_delete, &stat) || !cellFsStat(CI_delete, &stat) || 
		   !cellFsStat(MI_delete, &stat) || !cellFsStat(PTL_delete, &stat))
		{
			ShowMessage("msg_hf_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
            return 1;
		}
        
        user_id++; 
    }

	ShowMessage("msg_syscalls_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void checkSyscall(int syscall)
{
	int ret = 1;

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_SYSCALL, syscall);
	ret = (int)(p1);

	if(!ret)
		ShowMessage("msg_syscall8_status_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	else
		ShowMessage("msg_syscall8_status_disabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

void check_QA()
{	
	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_QA); 
	int ret = (int)(p1);		

	ShowMessage((!ret) ? "msg_qa_check_disabled" : "msg_qa_check_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

int set_qa(int value)
{
	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_QA, value); 
	int ret = (int)(p1);	

	if(ret != 0)
	{
		switch(ret)
		{
			case 1:
				ShowMessage("msg_idps_not_valid", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 2:
				ShowMessage("msg_error_allocate_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 3:
				ShowMessage("msg_error_map_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 4:
				ShowMessage("msg_error_write_uart", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			default:
				ShowMessage("msg_error_unexpected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
		};

		return 1;
	}

	ShowMessage((!value) ? "msg_qa_toggle_disabled" : "msg_qa_toggle_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	return 0;
}

void fan_speed()
{
	uint8_t st, mode, unknown;
	uint8_t fan_speed, speed_percent;

	sys_sm_get_fan_policy(0, &st, &mode, &fan_speed, &unknown);	

	speed_percent = (fan_speed * 100) / 255;

	int string = RetrieveString("msg_fan_speed", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (uint8_t)fan_speed, speed_percent);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void show_cobra_info()
{
	char fw_type[16], buffer[20];	
	uint16_t cobra_version = check_cobra_version();	

	if(!cobra_version)
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_FW_TYPE, (uint64_t)fw_type);  	
	
    if((cobra_version & 0x0F) == 0)
        sprintf_(buffer, "%X.%X", cobra_version >> 8, (cobra_version & 0xFF) >> 4);
    else
        sprintf_(buffer, "%X.%02X", cobra_version >> 8, (cobra_version & 0xFF));	
	
	uint64_t fw_version = get_cobra_fw_version();	
	unsigned char *bytes = (unsigned char*)&fw_version;

	int string = RetrieveString("msg_cobra_info", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (uint64_t)fw_type, (int)buffer, bytes[6], bytes[7]);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

int save_ps2_fan_cfg(int mode)
{
	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	cobra_read_config(cobra_config);
	cobra_config->ps2_speed = mode;   
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_PS2_FAN_SPEED, mode);

	return 0;
}

int save_cobra_fan_cfg(int mode)
{
	if(!check_cobra_version())
	{
		// Supporting manual mode with Cobra disabled
		if(mode >= 0x67 && mode < 0xFE)
			sys_sm_set_fan_policy(0, 2, mode);
		else
		{
			ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return 1;
		}		
	}

	cobra_read_config(cobra_config);
	cobra_config->fan_speed = mode;   
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_FAN_SPEED, mode);

	return 0;
}

// This is for skip_existing_rif, allow_restore_sc and any opcode that returns an integer
int RetrieveValue(uint16_t opcode)
{
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, opcode);
	return (int)(p1);
}

void allow_restore_sc()
{
	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	cobra_read_config(cobra_config);
	cobra_config->allow_restore_sc = !cobra_config->allow_restore_sc;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_ALLOW_RESTORE_SYSCALLS, (int)cobra_config->allow_restore_sc);

	ShowMessage(((int)cobra_config->allow_restore_sc) ? "msg_syscalls_restore_enabled" : "msg_syscalls_restore_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void skip_existing_rif()
{
	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	cobra_read_config(cobra_config);
	cobra_config->skip_existing_rif = !cobra_config->skip_existing_rif;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SKIP_EXISTING_RIF, (int)cobra_config->skip_existing_rif);

	ShowMessage(((int)cobra_config->skip_existing_rif) ? "msg_skip_rif_enabled" : "msg_skip_rif_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void check_temp()
{
	uint32_t temp_cpu = 0, temp_rsx = 0;
	sys_game_get_temperature(0, &temp_cpu);
    sys_game_get_temperature(1, &temp_rsx);

	int systemLang;
	xSettingSystemInfoGetInterface()->GetSystemLanguage(&systemLang);

	if(systemLang == 0x01) // Show fahrenheit for USA
	{
		celsius_to_fahrenheit(&temp_cpu);
		celsius_to_fahrenheit(&temp_rsx);
	}	

	int string = RetrieveString("msg_fan_temp", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, temp_cpu, temp_rsx);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

static int load_video_rec_plugin()
{	
	int *prx = load_module("/dev_flash/vsh/module/videorec.sprx");
	log("VideoRec.prx load: %x\n", prx[7]);

	return *prx;
}

void clean_log()
{
	int ret = cellFsUnlink(getlogpath());
	ShowMessage((ret == CELL_OK) ? "msg_logfile_cleaned" : "msg_logfile_error", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
}

void log_klic()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_klicensee();
	ShowMessage((ret == CELL_OK) ? "msg_klicensee_enabled" : "msg_klicensee_disabled", (char*)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void log_secureid()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_secureid();
	ShowMessage((ret == CELL_OK) ? "msg_secureid_enabled" : "msg_secureid_disabled", (char*)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void enable_recording()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_video_rec();
	ShowMessage((ret == CELL_OK) ? "msg_gameplay_recording_enabled" : "msg_gameplay_recording_disabled", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
}

void enable_screenshot()
{
	((int*)getNIDfunc("vshmain",0x981D7E9F))[0] -= 0x2C;
	ShowMessage("msg_screenshots_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}		

void override_sfo()
{	
	int ret;
	ret = load_video_rec_plugin();
	
	ret = _videorec_export_function_sfoverride();
	ShowMessage((ret == CELL_OK) ? "msg_sfo_override_enabled" : "msg_sfo_override_disabled", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);

	ejectDisc(); // drive unload
}

int toggle_cobra()
{
	int ret = 1;
	CellFsStat statinfo;

	if(cellFsStat("/dev_blind", &statinfo) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	// Rebug
	if(cellFsStat("/dev_flash/rebug", &statinfo) == CELL_OK)
	{
		int ret_cex, ret_dex;

		if(cellFsStat(STAGE2_CEX_ENABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_ENABLED, &statinfo) == CELL_OK)
		{
			ret_cex = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_DISABLED);
			ret_dex = cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_DISABLED);

			if(ret_cex || ret_dex)
			{
				ShowMessage("msg_cant_disable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				ret = 1;
			}
			else
			{
				ShowMessage("msg_cobra_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			
				ret = 0;
				wait(2);
			}
		}
		else if(cellFsStat(STAGE2_CEX_DISABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_DISABLED, &statinfo) == CELL_OK)
		{
			ret_cex = cellFsRename(STAGE2_CEX_DISABLED, STAGE2_CEX_ENABLED);
			ret_dex = cellFsRename(STAGE2_DEX_DISABLED, STAGE2_DEX_ENABLED);

			if(ret_cex || ret_dex)
			{
				ShowMessage("msg_cant_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				ret = 1;
			}
			else
			{
				ShowMessage("msg_cobra_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			
				ret = 0;
				wait(2);
			}
		}
		else
		{
			ret = 1;
			ShowMessage("msg_stage2_rebug_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
		}
	}
	else
	{
		if(cellFsStat(STAGE2_BIN_ENABLED, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_DISABLED);

			if(ret != CELL_OK)		
				ShowMessage("msg_cant_disable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
			{
				ShowMessage("msg_cobra_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);				
				wait(2);
			}
		} 
		else if(cellFsStat(STAGE2_BIN_DISABLED, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_DISABLED, STAGE2_BIN_ENABLED);

			if(ret != CELL_OK)				
				ShowMessage("msg_cant_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
			{
				ShowMessage("msg_cobra_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		
				wait(2);
			}
		}
		else
		{
			ret = 1;
			ShowMessage("msg_stage2_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
		}
	}

	log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));

	return ret;
}

int toggle_cobra_version()
{
	char fw_type[16];
	int ret = 1;
	CellFsStat statinfo;

	if(cellFsStat("/dev_blind", &statinfo) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	// Rebug
	if(cellFsStat("/dev_flash/rebug", &statinfo) == CELL_OK)
	{
		int ret_cex, ret_dex;

		if(cellFsStat(STAGE2_CEX_ENABLED, &statinfo) != CELL_OK || cellFsStat(STAGE2_DEX_ENABLED, &statinfo) != CELL_OK)
		{
			ShowMessage("msg_please_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			cellFsUtilUnMount("/dev_blind", 0);
			return 1;
		}
		
		// stage2.cex.release/stage2.dex.release
		if(cellFsStat(STAGE2_CEX_RELEASE, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_RELEASE, &statinfo) == CELL_OK)
		{
			ret_cex = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_DEBUG);
			ret_dex = cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_DEBUG);

			if(ret_cex || ret_dex)
			{
				cellFsUtilUnMount("/dev_blind", 0);
				ShowMessage("msg_cobra_rename_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				return 1;
			}

			ret_cex = cellFsRename(STAGE2_CEX_RELEASE, STAGE2_CEX_ENABLED);
			ret_dex = cellFsRename(STAGE2_DEX_RELEASE, STAGE2_DEX_ENABLED);

			if(ret_cex || ret_dex)
			{
				// Restore previous renaming
				cellFsRename(STAGE2_CEX_DEBUG, STAGE2_CEX_ENABLED);
				cellFsRename(STAGE2_DEX_DEBUG, STAGE2_DEX_ENABLED);
		
				cellFsUtilUnMount("/dev_blind", 0);
				ShowMessage("msg_cobra_release_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				return 1;
			}

			ShowMessage("msg_cobra_release_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
			return 0;
		}
		// stage2.cex.debug/stage2.dex.debug
		else if(cellFsStat(STAGE2_CEX_DEBUG, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_DEBUG, &statinfo) == CELL_OK)
		{
			ret_cex = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_RELEASE);
			ret_dex = cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_RELEASE);

			if(ret_cex || ret_dex)
			{
				cellFsUtilUnMount("/dev_blind", 0);
				ShowMessage("msg_cobra_rename_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				return 1;
			}

			ret_cex = cellFsRename(STAGE2_CEX_DEBUG, STAGE2_CEX_ENABLED);
			ret_dex = cellFsRename(STAGE2_DEX_DEBUG, STAGE2_DEX_ENABLED);

			if(ret_cex || ret_dex)
			{
				// Restore previous renaming
				cellFsRename(STAGE2_CEX_RELEASE, STAGE2_CEX_ENABLED);
				cellFsRename(STAGE2_DEX_RELEASE, STAGE2_DEX_ENABLED);

				cellFsUtilUnMount("/dev_blind", 0);
				ShowMessage("msg_cobra_debug_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				return 1;
			}

			ShowMessage("msg_cobra_debug_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
			return 0;
		}
		else
		{
			ret = 1;
			ShowMessage("msg_cobra_versions_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
		}
	}
	// Normal
	else
	{
		if(cellFsStat(STAGE2_BIN_ENABLED, &statinfo) != CELL_OK)
		{
			ShowMessage("msg_please_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			cellFsUtilUnMount("/dev_blind", 0);
			return 1;
		}
		else if(cellFsStat(STAGE2_BIN_RELEASE, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_DEBUG);

			if(ret == CELL_OK)
			{
				ret = cellFsRename(STAGE2_BIN_RELEASE, STAGE2_BIN_ENABLED);

				if(ret == CELL_OK)
				{
					ShowMessage("msg_cobra_release_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
					wait(2);
				}
				else
					ShowMessage("msg_cobra_release_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			}
			else	
				ShowMessage("msg_cobra_rename_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		} 
		else if(cellFsStat(STAGE2_BIN_DEBUG, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_RELEASE);

			if(ret == CELL_OK)
			{
				ret = cellFsRename(STAGE2_BIN_DEBUG, STAGE2_BIN_ENABLED);

				if(ret == CELL_OK)
				{
					ShowMessage("msg_cobra_debug_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
					wait(2);
				}
				else
					ShowMessage("msg_cobra_debug_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			}
			else	
				ShowMessage("msg_cobra_rename_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		} 
		else
		{
			ret = 1;
			ShowMessage("msg_cobra_versions_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
		}
	}

	log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));

	return ret;
}

int toggle_sysconf()
{
	int ret;
	CellFsStat statinfo;

	const char *sysconf_rco_file = "/dev_blind/vsh/resource/sysconf_plugin.rco";
	const char *sysconf_rco_original = "/dev_blind/vsh/resource/sysconf_plugin.rco.ori";
	const char *sysconf_rco_modded = "/dev_blind/vsh/resource/sysconf_plugin.rco.mod";

	if(cellFsStat("/dev_blind", &statinfo) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	// Check if sysconf_plugin.rco.ori exists and swap it
	if(cellFsStat(sysconf_rco_original, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(sysconf_rco_file, sysconf_rco_modded);
		if(ret != CELL_OK)		
		{
			ShowMessage("msg_sysconf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
			return ret;
		}
			
		ret = cellFsRename(sysconf_rco_original, sysconf_rco_file);				
		if(ret != CELL_OK)	
		{
			ShowMessage("msg_sysconf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}

		log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
		return ret;
	}
	// Check if sysconf_plugin.rco.mod exists and swap it
	else if(cellFsStat(sysconf_rco_modded, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(sysconf_rco_file, sysconf_rco_original);
		if(ret != CELL_OK)			
		{
			ShowMessage("msg_sysconf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
			return ret;
		}

		ret = cellFsRename(sysconf_rco_modded, sysconf_rco_file);
		if(ret != CELL_OK)	
		{
			ShowMessage("msg_sysconf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}

		log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
		return ret;
	}	
	else	
	{
		ShowMessage("msg_no_sysconf_detected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	return ret;
}

int toggle_coldboot()
{
	int ret;
	CellFsStat statinfo;

	const char *coldboot_file = "/dev_blind/vsh/resource/coldboot.raf";
	const char *coldboot_original = "/dev_blind/vsh/resource/coldboot.raf.ori";
	const char *coldboot_modded = "/dev_blind/vsh/resource/coldboot.raf.mod";

	if(cellFsStat("/dev_blind", &statinfo) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	// Check if colboot.raf.ori exists and swap it
	if(cellFsStat(coldboot_original, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(coldboot_file, coldboot_modded);
		if(ret != CELL_OK)			
			ShowMessage("msg_raf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
			
		ret = cellFsRename(coldboot_original, coldboot_file);				
		if(ret != CELL_OK)	
			ShowMessage("msg_raf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);

		log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
		return ret;
	} 
	// Check if colboot.raf.mod exists and swap it
	else if(cellFsStat(coldboot_modded, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(coldboot_file, coldboot_original);
		if(ret != CELL_OK)					
			ShowMessage("msg_raf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			

		ret = cellFsRename(coldboot_modded, coldboot_file);
		if(ret != CELL_OK)	
			ShowMessage("msg_raf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);

		log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
		return ret;
	}	
	else	
	{
		ShowMessage("msg_no_coldboot_detected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}
	
	return ret;
}

void button_assignment()
{
	int button;
	xSettingSystemInfoGetInterface()->GetEnterButtonAssign(&button);

	button = !button;

	xSettingSystemInfoGetInterface()->SetEnterButtonAssign(button);

	ShowMessage((button) ? "msg_button_accept_x" : "msg_button_accept_o", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void toggle_dlna()
{
	explore_interface = (explore_plugin_interface *)GetPluginInterface("explore_plugin", 1);

	int dlna = xSettingRegistryGetInterface()->loadRegistryDlnaFlag();
	log("loadRegistryDlnaFlag(): %x\n", dlna);
	dlna = dlna ^ 1;

	int ret = xSettingRegistryGetInterface()->saveRegistryDlnaFlag(dlna);
	log("saveRegistryDlnaFlag(): %x\n", ret);

	if(ret != CELL_OK)	
		ShowMessage("msg_dlna_set_flag_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		Job_start(0,(dlna == 1) ? handler1_enabled : handler1_disabled, 0, -1, -1, handler2);
		explore_interface->DoUnk6("reload_category photo", 0, 0);
		explore_interface->DoUnk6("reload_category music", 0, 0);
		explore_interface->DoUnk6("reload_category video", 0, 0);
		ShowMessage((dlna == 1) ? "msg_dlna_enabled" : "msg_dlna_disabled", (char*)XAI_PLUGIN, (dlna == 1) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}
}

bool enable_hvdbg()
{
	// patch whitelist for write eprom
	log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets
	for(uint64_t offset = 0xE0000; offset < 0x1000000; offset = offset + 4)
	{	
		if(lv1_peek(offset) == 0x2B800003419D02B4ULL)
		{
			log("Found lv1 code @0x%x\n", (int)offset);
			lv1_poke(offset,0x2B8000032B800003ULL);
			break;			
		}
	}

	// patch whitelist for read eprom
	for(uint64_t offset = 0xE0000; offset < 0x1000000; offset = offset + 4)
	{	
		if(lv1_peek(offset) == 0x2B800003419D0054ULL)
		{
			log("Found lv1 code @0x%x\n", (int)offset);
			lv1_poke(offset,0x2B8000032B800003ULL);
			break;			
		}
	}

	uint8_t data;
	int ret = update_mgr_read_eprom(0x48CF0, &data);

	if(ret != 0)
	{
		ShowMessage("msg_read_eprom_failed", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(data == 0xFF)
	{
		ret = update_mgr_write_eprom(0x48CF0, 0x00);

		for(int i = 0x48CF1; i < 0x48D00; i++)		
			ret = update_mgr_write_eprom(i, 0xCC);			
		
		ShowMessage((ret == 0) ? "msg_hvproc_enabled" : "msg_write_eprom_failed", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}

	if(data == 0x00)
	{
		ret = update_mgr_write_eprom(0x48CF0, 0xFF);

		for(int i = 0x48CF1; i < 0x48D00; i++)		
			ret = update_mgr_write_eprom(i, 0xFF);			
		
		ShowMessage((ret == 0) ? "msg_hvproc_disabled" : "msg_write_eprom_failed", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}

	wait(2);
	return (ret == 0) ? true : false;
}

void backup_registry()
{
	int ret;
	bool found = false;	
	CellFsStat sb;
	ret = cellFsStat("/dev_flash2", &sb);

	if(ret != CELL_OK)
	{
		log("mount(dev_flash2)\n");
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH2", "CELL_FS_FAT", "/dev_flash2", 0, 0, 0, 0);

		if(ret != CELL_OK)		
		{
			ShowMessage("msg_devflash2_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}
	}	

	int fda;
	ret = cellFsOpen(XREGISTRY_FILE, CELL_FS_O_RDONLY, &fda, 0, 0);

	if(ret != CELL_OK)	
	{
		ShowMessage("msg_xregistry_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	int fdb;
	char backup[120], output[120];

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(backup, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(backup, &sb))
		{
			found = true;
			sprintf_(backup, "%s/xRegistry.sys", (int)backup, NULL);
			break;
		}
	}

	if(!found)
		sprintf_(backup, "/dev_hdd0/tmp/xRegistry.sys", NULL, NULL);
		
	ret = cellFsOpen(backup, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fdb, 0, 0);	
	
	if(ret != CELL_OK)
	{
		ShowMessage("msg_xregistry_backup_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
		return;
	}

	uint8_t buf[0x1000];
	uint64_t nr, nrw;

	while((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
	{
		if((int)nr == 0x1000)
		{
			ret = cellFsWrite(fdb, buf, nr, &nrw);
			memset(buf, 0, 0x1000);
		}
		else			
			break;			
	}

	cellFsClose(fda);
	cellFsClose(fdb);

	cellFsChmod(backup, 0666);

	int string = RetrieveString("msg_backup_created", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)backup);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void usb_firm_loader()
{	
	CellFsStat sb;
	char usb[120];
	bool usb_found = false;
	int usb_port;
	//int ret = cellFsStat("/dev_usb", &sb);

	for(int i = 0; i < 127; i++)
	{
		sprintf_(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &sb))
		{
			usb_found = true;
			usb_port = i;
		}
	}

	if(!usb_found)
	{
		ShowMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	uint64_t dev_flash  = 0x5F666C6173680000ULL; // '_flash..'
	uint64_t dev_flashO = 0x5F666C6173684F00ULL; // '_flashO.'
	uint64_t dev_hdd0   = 0x5F68646430000000ULL;
	uint64_t dev_hdd1   = 0x5F68646431000000ULL;
	uint64_t dev_hdd2   = 0x5F68646432000000ULL;
	uint64_t dev_usb000 = 0x5F75736230303000ULL;
	uint64_t dev_usb001 = 0x5F75736230303100ULL;
	uint64_t dev_usb002 = 0x5F75736230303200ULL;
	uint64_t dev_usb003 = 0x5F75736230303300ULL;
	uint64_t dev_usb004 = 0x5F75736230303400ULL;
	uint64_t dev_usb005 = 0x5F75736230303500ULL;
	uint64_t dev_usb006 = 0x5F75736230303600ULL;

	uint64_t Start = 0x80000000003EE470ULL;		//MTAB  // 0x80000000003EE870
	uint64_t Stop =  0x8000000000500000ULL;		//end
	uint64_t Current;
	uint64_t Data;
	
	log("Looking for test value\n");
	for (uint64_t i = 0x8000000000500000ULL; i > 0x80000000003D0000ULL; i = i - 4 )
	{
		if( peekq(i) == 0x0101000000000009ULL)
		{
			Start = i - 0x3000;
			log("Found value @: %08x", (int)(Start >> 32)); 
			log("%08x\n", (int)Start);
			i = 0x80000000003D0000ULL;
		}
	}

	// Jailcrab code
	for (Current = Start;Current < Stop; Current = Current + 4)
	{
		Data = peekq(Current);

		//Flash -> FlashO
		//HDD   -> Flash
		//USB   -> HDD
		if (Data == dev_flash)
		{
			log("Found dev_flash @: %08x", (int)(Current >> 32)); 
			log("%08x\n", (int)Current);
			pokeq(Current, dev_flashO);
		}

		if ((Data == dev_usb000) || (Data == dev_usb001) || (Data == dev_usb002) || (Data == dev_usb003) || (Data == dev_usb004) || (Data == dev_usb005) || (Data == dev_usb006))
		{
			log("Found dev_usb @: %08x", (int)(Current >> 32)); 
			log("%08x\n", (int)Current);
			pokeq(Current,dev_flash);
			Current = Stop;
		}
	}
	
	ShowMessage("msg_fw_load_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

int vtrm_manager_init()
{
    system_call_5(862, 0x2001, 0, 0, 0, 0);
    return_to_user_prog(int);
}

bool rsod_fix()
{			
	uint8_t data;
	int ret = read_product_mode_flag(&data);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_pm_read_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(data == 0xFF)
	{
		ShowMessage("msg_pm_read_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = vtrm_manager_init();
	if(ret != CELL_OK)
	{
		ShowMessage("msg_vtrm_init_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ShowMessage("msg_vtrm_init_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	wait(2);

	return true;
}

bool patch_laidpaid_sserver2()
{
	log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets

	for(uint64_t offset = 0x60000; offset < 0x1000000; offset = offset + 4)
	{
		if(lv1_peek(offset) == 0x396B00204200FFCCULL)
		{
			if(lv1_peek(offset + 8) == 0x3860000548000010ULL)
			{
				log("Found lv1 code @0x%x\n", (int)offset);
				lv1_poke(offset+8,0x3860000048000010ULL);
				return true;
			}
		}
	}

	return false;
}

// Decrypt EID2
bool load_iso_root(void *iso_key, void *iso_iv)
{	
	CellFsStat statinfo;
	bool usb_found = false;
	char eid_root_key[120], usb[120];
	int root_fd, usb_port;
	uint64_t nread;

	sprintf_(eid_root_key, "/dev_hdd0/tmp/%s", (int)EID_ROOT_KEY_FILE_NAME);

	for(int i = 0; i < 127; i++)
	{
		sprintf_(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &statinfo))
		{
			usb_found = true;
			usb_port = i;
		}
	}

	if(usb_found)
		sprintf_(eid_root_key, "/dev_usb%03d/%s", usb_port, (int)EID_ROOT_KEY_FILE_NAME);

	int ret = cellFsOpen(eid_root_key, CELL_FS_O_RDONLY, &root_fd, 0, 0);

	if(ret != CELL_OK)	
		return false;		
	else
	{
		cellFsRead(root_fd, iso_key ,0x20, &nread );
		cellFsRead(root_fd, iso_iv, 0x10, &nread );
		cellFsClose(root_fd);
		return true;
	}
}

int get_individual_info_size(uint16_t eid_index, uint64_t *size)
{
	system_call_5(868, (uint64_t)0x17001, (uint64_t)eid_index, (uint64_t)size, 0, 0);
	return_to_user_prog(int);
}

int read_individual_info(uint64_t eid_index, void *buffer, uint64_t size, uint64_t *nread)
{
	system_call_5(868, (uint64_t)0x17002, (uint64_t)eid_index, (uint64_t)buffer, (uint64_t)size, (uint64_t)nread);
	return_to_user_prog(int);
}

bool decrypt_eid2()
{
	int ret;
	uint8_t iso_root_key[0x20];
	uint8_t iso_root_iv[0x10];
	memset(iso_root_key, 0, 0x20);
	memset(iso_root_iv, 0, 0x10);

	uint8_t eid2_indiv_seed[0x40];
	memcpy(eid2_indiv_seed, eid2_indiv_seed_, 0x40);
	
	memset(&eid2, 0, sizeof(eid2_struct));	
	
	uint64_t nread = 0;
	ret = get_individual_info_size(2, &nread);

	if(ret != CELL_OK)
	{
		// incase not patched
		if(patch_laidpaid_sserver2() == false)
		{
			ShowMessage("msg_ss_server2_error_patch", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return false;
		}
	}

	if(load_iso_root(iso_root_key, iso_root_iv) == false)
	{
		ShowMessage("msg_rootkey_not_detected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	nread = 0;
	ret = get_individual_info_size(2, &nread);

	//log("EID2 size ret: %x, ",ret); log("size: %x\n",(int)nread);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_eid2_size_get_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(nread != sizeof(eid2_struct))
	{
		ShowMessage("msg_eid2_wrong_size", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	nread = 0;
	ret = read_individual_info(2, &eid2, (uint64_t)sizeof(eid2_struct), &nread);

	//log("EID2 ret: %x\n",ret);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_eid2_get_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = AesCbcCfbEncrypt(eid2_indiv_seed, eid2_indiv_seed, 0x40, iso_root_key, 256, iso_root_iv);	// correct!
	//log_data(eid2_indiv_seed,0x40);
	//log("EID2 AES: %x\n",ret);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_eid2_create_keys_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	uint8_t eid2_key[0x20];
	uint8_t eid2_iv[0x20];
	memcpy(eid2_iv, eid2_indiv_seed + 0x10, 0x10);
	memcpy(eid2_key, eid2_indiv_seed + 0x20, 0x20);

	ret = AesCbcCfbDecrypt(&eid2.pblock_aes, &eid2.pblock_aes, sizeof(pblock_aes_struct), eid2_key, 256, eid2_iv);

	//log_data(&eid2.pblock_aes,sizeof(pblock_aes_struct));
	//log("aes decrypt EID2 P-Block: %x\n",ret);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_eid2_cant_decrypt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if( eid2.pblock_aes.pblock_hdr[0] != 1)
	{
		ShowMessage("msg_eid2_rootkey_wrong_size", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	uint64_t eid2_des_key = 0x6CCAB35405FA562CULL;
	uint64_t eid2_des_iv = 0;
    mbedtls_des_context des_ctx;
	memset(&des_ctx, 0, sizeof(mbedtls_des_context));
	mbedtls_des_setkey_dec(&des_ctx, (const unsigned char*)&eid2_des_key);
	mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, 0x70, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.pblock_aes.pblock_des), (unsigned char*)(eid2.pblock_aes.pblock_des));
	//log_data(eid2.pblock_aes.pblock_des,0x60);
	log("EID2 P-Block decrypted\n");

	ret = AesCbcCfbDecrypt(&eid2.sblock_aes, &eid2.sblock_aes, sizeof(sblock_aes_struct), eid2_key, 256, eid2_iv);

	//log_data(&eid2.sblock_aes,sizeof(sblock_aes_struct));
	//log("aes decrypt EID2 S-Block: %x\n",ret);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_eid2_error_decrypt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	eid2_des_key = 0x6CCAB35405FA562CULL;
	eid2_des_iv = 0;
	
	memset(&des_ctx, 0, sizeof(mbedtls_des_context));
	mbedtls_des_setkey_dec(&des_ctx, (const unsigned char*)&eid2_des_key);
	mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, 0x680, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.sblock_aes.sblock_des), (unsigned char*)(eid2.sblock_aes.sblock_des));
	//log_data(eid2.sblock_aes.sblock_des,0x670);
	log("EID2 S-Block decrypted\n");

	return true;
}

bool open_bdvd_device()
{
	int ret = sys_storage_open(0x101000000000006ULL, &bdvd_fd);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_sys_storage_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	log("sys_storage_open(bdvd) = %x\n", ret);	

	int indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);

	log("stg BDVD Auto Request Sense OFF returned = %x\n", ret);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_bdvd_ar_off_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	return true;
}

int sys_storage_send_atapi_command(uint32_t fd, struct lv2_atapi_cmnd_block *atapi_cmnd, uint8_t *buffer) 
{
	return sys_storage_send_device_command(fd, 1, atapi_cmnd , sizeof (struct lv2_atapi_cmnd_block), buffer, atapi_cmnd->block_size * atapi_cmnd->blocks);
}

void init_atapi_cmnd_block( struct lv2_atapi_cmnd_block *atapi_cmnd, uint32_t block_size, uint32_t proto, uint32_t type) 
{
    memset(atapi_cmnd, 0, sizeof(struct lv2_atapi_cmnd_block));
    atapi_cmnd->pktlen = 12; // 0xC
    atapi_cmnd->blocks = 1;
    atapi_cmnd->block_size = block_size; /* transfer size is block_size * blocks */
    atapi_cmnd->proto = proto;
    atapi_cmnd->in_out = type;
}

int ps3rom_lv2_read_buffer(int fd, uint8_t buffer, uint32_t length, uint8_t *data) 
{
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;
	log("ps3rom_lv2_read_buffer(%d,", (int)buffer);
	log("%x)", (int)length);
    init_atapi_cmnd_block(&atapi_cmnd, length, PIO_DATA_IN_PROTO, DIR_READ);
    atapi_cmnd.pkt[0] = 0x3C; // Read Buffer 
    atapi_cmnd.pkt[1] = 0x02; // /* mode */
    atapi_cmnd.pkt[2] = buffer;
    atapi_cmnd.pkt[3] = 0; 
    atapi_cmnd.pkt[4] = 0;
    atapi_cmnd.pkt[5] = 0;
	atapi_cmnd.pkt[6] = (length >> 16) & 0xff;
	atapi_cmnd.pkt[7] = (length >> 8) & 0xff;
	atapi_cmnd.pkt[8] = length & 0xff;
	atapi_cmnd.pkt[9] = 0x00;
    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, data);
	log(" = %x\n", res);
    return res;
}

int ps3rom_lv2_write_buffer(int fd, uint8_t buffer, uint32_t length, uint8_t *data) 
{
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;
	log("ps3rom_lv2_write_buffer(%d,", (int)buffer);
	log("%x)", (int)length);
    init_atapi_cmnd_block(&atapi_cmnd, length, PIO_DATA_OUT_PROTO, DIR_WRITE);
    atapi_cmnd.pkt[0] = 0x3B; // Read Buffer 
    atapi_cmnd.pkt[1] = 0x05; // /* mode */
    atapi_cmnd.pkt[2] = buffer;
    atapi_cmnd.pkt[3] = 0; 
    atapi_cmnd.pkt[4] = 0;
    atapi_cmnd.pkt[5] = 0;
	atapi_cmnd.pkt[6] = (length >> 16) & 0xff;
	atapi_cmnd.pkt[7] = (length >> 8) & 0xff;
	atapi_cmnd.pkt[8] = length & 0xff;
	atapi_cmnd.pkt[9] = 0x00;
    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, data);
	log(" = %x\n", res);
    return res;
}

int ps3rom_lv2_get_inquiry(int fd, uint8_t *buffer) 
{
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x3C, PIO_DATA_IN_PROTO, DIR_READ);
    atapi_cmnd.pkt[0] = 0x12;
    atapi_cmnd.pkt[1] = 0;
    atapi_cmnd.pkt[2] = 0;
    atapi_cmnd.pkt[3] = 0;
    atapi_cmnd.pkt[4] = 0x3C;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);
    return res;
}

int ps3rom_lv2_mode_sense(int fd, uint8_t *buffer)
{
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x10, PIO_DATA_IN_PROTO, DIR_READ);

    atapi_cmnd.pkt[0] = 0x5a; //GPCMD_MODE_SENSE_10;
    atapi_cmnd.pkt[1] = 0x08;
    atapi_cmnd.pkt[2] = 0x03;
    atapi_cmnd.pkt[8] = 0x10;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);
    // if (buffer[11] == 2) exec_mode_select
    return res;
}

int ps3rom_lv2_mode_select(int fd, uint8_t *buffer) 
{
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x10, PIO_DATA_OUT_PROTO, DIR_WRITE);

    atapi_cmnd.pkt[0] = 0x55; //GPCMD_MODE_SENSE_10;
	atapi_cmnd.pkt[1] = 0x10;
	atapi_cmnd.pkt[2] = 0x00;
	atapi_cmnd.pkt[3] = 0x00;
	atapi_cmnd.pkt[4] = 0x00;
	atapi_cmnd.pkt[5] = 0x00;
	atapi_cmnd.pkt[6] = 0x00;
	atapi_cmnd.pkt[7] = 0x00;
	atapi_cmnd.pkt[8] = 0x10;
	atapi_cmnd.pkt[9] = 0x00;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);    
    return res;
}

bool MODE_SELECT(uint8_t buffer_id)
{
	log("ps3rom_lv2_mode_select(%d)", (int) buffer_id);
	uint8_t data[0x10] = { 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00, 0x2D, 0x06, buffer_id, 0x00, 0x00, 0x00, 0x00, 0x00 };
	int ret = ps3rom_lv2_mode_select(bdvd_fd,data);
	log(" = %x\n", ret);
	return (ret == CELL_OK) ? true : false;
}

bool GET_bd_drive_sflash()
{	
	log("[ BD DRIVE SFLASH ]");
	uint8_t sflash_test[0x800];
	memset(sflash_test, 0, 0x800);

	int ret = ps3rom_lv2_read_buffer(bdvd_fd, 1, 0x800, sflash_test);
	log_data(sflash_test, 0x800);
	return (ret == CELL_OK) ? true : false;
}

bool CEX_drive_init_pblock()
{
	MODE_SELECT(2);

	uint8_t pblock_test[sizeof(eid2.pblock_aes.pblock_des)];
	memset(pblock_test, 0, sizeof(eid2.pblock_aes.pblock_des));

	// READ
	//int ret = ps3rom_lv2_read_buffer(bdvd_fd,2,sizeof(eid2.pblock_aes.pblock_des),pblock_test);
	//log_data(pblock_test,sizeof(eid2.pblock_aes.pblock_des));
	// WRITE
	int ret = ps3rom_lv2_write_buffer(bdvd_fd, 2, sizeof(eid2.pblock_aes.pblock_des),eid2.pblock_aes.pblock_des);
	return (ret == CELL_OK) ? true : false;
}

bool CEX_drive_init_sblock()
{
	MODE_SELECT(3);

	uint8_t sblock_test[sizeof(eid2.sblock_aes.sblock_des)];
	memset(sblock_test, 0, sizeof(eid2.sblock_aes.sblock_des));

	// READ
	//int ret = ps3rom_lv2_read_buffer(bdvd_fd,3,sizeof(eid2.sblock_aes.sblock_des),sblock_test);
	//log_data(sblock_test,sizeof(eid2.sblock_aes.sblock_des));
	// WRITE
	int ret = ps3rom_lv2_write_buffer(bdvd_fd, 3, sizeof(eid2.sblock_aes.sblock_des), eid2.sblock_aes.sblock_des);
	return (ret == CELL_OK) ? true : false;
}

bool CEX_drive_init_AACS_HRL()
{
	MODE_SELECT(4);
	
	sys_addr_t hrl;
	int ret = sys_memory_allocate(1 * 1024 * 1024, SYS_MEMORY_PAGE_SIZE_1M, &hrl);

	uint8_t data[0x54] = 
	{ 
		0x10, 0x00, 0x00, 0x0C, 0x00, 0x03, 0x10, 0x03, 0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x34,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x0B, 0xF2, 0x6D, 0x47, 0x9E, 0x77, 0x62,
		0x3D, 0x91, 0xFC, 0x78, 0xB1, 0x59, 0xC9, 0x52, 0xCA, 0xA4, 0xC7, 0x41, 0x85, 0x24, 0x96, 0x64,
		0x8D, 0x1D, 0x95, 0x8E, 0x9B, 0x84, 0xC6, 0xFA, 0x4A, 0xDD, 0x43, 0x9B, 0x42, 0x98, 0xFE, 0xFF,
		0xDF, 0xE6, 0xF3, 0x56, 0x85, 0x81, 0xE1, 0x1B, 0x27, 0x53, 0x08, 0x14, 0x16, 0x6D, 0x97, 0x3C,
		0x20, 0x2D, 0xE2, 0x97
	};

	memcpy((void*)hrl, data, 0x54);
	
	int ret2 = ps3rom_lv2_write_buffer(bdvd_fd, 4, 0x8000, (uint8_t*)hrl);
	ret = sys_memory_free(hrl);
	return (ret2 == CELL_OK) ? true : false;
}

bool CEX_drive_init()
{
	int ret;
	if( open_bdvd_device() == false)	
		return false;	
		
	// identify drive
	char inquiry[0x3C];
	memset(inquiry, 0, 0x3C);
	ret = ps3rom_lv2_get_inquiry(bdvd_fd, (uint8_t*)inquiry);
	log("Identified Drive = %s\n", (char*)(inquiry + 8));

	if( CEX_drive_init_pblock() == false)
	{
		ShowMessage("msg_cex_drive_init_pblock_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	int indata = 0;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);
	log("stg BDVD Auto Request Sense ON returned = %x\n", ret);

	if( ret != CELL_OK)
	{
		ShowMessage("msg_bdvd_ar_on_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = Authenticate_BD_Drive(0x29);
	log("Authenticate_BD_Drive(0x29) = %x\n", ret);
	if( ret != CELL_OK)
	{
		ShowMessage("msg_auth_bd_drive_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);
	log("stg BDVD Auto Request Sense OFF returned = %x\n", ret);

	if( ret != CELL_OK)
	{
		ShowMessage("msg_bdvd_ar_off_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if( CEX_drive_init_sblock() == false)
	{
		ShowMessage("msg_cex_drive_init_sblock_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	if( CEX_drive_init_AACS_HRL() == false)
	{
		ShowMessage("msg_cex_drive_init_aacs_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	return true;
}

void remarry_bd()
{	
	uint8_t data;
	int fsmret = read_product_mode_flag(&data);

	if(fsmret != CELL_OK)
	{		
		ShowMessage("msg_read_eprom_failed", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(data == 0xFF)
	{
		ShowMessage("msg_enable_fsm", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(decrypt_eid2() == false)	
		return;	

	bool ret = CEX_drive_init();
	sys_storage_close(bdvd_fd);

	if( ret == false)	
		ShowMessage("msg_cex_init_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else 	
		ShowMessage("msg_cex_init_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void toggle_devblind()
{
	int ret;
	CellFsStat stat;

	if(cellFsStat("/dev_blind", &stat) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}

		ShowMessage("msg_devblind_mounted", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
	else
	{
		ret = cellFsUtilUnMount("/dev_blind", 0);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_devblind_unmount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}

		ShowMessage("msg_devblind_unmounted", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
}

void dump_disc_key()
{
	int ret;
	int disc_type = iBdvd->GetDiscType();

	if(disc_type != BDGAME)	
		ShowMessage("msg_insert_disc", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		uint8_t discinfo[0x20];
		memset(discinfo, 0, 0x20);
		iBdvd->DoUnk17(discinfo);
		log("TitleID: %s\n", (char*)(discinfo + 0x10));

		ret = authDisc(); // auth disc, get disc profile, etc. information

		uint8_t dhk[0x10];
		memset(dhk, 0, 0x10);
		ret = getDiscHashKey(dhk); // get disc hash key

		if(ret == CELL_OK)
			log_key("disc_hash_key", dhk);	

		ShowMessage((ret == 0) ? "msg_dhk_dumped" : "msg_dhk_fail", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}
}

void control_led(const char *action)
{
	if(strcmp(action, "ledmod_s") == 0)
	{
		sys_sm_control_led(1, 0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1, 1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action, "ledmod_f_v") == 0)
	{
		sys_sm_control_led(1, 0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1, 1);
		sys_sm_control_led(2, 1);
		sys_timer_usleep(250000);
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action, "ledmod_f_z") == 0)
	{
		sys_sm_control_led(1, 0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1, 1);
		sys_sm_control_led(2, 1);
		sys_timer_usleep(850000);
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action, "ledmod_bd_an") == 0)
	{
		sys_sm_control_led(1, 0);
		sys_timer_usleep(100000);
		sys_sm_control_led(2, 1);	
		sys_timer_usleep(270000);
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 1);							
		sys_timer_sleep(2);
	}
	else if(strcmp(action, "ledmod_bd_aus") == 0)
	{
		sys_sm_control_led(1, 0);
		sys_timer_usleep(100000);
		sys_sm_control_led(2, 1);
		sys_timer_usleep(850000);
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 1);
		sys_timer_sleep(2);
	}
}

void show_idps()
{
	uint8_t idps[0x10];
	char idps_char1[120], idps_char2[120], idps_full[120];

	memset(idps, 0, 0x10);

	int ret = sys_ss_get_console_id(idps);

	if(ret == EPERM)
		ret = GetIDPS(idps);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_idps_dump_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	sprintf_(idps_char1, "%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7]);
	sprintf_(idps_char2, "%02X%02X%02X%02X%02X%02X%02X%02X", idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
	sprintf_(idps_full, "%s\n         %s", (int)idps_char1, (int)idps_char2);
	
	int string = RetrieveString("msg_idps_show", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)idps_full);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void dump_idps()
{
	uint8_t idps[0x10];
	memset(idps, 0, 0x10);

	int ret = sys_ss_get_console_id(idps);

	if(ret == EPERM)
		ret = GetIDPS(idps);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_idps_dump_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	log_key("IDPS", idps);
	ShowMessage("msg_idps_dumped", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void show_psid()
{
	uint8_t psid[0x10];
	char psid_char1[120], psid_char2[120], psid_full[120];

	memset(psid, 0, 0x10);

	int ret = sys_ss_get_open_psid(psid);

	if(ret == EPERM)
		ret = GetPSID(psid);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_psid_dump_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	sprintf_(psid_char1, "%02X%02X%02X%02X%02X%02X%02X%02X", psid[0], psid[1], psid[2], psid[3], psid[4], psid[5], psid[6], psid[7]);
	sprintf_(psid_char2, "%02X%02X%02X%02X%02X%02X%02X%02X", psid[8], psid[9], psid[10], psid[11], psid[12], psid[13], psid[14], psid[15]);
	sprintf_(psid_full, "%s\n         %s", (int)psid_char1, (int)psid_char2);
	
	int string = RetrieveString("msg_psid_show", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)psid_full);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void dump_psid()
{
	uint8_t psid[0x10];
	memset(psid, 0, 0x10);

	int ret = sys_ss_get_open_psid(psid);

	if(ret == EPERM)
		ret = GetPSID(psid);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_psid_dump_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	log_key("PSID", psid);
	ShowMessage("msg_psid_dumped", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rebuild_db()
{	
	int fd;	
	cellFsOpen("/dev_hdd0/mms/db.err", CELL_FS_O_RDWR | CELL_FS_O_CREAT, &fd, NULL, 0);

	uint64_t nrw;
	int rebuild_flag = 0x000003E9;
	cellFsWrite(fd, &rebuild_flag, 4, &nrw);
	cellFsClose(fd);

	close_xml_list();

	xmb_reboot(SYS_HARD_REBOOT);
}

static int fs_check()
{
	int ret;
	ret = cellFsUtilMount("CELL_FS_UTILITY:HDD0", "CELL_FS_SIMPLEFS", "/dev_simple_hdd0", 0, 0, 0, 0);

	if(ret != CELL_OK)
	{
		ShowMessage("msg_hdd_mount_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return ret;
	}	
	else
	{
		int fd;
		ret = cellFsOpen("/dev_simple_hdd0", CELL_FS_O_RDWR, &fd, 0, 0);

		if(ret != CELL_OK)
		{
			ShowMessage("msg_hdd_open_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return ret;
		}	
		else
		{
			uint64_t pos;
			cellFsLseek(fd, 0x10520 ,0, &pos);
	
			int buf;
			uint64_t nrw;
			cellFsRead(fd, &buf, 4, &nrw);

			buf = buf | 4;

			cellFsLseek(fd, 0x10520, 0, &pos);
			cellFsWrite(fd, &buf, 4, &nrw);
			cellFsClose(fd);
		}

		cellFsUtilUnMount("/dev_simple_hdd0", 0);

		return CELL_OK;
	}
}

int read_recovery_mode_flag(void *data)
{	
	return update_mgr_read_eprom(RECOVERY_MODE_FLAG_OFFSET, data);
}

int set_recovery_mode_flag(uint8_t value)
{
	return update_mgr_write_eprom(RECOVERY_MODE_FLAG_OFFSET, value);
}

void recovery_mode()
{
	uint8_t data;

	int ret = check_flash_type();

	close_xml_list();

	if(!ret)
	{		
		ShowMessage("msg_nand_not_supported", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	ret = read_recovery_mode_flag(&data);

	if(ret != 0)
	{
		ShowMessage("msg_read_eprom_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(data == 0xFF)
	{
		ret = set_recovery_mode_flag(0x00);
		ShowMessage((ret == 0) ? "msg_recovery_mode_enabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
		wait(3);
		xmb_reboot(SYS_HARD_REBOOT);
	}

	if(data == 0x00)
	{
		ret = set_recovery_mode_flag(0xFF);
		ShowMessage((ret == 0) ? "msg_recovery_mode_disabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
	}
}	

int read_product_mode_flag(void *data)
{
	return update_mgr_read_eprom(PRODUCT_MODE_FLAG_OFFSET, data);
}

static int set_product_mode_flag(uint8_t value)
{
	return update_mgr_write_eprom(PRODUCT_MODE_FLAG_OFFSET, value);
}

int service_mode()
{
	uint8_t data;
	int ret = read_product_mode_flag(&data);

	close_xml_list();

	if(ret != 0)
	{
		ShowMessage("msg_read_eprom_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(data == 0xFF)
	{
		log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets
		for(uint64_t offset = 0xE0000; offset < 0x1000000; offset = offset + 4)
		{
			if(lv1_peek(offset) == 0x2F8000FF409E0028ULL)
			{
				if(lv1_peek(offset + 8) == 0x880101302F8000FFULL)
				{
					log("Found lv1 code @0x%x\n", (int)offset);
					lv1_poke(offset, 0x2F8000FF48000028ULL);
					break;
				}
			}
		}

		ret = set_product_mode_flag(0x00);
		ShowMessage((ret == 0) ? "msg_pm_enabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
	}
	else if(data == 0x00)
	{
		ret = set_product_mode_flag(0xFF);
		ShowMessage((ret == 0) ? "msg_pm_disabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
	}
	else
	{
		ShowMessage("msg_eprom_unknown_flag", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	wait(2);
	return ret;
}

int filecopy(const char *src, const char *dst)
{
	int fd_src, fd_dst, ret;
	char buffer[0x1000];
	uint64_t nread, nrw;
	CellFsStat stat;		

	if(cellFsStat(src, &stat) == CELL_FS_SUCCEEDED)
	{
		cellFsChmod(src, 0666);		

		//cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);

		if(cellFsOpen(src, CELL_FS_O_RDONLY, &fd_src, 0, 0) != CELL_FS_SUCCEEDED || cellFsOpen(dst, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd_dst, 0, 0) != CELL_FS_SUCCEEDED)
		{
			cellFsClose(fd_src);
			//log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
			return 1;
		}	

		while((ret = cellFsRead(fd_src, buffer, 0x1000, &nread)) == CELL_FS_SUCCEEDED)
		{
			if((int)nread)
			{
				ret = cellFsWrite(fd_dst, buffer, nread, &nrw);

				if(ret != CELL_FS_SUCCEEDED)
				{
					cellFsClose(fd_src);
					cellFsClose(fd_dst);
					//log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));
					return 1;
				}

				memset(buffer, 0, nread);
			}
			else			
				break;			
		}

		cellFsChmod(dst, 0666);		
	}
	else
		return 1;	    
	
	cellFsClose(fd_src);
	cellFsClose(fd_dst);
	//log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount("/dev_blind", 0));

	return 0;
}

static void patch_lv1()
{
	for(uint64_t offset = 0xA000; offset < 0x900000; offset = offset + 4)
	{
		if(lv1_peek(offset) == 0x2F666C682F6F732FULL || lv1_peek(offset) == 0x2F6C6F63616C5F73ULL)
		{
			if((lv1_peek(offset + 8) == 0x6C76325F6B65726EULL && lv1_peek(offset + 16) == 0x656C2E73656C6600ULL) ||
				(lv1_peek(offset + 8) == 0x7973302F6C76325FULL && lv1_peek(offset + 16) == 0x6B65726E656C2E73ULL))
			{
				log("Found lv1 code @0x%x\n", (int)offset);
				lv1_poke(offset +  0, 0x2F6C6F63616C5F73ULL);
				lv1_poke(offset +  8, 0x7973302F6C76325FULL);
				lv1_poke(offset + 16, 0x6B65726E656C2E73ULL);
				lv1_poke(offset + 24, 0x656C660000000000ULL);

				ShowMessage("msg_kernel_loaded", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
					
				wait(2);
				cellFsUtilUnMount("/dev_blind", 0);
				xmb_reboot(SYS_LV2_REBOOT);				
				return;
			}
		}
	}

	return;
}

int loadKernel()
{
	int ret = 1;
	CellFsStat stat;

	cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_blind", 0, 0, 0, 0);	

	if(filecopy("/dev_usb000/lv2_kernel.self", "/dev_blind/lv2_kernel.self") == CELL_FS_SUCCEEDED)
		patch_lv1();
	else if(cellFsStat("/dev_flash/lv2_kernel.self", &stat) == CELL_FS_SUCCEEDED)
		patch_lv1();	

	cellFsUtilUnMount("/dev_blind", 0);

	ShowMessage("msg_kernel_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);	
	return 1;
}

void installPKG_thread()
{
	game_ext_interface = (game_ext_plugin_interface *)GetPluginInterface("game_ext_plugin", 1);

	game_ext_interface->DoUnk0();
	log("File: %s\n", pkg_path);
	game_ext_interface->DoUnk34(pkg_path);
}

void installPKG(char *path)
{
	strcpy(pkg_path, path);
	LoadPlugin("game_ext_plugin", (void*)installPKG_thread);
}

void searchDirectory(char *pDirectoryPath, char *fileformat, char *fileout)
{
    int fd;
	int ret; 
	CellFsDirent dirent;

	ret = cellFsOpendir(pDirectoryPath, &fd);
	log("cellFsOpendir(pDirectoryPath, &fd) = %x\n", ret);	

	for(int i = 0; i < 64; i++)
	{
		wait(1);
		uint64_t n;

		ret = cellFsReaddir(fd, &dirent, &n);
		log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		log(dirent.d_name); 
		log("\n");

		if(CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			if(strncmp(dirent.d_name, fileformat, strlen(fileformat)) == 0)
			{
				strcpy(fileout, pDirectoryPath);
				strcat(fileout, dirent.d_name);
				log("Fileout: %s\n", fileout);
				break;
			}
		}
	}

    ret = cellFsClosedir(fd);
	log("cellFsClosedir(fd) = %x\n", ret);
}

void applicable_version()
{
	uint8_t data[0x20];
	memset(data, 0, 0x20);

	int ret = GetApplicableVersion(data);
	if(ret != CELL_OK)
	{
		ShowMessage("msg_applicable_version_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int string = RetrieveString("msg_minimum_downgrade", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, data[1], data[3]);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void activate_account()
{
	char userID[120], accountID[120], act_path[120];
	CellFsStat stat;
	uint32_t userid = xUserGetInterface()->GetCurrentUserNumber();	

	if(!check_cobra_version())
	{
		ShowMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	sprintf_(act_path, ACT_DAT_PATH, (int)userid, NULL);
	sprintf_(userID, "%08X", userid, NULL);
	sprintf_(accountID, "/setting/user/%s/npaccount/accountid", (int)userID, NULL);

	if(cellFsStat(act_path, &stat) == CELL_FS_SUCCEEDED)
	{
		ShowMessage("msg_cobra_create_act_exist", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return;
	}

	system_call_4(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_ACTIVATE_ACOUNT, (uint64_t)accountID, (uint64_t)userID);  
	int ret = (int)(p1);

	if(!ret)
		ShowMessage("msg_cobra_enable_account_activated", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	else if(ret == 1)
		ShowMessage("msg_cobra_create_empty", (char *)XAI_PLUGIN, (char *)TEX_WARNING);		
	else
		ShowMessage("msg_cobra_enable_account_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
}

void enable_WhatsNew()
{
	char country[120];
	xUserGetInterface()->GetRegistryNpGuestCountry(country);

	if(country[0] == '\0')			
	{		
		xUserGetInterface()->SetRegistryNpGuestLang("en");
		xUserGetInterface()->SetRegistryNpGuestCountry("us");
		xUserGetInterface()->SetRegistryNpGuestBirth(0x07E50101);
		xUserGetInterface()->SetRegistryFocusMask(0x10F);
		ShowMessage("msg_whats_new_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{		
		xUserGetInterface()->SetRegistryString(xUserGetInterface()->GetCurrentUserNumber(), 0x82, "", 0);
		xUserGetInterface()->SetRegistryString(xUserGetInterface()->GetCurrentUserNumber(), 0x83, "", 0);
		xUserGetInterface()->SetRegistryValue(xUserGetInterface()->GetCurrentUserNumber(), 0x84, 0);
		xUserGetInterface()->SetRegistryFocusMask(0);
		ShowMessage("msg_whats_new_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}	
}

void download_thread(int id)
{	
	wchar_t *url_path;
	download_interface = (download_if *)GetPluginInterface("download_plugin", 1);
	download_interface->DoUnk5(0, url_path, L"/dev_hdd0"); 	
}

static void downloadPKG(wchar_t *url)
{	
	wchar_t *url_path = url;
	LoadPlugin("download_plugin", (void*)download_thread);			
}
