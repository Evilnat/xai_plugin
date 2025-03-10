/* 
 *	This file contains data for different versions of FW
 *	It is possible that support for some more may need to be added
 */

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
#include "qa.h"
#include "savegames.h"
#include "cex2dex.h"
#include "eeprom.h"


extern "C" int _videorec_export_function_video_rec(void);
extern "C" int _videorec_export_function_klicensee(void);
extern "C" int _videorec_export_function_secureid(void);
extern "C" int _videorec_export_function_sfoverride(void);

int bdvd_fd;
char pkg_path[255];
wchar_t wchar_string[360]; // Global variable for swprintf
wchar_t *url_path;

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

int aes_omac1(uint8_t *out, uint8_t *input, uint32_t length, uint8_t *key, uint32_t keybits)
{
	return cellCryptoPuAesOmac1Mode(out, input, length, key, keybits);
}

int sha1_hmac(uint8_t *hmac_hash, uint8_t *data_in, int32_t data_length, uint8_t *key, int32_t key_length)
{
	return cellCryptoPuSha1Hmac(hmac_hash, data_in, data_length, key, key_length);
}

int sha1_hmac_starts(uint64_t data[160], uint8_t *key, int32_t key_length)
{
	return cellCryptoPuSha1HmacInit(data, key, key_length);
}

int sha1_hmac_update(uint64_t data[160], uint8_t *data_in, int32_t data_length)
{
	return cellCryptoPuSha1HmacTransform(data, data_in, data_length);
}

int sha1_hmac_finish(uint8_t *hmac_hash, uint64_t data[160])
{
	return cellCryptoPuSha1HmacFinal(hmac_hash, data);
}

int sha1_hash(uint8_t *out_sha1, uint8_t *in, uint32_t length)
{
	return cellCryptoPuSha1Hash(out_sha1, in, length);
}

int verify_ecdsa(uint64_t ret, uint8_t *hash, uint8_t *public_key, uint8_t *curve)
{
	return cellCryptoPuEccEcDsaVeri(ret, hash, public_key, curve);
}

int update_mgr_read_eeprom(int offset, void *buffer)
{
	return update_mgr_read_eprom(offset, buffer);
}

int update_mgr_write_eeprom(int offset, int value)
{
	return update_mgr_write_eprom(offset, value);
}

int sys_storage_send_atapi_command(uint32_t fd, struct lv2_atapi_cmnd_block *atapi_cmnd, uint8_t *buffer) 
{
	return sys_storage_send_device_command(fd, 1, atapi_cmnd , sizeof (struct lv2_atapi_cmnd_block), buffer, atapi_cmnd->block_size * atapi_cmnd->blocks);
}

void free__(void *ptr)
{
	free_(ptr);
}

int malloc__(size_t size)
{
	return (int)malloc_(size);
}

FILE *fopen__(const char *filename, const char *mode)
{
	return fopen_(filename, mode);
}

size_t fread__(void *pointer, size_t size, size_t nmemb, FILE *stream)
{
	return (size_t)fread_(pointer, size, nmemb, stream);
}

int fclose__(FILE *stream)
{
	return fclose_(stream);
}

int memalign__(size_t boundary, size_t size_arg)
{
	return (int)memalign_(boundary, size_arg);
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

int GetIDPS(void *idps)
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
	setNIDfunc(getDiscHashKey, "vsh", 0x2B58A92C);
	setNIDfunc(authDisc, "vsh", 0xE20104BE);
	setNIDfunc(cellFsUtilityMount, "vsh", 0xE44F29F4);
	setNIDfunc(cellFsUtilUmount, "vsh", 0x33ACD759);
	setNIDfunc(cellSsAimGetDeviceId, "vsh", 0x3B4A1AC4);
	setNIDfunc(cellSsAimGetOpenPSID, "vsh", 0x9AD2E524);
	setNIDfunc(Authenticate_BD_Drive, "vsh", 0x26709B91);

	setNIDfunc(loadModule, "paf", 0xCF068D31);
	setNIDfunc(ejectDisc, "paf", 0x55F2C2A6);
	setNIDfunc(startJob, "paf", 0x350B4536);
	setNIDfunc(getLoadedPlugins, "paf", 0xAF58E756);
	setNIDfunc(FindTexture, "paf", 0x3A8454FC);
	setNIDfunc(FindPlugin, "paf", 0xF21655F3);
	setNIDfunc(GetString, "paf", 0x89B67B9C);

	setNIDfunc(cellCryptoPuAesCbcCfb128Encrypt, "sdk", 0x7B79B6C5);
	setNIDfunc(cellCryptoPuAesCbcCfb128Decrypt, "sdk", 0xB45387CD);
	setNIDfunc(cellCryptoPuAesEncKeySet, "sdk", 0xFC096B9E);	
	setNIDfunc(cellCryptoPuAesOmac1Mode, "sdk", 0x68B630D5);	
	setNIDfunc(cellCryptoPuSha1Hmac, "sdk", 0x74A2A1FE);
	setNIDfunc(cellCryptoPuSha1HmacInit, "sdk", 0x547B602C);
	setNIDfunc(cellCryptoPuSha1HmacTransform, "sdk", 0x4484A101);
	setNIDfunc(cellCryptoPuSha1HmacFinal, "sdk", 0x300B99F2);
	setNIDfunc(cellCryptoPuSha1Hash, "sdk", 0x5FAFE92B);	
	setNIDfunc(cellCryptoPuEccEcDsaVeri, "sdk", 0xB80602D2);		

	setNIDfunc(update_mgr_read_eprom, "vshmain", 0x2C563C92);
	setNIDfunc(update_mgr_write_eprom, "vshmain", 0x172B05CD);
	setNIDfunc(vshmain_74A54CBF, "vshmain", 0x74A54CBF);
	setNIDfunc(vshmain_5F5729FB, "vshmain", 0x5F5729FB);

	setNIDfunc(xBDVDGetInstance, "x3", 0x9C246A91);
	iBdvd = (xBDVD*)xBDVDGetInstance();

	setNIDfunc(xSettingRegistryGetInterface, "xsetting", 0xD0261D72);
	setNIDfunc(xSettingSystemInfoGetInterface, "xsetting", 0xAF1F161);
	setNIDfunc(xUserGetInterface, "xsetting", 0xCC56EB2D);
	setNIDfunc(xSettingBdvdGetInterface, "xsetting", 0x16A8A805);
	setNIDfunc(xSettingDateGetInterface, "xsetting", 0x8B69F85A);	

	setNIDfunc(_cellRtcGetCurrentTick, "cellRtc", 0x9DAFC0D9);	 
	setNIDfunc(_cellRtcSetCurrentTick, "cellRtc", 0xEB22BB86);	 	

	setNIDfunc(NotifyWithTexture, "vshcommon", 0xA20E43DB);	

	setNIDfunc(free_, "allocator", 0x77A602DD);
	setNIDfunc(malloc_, "allocator", 0x759E0635);
	setNIDfunc(memalign_, "allocator", 0x6137D196);
	
	setNIDfunc(wcstombs_, "stdc", 0xB680E240);
	setNIDfunc(stoull_, "stdc", 0xD417EEB5);
	setNIDfunc(fopen_, "stdc", 0x69C27C12);
	setNIDfunc(fclose_, "stdc", 0xE1BD3587);
	setNIDfunc(fprintf_, "stdc", 0xFAEC8C60);
	setNIDfunc(fread_, "stdc", 0xD40723D6);
	setNIDfunc(ctime_, "stdc", 0xBC7B4B8E);		

	setNIDfunc(sceNetCtlGetInfoVsh, "netctl_main", 0x9A528B81);	
}

int saveFile(const char *path, void *data, size_t size)
{
	int file;
	uint64_t write;	

	if(cellFsOpen(path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &file, 0, 0) != SUCCEEDED)
		return -1;

	cellFsChmod(path, 0666);

	cellFsWrite(file, data, size, &write);
	cellFsClose(file);

	return SUCCEEDED;	
}

int readfile(const char *file, uint8_t *buffer, size_t size)
{
	int fd;
	uint64_t read;

	if(cellFsOpen(file, CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
		return -1;

	if(cellFsRead(fd, buffer, size, &read) != SUCCEEDED)
		return -1;

	cellFsClose(fd);

	return SUCCEEDED;
}

int get_usb_device()
{
	char usb[120];
	CellFsStat stat;

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &stat))
			return i;
	}

	return -1;
}

int RetrieveString(const char *string, const char *plugin)
{
	int plugin_uint = FindPlugin((char*)plugin);
	int wstring = GetString(plugin_uint, string); 
	return wstring;
}

void PrintString(wchar_t *string, const char *plugin, const char *tex_icon)
{
	int teximg, dummy = 0;

	int plugin_uint = FindPlugin((char*)plugin);

	char conv_str[120];
	wcstombs_((char *)conv_str, (wchar_t *)string, 120 + 1);

	log(conv_str);
	log("\n");

	FindTexture(&teximg, plugin_uint, tex_icon);
	NotifyWithTexture(0, tex_icon, 0, &teximg, &dummy, "", "", 0, (wchar_t*)string, 0, 0, 0);	
}

void showMessage(const char *string, const char *plugin, const char *tex_icon)
{
	int teximg, dummy = 0;

	int plugin_uint = FindPlugin((char*)plugin);
	int wstring = GetString(plugin_uint, string);

	char conv_str[120];
	wcstombs_((char *)conv_str, (wchar_t *)wstring, 120 + 1);

	log(conv_str);
	log("\n");

	FindTexture(&teximg, plugin_uint, tex_icon);
	NotifyWithTexture(0, tex_icon, 0, &teximg, &dummy, "", "", 0, (wchar_t*)wstring, 0, 0, 0);	
}

int create_rifs()
{
	int fd, string, usb_port = 0;
	CellFsStat statinfo;
	uint64_t read;
	CellFsDirent dir;
	char USB[120], rap_file[120];
	char rif_file[120], contentID[36];

	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	usb_port = get_usb_device();

	if(usb_port == -1)
	{
		showMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(USB, "/dev_usb%03d/exdata", usb_port, NULL);

	sprintf_(rif_file, "/dev_hdd0/home/%08d/exdata", userID, NULL);
	if(cellFsStat(rif_file, &statinfo) != 0)
		cellFsMkdir(rif_file, 0777);

	sprintf_(rif_file, ACT_DAT_PATH, userID, NULL);
	if(cellFsStat(rif_file, &statinfo) != 0)
	{
		showMessage("msg_account_act_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
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
					showMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	

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
				showMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	

			return 0;
		}
	}

	showMessage("msg_rap_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	cellFsClosedir(fd);
	return 1;	
}

int patch_savedata()
{
	int fd, string, usb_port;
	uint64_t read;
	CellFsDirent dir;
	CellFsStat statinfo;
	char string_sfo[120], string_pfd[120];
	char USB[120], source[120];	

	usb_port = get_usb_device();

	if(usb_port == -1)
	{
		showMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}
	
	showMessage("msg_savedata_converting_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

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

			int ret = patch_savedatas(source);

			if(ret != 0)
			{
				switch(ret)
				{							
					case 1:	
						string = RetrieveString("msg_xreg_open_error", (char*)XAI_PLUGIN);	
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

	showMessage("msg_savedata_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	cellFsClosedir(fd);
	return 1;	
}

int getAccountID()
{
	int string;
	uint16_t offset = 0;
	char entry[120];

	uint8_t *dump = (uint8_t *)malloc_(XREGISTRY_FILE_SIZE);	

	if(!dump)
	{
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		return 1;
	}

	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		showMessage("msg_xreg_open_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		free_(dump);
		return 1;
	}

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	
	sprintf_(entry, "/setting/user/%08d/npaccount/accountid", userID, NULL);

	for (int i = 0; i < 0x10000 - strlen(entry); i++)
	{
		if (!strcmp((char *)dump + i, entry))	
		{
			offset = i - 0x15;

			for (int i = 0; i < 0x15000 - 2; i++)
			{      
				if (*(uint16_t *)(dump + i) == offset && *(uint8_t *)(dump + i + 4) == 0x00 && 
					*(uint8_t *)(dump + i + 5) == 0x11 && *(uint8_t *)(dump + i + 6) == 0x02)
				{
					uint32_t valueOffset = i;

					uint8_t account_id[0x10];
					char acc_char[16], output[120];

					memcpy(&account_id, (uint8_t *)(dump + (uint32_t)valueOffset + 7), 16);

					for(int i = 0; i < 16; i++)
						acc_char[i] = account_id[i];

					acc_char[0x10] = '\0';	

					if(memcmp((uint8_t *)(dump + (uint32_t)valueOffset + 7), fake_accountid, 0x10) == 0)					
					{						
						string = RetrieveString("msg_accountid_fake", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string, (int)acc_char);	
					}
					else if(memcmp((uint8_t *)(dump + (uint32_t)valueOffset + 7), empty, 0x10) == 0)		
					{				
						string = RetrieveString("msg_accountid_empty", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string);	
					}
					else			
					{		
						string = RetrieveString("msg_accountid_result", (char*)XAI_PLUGIN);
						swprintf_(wchar_string, 120, (wchar_t *)string, (int)acc_char);
					} 

					free_(dump);
					PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);	
					return 0;
				}
			}
		}
	}
		
	showMessage("msg_accountid_unable_find", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	return 1;
}

int getClockSpeeds()
{
	char rsxData[120], cpuData[120];
	char core[25], memory[25];
	uint32_t core_val, rsx_val;
	uint8_t hex[10], cpu_hex[10], rsx_hex[10];
	int mode = 0;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	showMessage("msg_rsx_clock_freq_wait", (char*)XAI_PLUGIN, (char*)TEX_INFO2);	

	for(uint64_t offset = 0x600000; offset < 0x700000; offset++)
	{
		if(lv1_peek32(offset) == 0x7670653A && (lv1_peek32(offset + 7) == 0x7368643A || lv1_peek32(offset + 8) == 0x7368643A))
		{
			if(lv1_peek8(offset - 5) == 0x2F || lv1_peek8(offset - 6) == 0x2F)
			{
				if(lv1_peek8(offset - 10) == 0x20 && lv1_peek8(offset - 6) == 0x2F && lv1_peek8(offset - 1) == 0x20)
				{
					mode = 2;
					core_val = lv1_peek32(offset - 9);
					rsx_val = lv1_peek32(offset - 5);
					break;	
				}
				else if(lv1_peek8(offset - 10) == 0x20 && lv1_peek8(offset - 5) == 0x2F && lv1_peek8(offset - 1) == 0x20)
				{
					mode = 4;
					core_val = lv1_peek32(offset - 9);
					rsx_val = lv1_peek32(offset - 4);
					break;	
				}
				else if(lv1_peek8(offset - 11) == 0x20 && lv1_peek8(offset - 1) == 0x20 && lv1_peek8(offset - 6) == 0x2F)
				{
					mode = 3;
					core_val = lv1_peek32(offset - 10);
					rsx_val = lv1_peek32(offset - 5);
					break;	
				}
				else
				{
					mode = 1;
					core_val = lv1_peek32(offset - 8);
					rsx_val = lv1_peek32(offset - 4);
					break;	
				}		
			}
		}
	}

	if(!core_val || !rsx_val)
	{
		showMessage("msg_clock_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	memcpy(cpu_hex, &core_val, 4);
	memcpy(rsx_hex, &rsx_val, 4);

	for(int i = 0; i < 4; i++)
	{
      sprintf_(&cpuData[i], "%c", cpu_hex[i]);
	  sprintf_(&rsxData[i], "%c", rsx_hex[i]);
	}

	strncpy(core, cpuData, (mode == 3 ? 4 : mode == 4 ? 4 : 3));
	strncpy(memory, rsxData, (mode == 2 ? 4 : mode == 3 ? 4 : 3));

	int string = RetrieveString("msg_clock_speeds", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)core, (int)memory);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	return 0;
}

void changeAccountID(int mode, int force)
{
	if(force)
		close_xml_list();

	int ret = set_accountID(mode, force);	

	if(!ret)
	{
		if(mode == EMPTY)
			showMessage("msg_accountid_set_empty", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			
		else
			showMessage("msg_accountid_set_fake", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

		wait(3);
		rebootXMB(SYS_HARD_REBOOT);
	}
	else if(ret == 1)		
		showMessage("msg_accountid_not_empty", (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	else if(ret == 2)
		showMessage("msg_accountid_error_autologin", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else if(ret == 3)
		showMessage("msg_xreg_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	else
		showMessage("msg_accountid_unable_find", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
}

void backup_license()
{
	int fda, fdb, usb_port;
	char backup[120], act[120];
	CellFsStat stat;

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(act, ACT_DAT_PATH, userID, NULL);

	if(cellFsStat(act, &stat) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_account_act_not_found",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);	
		return;
	}

	usb_port = get_usb_device();

	if(usb_port == -1)
		sprintf_(backup, "/dev_hdd0/tmp/act.dat", NULL, NULL);	
	else
		sprintf_(backup, "/dev_usb%03d/act.dat", usb_port, NULL);

	uint8_t buf[0x1038];
	uint64_t nr, nrw;

	if(cellFsOpen(act, CELL_FS_O_RDONLY, &fda, 0, 0) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(cellFsOpen(backup, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fdb, 0, 0) != CELL_FS_SUCCEEDED)	
	{
		cellFsClose(fda);
		showMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);	
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
			showMessage("msg_act_backup_error",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);					
	}
	else
		showMessage("msg_act_unable_read",  (char *)XAI_PLUGIN, (char*)TEX_ERROR);		

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
			showMessage("msg_account_act_deleted", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
		else
			showMessage("msg_account_act_delete_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	}
	else
		showMessage("msg_account_act_not_found", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	
}

int create_syscalls()
{
	CellFsStat stat;
	uint64_t offset;

	create_cfw_syscalls();

	system_call_2(808, (uint64_t)"/dev_flash/vsh/module/software_update_plugin.sprx", (uint64_t)&stat);

	if(!checkSyscalls(LV2))
		showMessage("msg_create_syscalls_ok", (char *)XAI_PLUGIN, (char*)TEX_SUCCESS);
	else
		showMessage("msg_create_syscalls_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);

    return 0;
}

int dump_lv(int lv)
{
	int final_offset, ret;
	int mem = 0, max_offset = 0x40000;
	int fd, usb_port, fseek_offset = 0, start_offset = 0;

	char dump_file_path[120], lv_file[120];
	const char *dumping, *lv_dump, *lv_dumped, *lv_error;

	uint8_t platform_info[0x18];
	uint64_t nrw, seek, offset_dumped;
	CellFsStat st;	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
    system_call_1(387, (uint64_t)platform_info);

	if(lv == LV2)
	{
		ret = checkSyscalls(LV2);
		final_offset = 0x800000ULL;
		dumping = "msg_lv2_dumping";	
		lv_dumped = "msg_lv2_dumped";
		lv_error = "msg_lv2_dump_error";
		lv_dump = LV2_DUMP;
	}
	else if(lv == LV1)
	{
		ret = checkSyscalls(LV1);
		final_offset = 0x1000000ULL;
		dumping = "msg_lv1_dumping";	
		lv_dumped = "msg_lv1_dumped";
		lv_error = "msg_lv1_dump_error";
		lv_dump = LV1_DUMP;
	}
	else if(lv == RAM)
	{
		ret = checkSyscalls(LV1);
		final_offset = 0x10000000ULL;
		dumping = "msg_full_ram_dumping";	
		lv_dumped = "msg_full_ram_dumped";
		lv_error = "msg_full_ram_dump_error";
		lv_dump = RAM_DUMP;
	}
	else
		return 0;	

	if(ret)
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	sprintf_(lv_file, lv_dump, platform_info[0], platform_info[1], platform_info[2] >> 4);	
	sprintf_(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(dump_file_path, "/dev_usb%03d/%s", (int)usb_port, (int)lv_file);

	if(cellFsOpen(dump_file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
	{
		showMessage(lv_error, (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	cellFsChmod(dump_file_path, 0666);

	showMessage(dumping, (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	// Quickest method to dump LV2 and LV1 through xai_plugin
	// Default method will take at least two minutes to dump LV2, and even more for LV1
	uint8_t *dump = (uint8_t *)malloc_(0x40000);

	if(!dump)
	{
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
	memset(dump, 0, 0x40000);			

	for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
	{
		if(lv == LV2)
			offset_dumped = lv2_peek(0x8000000000000000ULL + offset);
		else
			offset_dumped = lv1_peek(0x8000000000000000ULL + offset);

		memcpy(dump + mem, &offset_dumped, 8);

		mem += 8;

		if(offset == max_offset - 8)
		{
			//cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, dump, 0x40000, &nrw) != SUCCEEDED)
			{
				free_(dump);				
				cellFsClose(fd);
				cellFsUnlink(dump_file_path);
				showMessage(lv_error, (char *)XAI_PLUGIN, (char *)TEX_ERROR);				

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
	buzzer(SINGLE_BEEP);

	return 0;
}

int dumpERK(int mode)
{
	uint32_t firmware;
	check_firmware(&firmware);

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	if(firmware < 0x4080)
	{
		showMessage("msg_unsupported_firmware", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	if(checkSyscalls(LV2) || checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return -1;
	}

	showMessage((mode == ERK ? "msg_dumping_erk" : "msg_dumping_metldr"), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	dumperk(mode);	
}

//	From sguerrini97's dump_sysrom
//	https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/dump_sysrom/source
int dump_sysrom()
{
	char file[120], usb_file[120];
	int string;
	int fd, fd_usb, usb_port;

	CellFsStat stat;
	uint8_t *dump = NULL;	
	uint64_t off, val, nrw;	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(check_flash_type())
	{
		showMessage("msg_dump_sysrom_not_supported", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	showMessage("msg_dump_sysrom_dumping", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	sprintf_(file, "/dev_hdd0/tmp/SYSROM.bin", NULL, NULL);

	if(cellFsOpen(file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)	
		goto error;

	for(off = DUMP_OFFSET; off < DUMP_OFFSET + DUMP_SIZE; off += 8) 
	{
		val = lv1_peek(off);

		if(cellFsWrite(fd, &val, 8, &nrw) != CELL_FS_SUCCEEDED)
			goto error;	
	}

	// Copy to USB if it is detected	
	usb_port = get_usb_device();

	if(usb_port != -1)
	{
		uint64_t nr, seek;

		sprintf_(usb_file, "/dev_usb%03d/SYSROM.bin", usb_port, NULL);

		if(cellFsOpen(usb_file, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd_usb, 0, 0) != CELL_FS_SUCCEEDED)		
			goto error;	

		cellFsChmod(usb_file, 0666);

		dump = (uint8_t *)malloc__(0x40000);

		if(!dump)
			goto error;	

		memset(dump, 0, 0x40000);

		cellFsLseek(fd, 0, SEEK_SET, &seek);

		if(cellFsRead(fd, dump, 0x40000, &nr) != CELL_FS_SUCCEEDED)
		{
			free__(dump);				
			goto error;
		}		

		if(cellFsWrite(fd_usb, dump, 0x40000, &nrw) != SUCCEEDED)
		{
			free__(dump);				
			goto error;
		}

		free__(dump);
		cellFsClose(fd_usb);
		cellFsUnlink(file);
	}

	cellFsClose(fd);
	string = RetrieveString("msg_dump_sysrom_dump_success", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(usb_port != -1 ? usb_file : file));	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	buzzer(SINGLE_BEEP);
	return 0;

error:
	cellFsClose(fd);
	cellFsClose(fd_usb);

	if(cellFsStat(file, &stat) == CELL_FS_SUCCEEDED)
		cellFsUnlink(file);

	if(cellFsStat(usb_file, &stat) == CELL_FS_SUCCEEDED)
		cellFsUnlink(usb_file);

	showMessage("msg_dump_sysrom_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
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
			showMessage("msg_hf_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
            return 1;
		}
        
        user_id++; 
    }

	uint64_t syscall_not_impl = lv2_peek(SYSCALL_TABLE);

	if(syscall_not_impl == DISABLED)
	{
		showMessage("msg_syscalls_already_disabled", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return 1;
	}

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
		lv2_poke(SYSCALL_TABLE + 8 * syscalls[i], syscall_not_impl);

	if(!checkSyscalls(LV2))
	{
		showMessage("msg_syscalls_disabling_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 1;
	}		

	showMessage("msg_syscalls_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void checkSyscall(int syscall)
{
	int ret = 1;

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_SYSCALL, syscall);
	ret = (int)(p1);

	if(!ret)
		showMessage("msg_syscall8_status_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	else
		showMessage("msg_syscall8_status_disabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

int set_qa(int value)
{
	int ret = 0;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	ret = set_qa_flag(value);

	if(ret != 0)
	{
		switch(ret)
		{
			case 1:
				showMessage("msg_idps_not_valid", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 2:
				showMessage("msg_error_allocate_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 3:
				showMessage("msg_error_map_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			case 4:
				showMessage("msg_error_write_uart", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
			default:
				showMessage("msg_error_unexpected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				break;
		};

		return 1;
	}

	showMessage((!value) ? "msg_qa_toggle_disabled" : "msg_qa_toggle_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	return 0;
}

void show_cobra_info()
{
	int syscall8, external_cobra, ret = 1;
	char fw_type[16], buffer[20];	
	char cobra_stage[120];
	char conv_str_syscall8[120], conv_str_ext_cobra[120];
	uint16_t cobra_version = check_cobra_version();	
	CellFsStat statinfo;

	if(!cobra_version)
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	strcpy(cobra_stage, "-");

	{ system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_FW_TYPE, (uint64_t)fw_type); }

	{ 
		system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_SYSCALL, 8);
		ret = (int)(p1); 
	}	

	if(!ret)
		syscall8 = RetrieveString("msg_enabled", (char*)XAI_PLUGIN);
	else
		syscall8 = RetrieveString("msg_disabled", (char*)XAI_PLUGIN);
	
    if((cobra_version & 0x0F) == 0)
        sprintf_(buffer, "%X.%X", cobra_version >> 8, (cobra_version & 0xFF) >> 4);
    else
        sprintf_(buffer, "%X.%02X", cobra_version >> 8, (cobra_version & 0xFF));	
	
	uint64_t fw_version = get_cobra_fw_version();	
	unsigned char *bytes = (unsigned char*)&fw_version;

	if(!strcmp(fw_type, "CEX COBRA") || !strcmp(fw_type, "CEX MAMBA"))
	{
		if((cellFsStat("/dev_flash/sys/stage2.cex.release", &statinfo) == CELL_OK && cellFsStat("/dev_flash/sys/stage2.cex.debug", &statinfo) != CELL_OK) ||
			(cellFsStat("/dev_flash/sys/stage2.bin.release", &statinfo) == CELL_OK && cellFsStat("/dev_flash/sys/stage2.bin.debug", &statinfo) != CELL_OK))
			strcpy(cobra_stage, "Debug");
		else
			strcpy(cobra_stage, "Release");
	}
	else if(!strcmp(fw_type, "DEX COBRA") || !strcmp(fw_type, "DEX MAMBA"))
	{
		if((cellFsStat("/dev_flash/sys/stage2.dex.release", &statinfo) == CELL_OK && cellFsStat("/dev_flash/sys/stage2.dex.debug", &statinfo) != CELL_OK) ||
			(cellFsStat("/dev_flash/sys/stage2.bin.release", &statinfo) == CELL_OK && cellFsStat("/dev_flash/sys/stage2.bin.debug", &statinfo) != CELL_OK))
			strcpy(cobra_stage, "Debug");
		else
			strcpy(cobra_stage, "Release");
	}

	if(cellFsStat(COBRA_USB_FLAG2, &statinfo) == CELL_FS_SUCCEEDED)
		external_cobra = RetrieveString("msg_enabled", (char*)XAI_PLUGIN);
	else
		external_cobra = RetrieveString("msg_disabled", (char*)XAI_PLUGIN);

	wcstombs_((char *)conv_str_syscall8, (wchar_t *)syscall8, 120 + 1);
	wcstombs_((char *)conv_str_ext_cobra, (wchar_t *)external_cobra, 120 + 1);

	int string = RetrieveString("msg_cobra_info", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 360, (wchar_t*)string, (uint64_t)fw_type, (int)buffer, (int)cobra_stage, bytes[6], bytes[7], (int)conv_str_syscall8, (int)conv_str_ext_cobra);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

int save_ps2_fan_cfg(int mode)
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
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
			showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return 1;
		}		
	}

	cobra_read_config(cobra_config);
	cobra_config->fan_speed = mode;   
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_FAN_SPEED, mode);

	return 0;
}

void allow_restore_sc()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->allow_restore_sc = !cobra_config->allow_restore_sc;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_ALLOW_RESTORE_SYSCALLS, (int)cobra_config->allow_restore_sc);

	showMessage(((int)cobra_config->allow_restore_sc) ? "msg_syscalls_restore_enabled" : "msg_syscalls_restore_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void skip_existing_rif()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->skip_existing_rif = !cobra_config->skip_existing_rif;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SKIP_EXISTING_RIF, (int)cobra_config->skip_existing_rif);

	showMessage(((int)cobra_config->skip_existing_rif) ? "msg_skip_rif_enabled" : "msg_skip_rif_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toogle_PS2_disc_icon()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->color_disc = !cobra_config->color_disc;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SWAP_PS2_ICON_COLOR, (int)cobra_config->color_disc);

	showMessage(((int)cobra_config->color_disc) ? "msg_ps2_disc_blue" : "msg_ps2_disc_default", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toggle_ofw_mode()
{
	uint8_t value = 0;
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);

	value = cobra_config->syscalls_mode + 1;

	if(value > 2)
		value = 0;

	// Allow syscalls to be restored automatically
	cobra_config->allow_restore_sc = 1;
	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_ALLOW_RESTORE_SYSCALLS, (int)cobra_config->allow_restore_sc);

	cobra_config->syscalls_mode = value;
    cobra_write_config(cobra_config);
	
	if(!value)
		showMessage("msg_ofw_mode_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	else if(value == 1)
		showMessage("msg_ofw_mode_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	else if(value == 2)
		showMessage("msg_ofw_mode_partial_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toggle_gameboot()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->gameboot_mode = !cobra_config->gameboot_mode;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GAMEBOOT, (int)cobra_config->gameboot_mode);

	showMessage(((int)cobra_config->gameboot_mode) ? "msg_gameboot_enabled" : "msg_gameboot_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toggle_epilepsy_warning()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->epilepsy_warning = !cobra_config->epilepsy_warning;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_EPILEPSY_WARNING, (int)cobra_config->epilepsy_warning);

	showMessage(((int)cobra_config->epilepsy_warning) ? "msg_epilepsy_warning_enabled" : "msg_epilepsy_warning_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toggle_coldboot_animation()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->coldboot_mode = !cobra_config->coldboot_mode;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_COLDBOOT, (int)cobra_config->coldboot_mode);

	showMessage(((int)cobra_config->coldboot_mode) ? "msg_coldboot_animation_disabled" : "msg_coldboot_animation_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void toggle_hidden_trophy_patch()
{
	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	cobra_read_config(cobra_config);
	cobra_config->hidden_trophy_mode = !cobra_config->hidden_trophy_mode;
    cobra_write_config(cobra_config);

	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_TROPHY, (int)cobra_config->hidden_trophy_mode);

	showMessage(((int)cobra_config->hidden_trophy_mode) ? "msg_hidden_trophy_disabled" : "msg_hidden_trophy_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
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
	showMessage((ret == CELL_OK) ? "msg_logfile_cleaned" : "msg_logfile_error", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
}

void log_klic()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_klicensee();
	showMessage((ret == CELL_OK) ? "msg_klicensee_enabled" : "msg_klicensee_disabled", (char*)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void log_secureid()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_secureid();
	showMessage((ret == CELL_OK) ? "msg_secureid_enabled" : "msg_secureid_disabled", (char*)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void enable_recording()
{	
	int ret = -1;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_video_rec();
	showMessage((ret == CELL_OK) ? "msg_gameplay_recording_enabled" : "msg_gameplay_recording_disabled", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
}

void enable_screenshot()
{
	setNIDfunc(plugin_SetInterface2, "paf", 0x3F7CB0BF);

	((int*)getNIDfunc("vshmain", 0x981D7E9F))[0] -= 0x2C;
	showMessage("msg_screenshots_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}		

void override_sfo()
{	
	int ret;
	ret = load_video_rec_plugin();
	
	ret = _videorec_export_function_sfoverride();
	showMessage((ret == CELL_OK) ? "msg_sfo_override_enabled" : "msg_sfo_override_disabled", (char*)XAI_PLUGIN, (ret == CELL_OK) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);

	ejectDisc(); // drive unload
}

int toggle_coldboot()
{
	CellFsStat stat, stat_usb;
	int ret, found_external_colboot = 0, fd;	
	char usb_file[120];
	uint64_t read;

	const char *coldboot_usb = "/dev_usb%03d/coldboot.raf";
	const char *coldboot_file = "/dev_blind/vsh/resource/coldboot.raf";
	const char *coldboot_original = "/dev_blind/vsh/resource/coldboot.raf.ori";
	const char *coldboot_modded = "/dev_blind/vsh/resource/coldboot.raf.mod";

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	for(int i = 0; i < 127; i++)
	{				
		sprintf_(usb_file, coldboot_usb, i);

		if(!cellFsStat(usb_file, &stat_usb))
		{
			log(usb_file);
			found_external_colboot = 1;
			break;
		}
	}

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	if(found_external_colboot)
	{		
		if(cellFsOpen(usb_file, CELL_FS_O_RDONLY, &fd, 0, 0) == CELL_FS_SUCCEEDED)
		{			
			void *buffer = malloc_(stat_usb.st_size);

			if(buffer)
			{
				cellFsRead(fd, buffer, stat_usb.st_size, &read);

				if(saveFile((cellFsStat(coldboot_original, &stat) == CELL_FS_SUCCEEDED ? coldboot_file : coldboot_modded), buffer, stat_usb.st_size) != CELL_FS_SUCCEEDED)
				{
					showMessage("msg_external_coldboot_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
					free_(buffer);
					cellFsClose(fd);
					return 1;
				}

				free_(buffer);
				cellFsClose(fd);
				showMessage("msg_external_coldboot_success", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
				return 0;
			}
		}

		showMessage("msg_external_coldboot_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	}
	else
	{
		// Check if colboot.raf.ori exists and swap it
		if(cellFsStat(coldboot_original, &stat) == CELL_OK)
		{
			ret = cellFsRename(coldboot_file, coldboot_modded);
			if(ret != CELL_OK)			
				showMessage("msg_raf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
			
			ret = cellFsRename(coldboot_original, coldboot_file);				
			if(ret != CELL_OK)	
				showMessage("msg_raf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
		} 
		// Check if colboot.raf.mod exists and swap it
		else if(cellFsStat(coldboot_modded, &stat) == CELL_OK)
		{
			ret = cellFsRename(coldboot_file, coldboot_original);
			if(ret != CELL_OK)					
				showMessage("msg_raf_swap_ori_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			

			ret = cellFsRename(coldboot_modded, coldboot_file);
			if(ret != CELL_OK)	
				showMessage("msg_raf_swap_mod_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		}	
		else	
		{
			cellFsUtilUnMount(DEV_BLIND, 0);
			showMessage("msg_no_coldboot_detected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}

		cellFsUtilUnMount(DEV_BLIND, 0);
		showMessage((cellFsStat("/dev_flash/vsh/resource/coldboot.raf.ori", &stat) == CELL_OK) ? "msg_mod_coldboot_enabled" : "msg_ori_coldboot_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	
	return 0;
}

void button_assignment()
{
	int button;
	xSettingSystemInfoGetInterface()->GetEnterButtonAssign(&button);

	button = !button;

	xSettingSystemInfoGetInterface()->SetEnterButtonAssign(button);

	showMessage((button) ? "msg_button_accept_x" : "msg_button_accept_o", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
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
		showMessage("msg_dlna_set_flag_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		Job_start(0,(dlna == 1) ? handler1_enabled : handler1_disabled, 0, -1, -1, handler2);
		explore_interface->DoUnk6("reload_category photo", 0, 0);
		explore_interface->DoUnk6("reload_category music", 0, 0);
		explore_interface->DoUnk6("reload_category video", 0, 0);
		showMessage((dlna == 1) ? "msg_dlna_enabled" : "msg_dlna_disabled", (char*)XAI_PLUGIN, (dlna == 1) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
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
	int ret = update_mgr_read_eeprom(0x48CF0, &data);

	if(ret != 0)
	{
		showMessage("msg_read_eprom_failed", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(data == 0xFF)
	{
		ret = update_mgr_write_eeprom(0x48CF0, 0x00);

		for(int i = 0x48CF1; i < 0x48D00; i++)		
			ret = update_mgr_write_eeprom(i, 0xCC);			
		
		showMessage((ret == 0) ? "msg_hvproc_enabled" : "msg_write_eprom_failed", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}

	if(data == 0x00)
	{
		ret = update_mgr_write_eeprom(0x48CF0, 0xFF);

		for(int i = 0x48CF1; i < 0x48D00; i++)		
			ret = update_mgr_write_eeprom(i, 0xFF);			
		
		showMessage((ret == 0) ? "msg_hvproc_disabled" : "msg_write_eprom_failed", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}

	wait(2);
	return (ret == 0) ? true : false;
}

void backup_registry()
{
	int ret, usb_port;
	CellFsStat sb;
	ret = cellFsStat("/dev_flash2", &sb);

	if(ret != CELL_OK)
	{
		log("mount(dev_flash2)\n");
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH2", "CELL_FS_FAT", "/dev_flash2", 0, 0, 0, 0);

		if(ret != CELL_OK)		
		{
			showMessage("msg_devflash2_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}
	}	

	int fda;
	ret = cellFsOpen(XREGISTRY_FILE, CELL_FS_O_RDONLY, &fda, 0, 0);

	if(ret != CELL_OK)	
	{
		showMessage("msg_xreg_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	int fdb;
	char backup[120], output[120];

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(backup, "/dev_usb%03d/xRegistry.sys", usb_port, NULL);
	else
		sprintf_(backup, "/dev_hdd0/tmp/xRegistry.sys", NULL, NULL);
		
	ret = cellFsOpen(backup, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fdb, 0, 0);	
	
	if(ret != CELL_OK)
	{
		showMessage("msg_xregistry_backup_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);			
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
	int usb_port;

	usb_port = get_usb_device();
	sprintf_(usb, "/dev_usb%03d", usb_port, NULL);

	if(usb_port == -1)
	{
		showMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
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
		if( lv2_peek(i) == 0x0101000000000009ULL)
		{
			Start = i - 0x3000;
			log("Found value @: %08x", (int)(Start >> 32)); 
			log("%08x\n", (int)Start);
			i = 0x80000000003D0000ULL;
		}
	}

	// Jailcrab code
	for (Current = Start; Current < Stop; Current = Current + 4)
	{
		Data = lv2_peek(Current);

		//Flash -> FlashO
		//HDD   -> Flash
		//USB   -> HDD
		if (Data == dev_flash)
		{
			log("Found dev_flash @: %08x", (int)(Current >> 32)); 
			log("%08x\n", (int)Current);
			lv2_poke(Current, dev_flashO);
		}

		if ((Data == dev_usb000) || (Data == dev_usb001) || (Data == dev_usb002) || (Data == dev_usb003) || (Data == dev_usb004) || (Data == dev_usb005) || (Data == dev_usb006))
		{
			log("Found dev_usb @: %08x", (int)(Current >> 32)); 
			log("%08x\n", (int)Current);
			lv2_poke(Current,dev_flash);
			Current = Stop;
		}
	}
	
	showMessage("msg_fw_load_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
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
		showMessage("msg_pm_read_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(data == 0xFF)
	{
		showMessage("msg_pm_read_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = vtrm_manager_init();
	if(ret != CELL_OK)
	{
		showMessage("msg_vtrm_init_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	showMessage("msg_vtrm_init_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
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
	char eid_root_key[120];
	int root_fd, usb_port;
	uint64_t nread;	

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(eid_root_key, "/dev_usb%03d/%s", usb_port, (int)EID_ROOT_KEY_FILE_NAME);
	else
		sprintf_(eid_root_key, "/dev_hdd0/tmp/%s", (int)EID_ROOT_KEY_FILE_NAME);
	
	int ret = cellFsOpen(eid_root_key, CELL_FS_O_RDONLY, &root_fd, 0, 0);

	if(ret != CELL_OK)	
		return false;		
	else
	{
		cellFsRead(root_fd, iso_key, 0x20, &nread);
		cellFsRead(root_fd, iso_iv, 0x10, &nread);
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
			showMessage("msg_ss_server2_error_patch", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return false;
		}
	}

	if(load_iso_root(iso_root_key, iso_root_iv) == false)
	{
		showMessage("msg_rootkey_not_detected", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	nread = 0;
	ret = get_individual_info_size(2, &nread);

	if(ret != CELL_OK)
	{
		showMessage("msg_eid2_size_get_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if(nread != sizeof(eid2_struct))
	{
		showMessage("msg_eid2_wrong_size", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	nread = 0;
	ret = read_individual_info(2, &eid2, (uint64_t)sizeof(eid2_struct), &nread);

	if(ret != CELL_OK)
	{
		showMessage("msg_eid2_get_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = AesCbcCfbEncrypt(eid2_indiv_seed, eid2_indiv_seed, 0x40, iso_root_key, 256, iso_root_iv);	// correct!

	if(ret != CELL_OK)
	{
		showMessage("msg_eid2_create_keys_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	uint8_t eid2_key[0x20];
	uint8_t eid2_iv[0x20];
	memcpy(eid2_iv, eid2_indiv_seed + 0x10, 0x10);
	memcpy(eid2_key, eid2_indiv_seed + 0x20, 0x20);

	ret = AesCbcCfbDecrypt(&eid2.pblock_aes, &eid2.pblock_aes, sizeof(pblock_aes_struct), eid2_key, 256, eid2_iv);

	if(ret != CELL_OK)
	{
		showMessage("msg_eid2_cant_decrypt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if( eid2.pblock_aes.pblock_hdr[0] != 1)
	{
		showMessage("msg_eid2_rootkey_wrong_size", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	uint64_t eid2_des_key = 0x6CCAB35405FA562CULL;
	uint64_t eid2_des_iv = 0;
    mbedtls_des_context des_ctx;
	memset(&des_ctx, 0, sizeof(mbedtls_des_context));
	mbedtls_des_setkey_dec(&des_ctx, (const unsigned char*)&eid2_des_key);
	mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, 0x70, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.pblock_aes.pblock_des), (unsigned char*)(eid2.pblock_aes.pblock_des));
	log("EID2 P-Block decrypted\n");

	ret = AesCbcCfbDecrypt(&eid2.sblock_aes, &eid2.sblock_aes, sizeof(sblock_aes_struct), eid2_key, 256, eid2_iv);

	if(ret != CELL_OK)
	{
		showMessage("msg_eid2_error_decrypt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	eid2_des_key = 0x6CCAB35405FA562CULL;
	eid2_des_iv = 0;
	
	memset(&des_ctx, 0, sizeof(mbedtls_des_context));
	mbedtls_des_setkey_dec(&des_ctx, (const unsigned char*)&eid2_des_key);
	mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, 0x680, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.sblock_aes.sblock_des), (unsigned char*)(eid2.sblock_aes.sblock_des));
	log("EID2 S-Block decrypted\n");

	return true;
}

bool open_bdvd_device()
{
	int ret = sys_storage_open(0x101000000000006ULL, &bdvd_fd);
	if(ret != CELL_OK)
	{
		showMessage("msg_sys_storage_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	log("sys_storage_open(bdvd) = %x\n", ret);	

	int indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);

	log("stg BDVD Auto Request Sense OFF returned = %x\n", ret);
	if(ret != CELL_OK)
	{
		showMessage("msg_bdvd_ar_off_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	return true;
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
		showMessage("msg_cex_drive_init_pblock_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	int indata = 0;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);
	log("stg BDVD Auto Request Sense ON returned = %x\n", ret);

	if( ret != CELL_OK)
	{
		showMessage("msg_bdvd_ar_on_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	ret = Authenticate_BD_Drive(0x29);
	log("Authenticate_BD_Drive(0x29) = %x\n", ret);
	if( ret != CELL_OK)
	{
		showMessage("msg_auth_bd_drive_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30, &indata, 4, 0, 0);
	log("stg BDVD Auto Request Sense OFF returned = %x\n", ret);

	if( ret != CELL_OK)
	{
		showMessage("msg_bdvd_ar_off_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	if( CEX_drive_init_sblock() == false)
	{
		showMessage("msg_cex_drive_init_sblock_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
	
	if( CEX_drive_init_AACS_HRL() == false)
	{
		showMessage("msg_cex_drive_init_aacs_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}

	return true;
}

void remarry_bd()
{	
	uint8_t data;
	int fsmret = read_product_mode_flag(&data);

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(fsmret != CELL_OK)
	{		
		showMessage("msg_read_eprom_failed", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(data == 0xFF)
	{
		showMessage("msg_enable_fsm", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(decrypt_eid2() == false)	
		return;	

	bool ret = CEX_drive_init();
	sys_storage_close(bdvd_fd);

	if(ret == false)	
		showMessage("msg_cex_init_fail", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else 	
		showMessage("msg_cex_init_ok", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void toggle_devblind()
{
	int ret;
	CellFsStat stat;

	if(cellFsStat(DEV_BLIND, &stat) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

		if(ret != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}

		showMessage("msg_devblind_mounted", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
	else
	{
		ret = cellFsUtilUnMount(DEV_BLIND, 0);

		if(ret != CELL_OK)
		{
			showMessage("msg_devblind_unmount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}

		showMessage("msg_devblind_unmounted", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
}

void dump_disc_key()
{
	int ret;
	int disc_type = iBdvd->GetDiscType();

	if(disc_type != BDGAME)	
		showMessage("msg_insert_disc", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
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

		showMessage((ret == 0) ? "msg_dhk_dumped" : "msg_dhk_fail", (char*)XAI_PLUGIN, (ret == 0) ? (char*)TEX_SUCCESS : (char*)TEX_ERROR);
	}
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

	rebootXMB(SYS_LV2_REBOOT);
}

static int fs_check()
{
	int ret;
	ret = cellFsUtilMount("CELL_FS_UTILITY:HDD0", "CELL_FS_SIMPLEFS", "/dev_simple_hdd0", 0, 0, 0, 0);

	if(ret != CELL_OK)
	{
		showMessage("msg_hdd_mount_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return ret;
	}	
	else
	{
		int fd;
		ret = cellFsOpen("/dev_simple_hdd0", CELL_FS_O_RDWR, &fd, 0, 0);

		if(ret != CELL_OK)
		{
			showMessage("msg_hdd_open_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return ret;
		}	
		else
		{
			uint64_t pos;
			cellFsLseek(fd, 0x10520, 0, &pos);
	
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
		showMessage("msg_nand_not_supported", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	ret = read_recovery_mode_flag(&data);

	if(ret != 0)
	{
		showMessage("msg_read_eprom_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(data == 0xFF)
	{
		ret = set_recovery_mode_flag(0x00);
		showMessage((ret == 0) ? "msg_recovery_mode_enabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
		wait(3);
		rebootXMB(SYS_HARD_REBOOT);
	}

	if(data == 0x00)
	{
		ret = set_recovery_mode_flag(0xFF);
		showMessage((ret == 0) ? "msg_recovery_mode_disabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
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

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	close_xml_list();

	if(ret != 0)
	{
		showMessage("msg_read_eprom_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
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
		showMessage((ret == 0) ? "msg_pm_enabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
	}
	else if(data == 0x00)
	{
		ret = set_product_mode_flag(0xFF);
		showMessage((ret == 0) ? "msg_pm_disabled" : "msg_write_eprom_failed", (char *)XAI_PLUGIN, (ret == 0) ? (char *)TEX_SUCCESS : (char *)TEX_ERROR);
	}
	else
	{
		showMessage("msg_eprom_unknown_flag", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
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

		if(cellFsOpen(src, CELL_FS_O_RDONLY, &fd_src, 0, 0) != CELL_FS_SUCCEEDED || cellFsOpen(dst, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd_dst, 0, 0) != CELL_FS_SUCCEEDED)
		{
			cellFsClose(fd_src);
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

	return 0;
}

static void patch_lv1()
{
	for(uint64_t offset = 0xA000; offset < 0x900000; offset = offset + 8)
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

				showMessage("msg_kernel_loaded", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
					
				wait(3);
				cellFsUtilUnMount(DEV_BLIND, 0);
				rebootXMB(SYS_LV2_REBOOT);				
				return;
			}
		}
	}

	return;
}

int loadKernel()
{
	CellFsStat stat;

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	mount_dev_blind();

	if(cellFsStat(USB_KERNEL, &stat) == CELL_FS_SUCCEEDED)
	{
		cellFsUnlink(DBLIND_KERNEL);

		sys_timer_usleep(10000);

		uint64_t free_size = check_flash_free_space();

		if(stat.st_size > free_size)
		{
			int string = RetrieveString("msg_not_enough_space", (char*)XAI_PLUGIN);	
			swprintf_(wchar_string, 120, (wchar_t*)string, (int)"/dev_flash");
			PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			umount_dev_blind();
			return 1;
		}	
	}

	showMessage("msg_kernel_loading", (char *)XAI_PLUGIN, (char *)TEX_INFO2);	

	if(filecopy(USB_KERNEL, DBLIND_KERNEL) == CELL_FS_SUCCEEDED)
		patch_lv1();
	else if(cellFsStat(FLASH_KERNEL, &stat) == CELL_FS_SUCCEEDED)
		patch_lv1();	

	umount_dev_blind();

	showMessage("msg_kernel_failed", (char *)XAI_PLUGIN, (char *)TEX_ERROR);	
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

/*void searchDirectory(char *pDirectoryPath, char *fileformat, char *fileout)
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
}*/

void applicable_version()
{
	uint8_t data[0x20];
	memset(data, 0, 0x20);

	int ret = GetApplicableVersion(data);
	if(ret != CELL_OK)
	{
		showMessage("msg_applicable_version_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int string = RetrieveString("msg_minimum_downgrade", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, data[1], data[3]);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

int activate_account()
{
	CellFsStat stat;
	uint8_t account_id[0x10];
	int ret = -1;
	char accountID[120], act_path[120];		

	uint32_t userid = xUserGetInterface()->GetCurrentUserNumber();	
	sprintf_(act_path, ACT_DAT_PATH, (int)userid, NULL);
	if(cellFsStat(act_path, &stat) == CELL_FS_SUCCEEDED)
	{
		showMessage("msg_cobra_create_act_exist", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return 1;
	}

	uint8_t *dump = (uint8_t *)malloc_(XREGISTRY_FILE_SIZE);	

	if(!dump)
	{
		showMessage("msg_cobra_enable_account_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		showMessage("msg_xreg_open_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		free_(dump);
		return 1;
	}

	sprintf_(accountID, "/setting/user/%08d/npaccount/accountid", (int)userid, NULL);	

	ret = search_data((char *)dump, accountID, ACCOUNTID, READ, 0, 1, account_id);
	
	free_(dump);
	
	if(!ret)
	{
		int fd;		
		uint64_t size;
		char full_path[120], exdata_dir[120], hen_path[120];
		CellFsStat stat;

		uint8_t timedata[0x10] = 
		{ 
			0x00, 0x00, 0x01, 0x2F, 0x3F, 0xFF, 0x00, 0x00, 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};		

		uint64_t accountID = (uint64_t)stoull_((const char*)account_id, 0, 16);
		accountID = SWAP64(accountID);
	
		uint8_t *actdat = (uint8_t *)malloc_(0x1038);	
		uint64_t header = 0x0000000100000002ULL;

		if(!actdat)
		{
			showMessage("msg_cobra_enable_account_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return 1;
		}

		memset(actdat, 0x11, 0x1038);
		memcpy(actdat, &header, 8);
		memcpy(actdat + 8, &accountID, 8);
		memcpy(actdat + 0x870, timedata, 0x10);

		sprintf_(exdata_dir, "/dev_hdd0/home/%08d/exdata", userid, NULL);

		if(cellFsStat(exdata_dir, &stat) != SUCCEEDED)				
			cellFsMkdir(exdata_dir, 0777);		

		sprintf_(full_path, "%s/act.dat", (int)exdata_dir, NULL); 
		sprintf_(hen_path, "%s/act.bak", (int)exdata_dir, NULL); 		
		
		// Normal
		cellFsOpen(full_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0);
		cellFsChmod(full_path, 0777);
		
		if(cellFsWrite(fd, actdat, 0x1038, &size) != SUCCEEDED)
		{
			showMessage("msg_cobra_enable_account_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return -1;
		}

		cellFsClose(fd);

		// HEN
		if(!is_hen())
		{
			buzzer(SINGLE_BEEP);
			cellFsOpen(hen_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsChmod(hen_path, 0777);
			cellFsWrite(fd, actdat, 0x1038, &size);
			cellFsClose(fd);
		}

		free_(actdat);
		
		showMessage("msg_cobra_enable_account_activated", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(ret == 1)
		showMessage("msg_cobra_create_empty", (char *)XAI_PLUGIN, (char *)TEX_WARNING);		
	else if(ret == 2)
		showMessage("msg_accountid_unable_find", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
	else
		showMessage("msg_cobra_enable_account_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	return 0;
}

void check_8th_spe()
{
	uint8_t value = 0;	
	update_mgr_read_eeprom(SPE_8TH_EEPROM_OFFSET, &value);

	log("SPE result: %02x\n", (int)value);

	if(value == 0x06)
		showMessage("msg_8th_spe_disabled", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	else if(value == 0x07)
		showMessage("msg_8th_spe_enabled", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	else
		showMessage("msg_8th_spe_unknown", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void toggle_8th_spe()
{
	close_xml_list();

	uint8_t current_value = 0, new_value = 0;	

	update_mgr_read_eeprom(SPE_8TH_EEPROM_OFFSET, &current_value);
	update_mgr_write_eeprom(SPE_8TH_EEPROM_OFFSET, (current_value == 0x06) ? 0x07 : 0x06);
	update_mgr_read_eeprom(SPE_8TH_EEPROM_OFFSET, &new_value);

	log("SPE result: %02x\n", (int)new_value);

	if(new_value == 0x06)
		showMessage("msg_8th_spe_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		
	else if(new_value == 0x07)
		showMessage("msg_8th_spe_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	else
		showMessage("msg_8th_spe_unknown", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
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
		showMessage("msg_whats_new_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{		
		xUserGetInterface()->SetRegistryString(xUserGetInterface()->GetCurrentUserNumber(), 0x82, "", 0);
		xUserGetInterface()->SetRegistryString(xUserGetInterface()->GetCurrentUserNumber(), 0x83, "", 0);
		xUserGetInterface()->SetRegistryValue(xUserGetInterface()->GetCurrentUserNumber(), 0x84, 0);
		xUserGetInterface()->SetRegistryFocusMask(0);
		showMessage("msg_whats_new_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}	
}

void download_thread()
{	
	download_interface = (download_if *)GetPluginInterface("download_plugin", 1);
	download_interface->DoUnk5(0, url_path, L"/dev_hdd0/packages"); 	
}

static void downloadPKG(wchar_t *url)
{	
	url_path = url;
	LoadPlugin("download_plugin", (void *)download_thread);			
}

void setLed(const char *mode)
{
	if(strcmp(mode, "ledOff") == 0)
	{
		sys_sm_control_led(2, 0); 
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
	}
	else if(strcmp(mode, "ledRed_default") == 0)
	{
		sys_sm_control_led(2, 0);		
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 1);
	}
	else if(strcmp(mode, "ledRed_blink_slow") == 0)
	{
		sys_sm_control_led(2, 0);		
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 3);
	}
	else if(strcmp(mode, "ledRed_blink_fast") == 0)
	{
		sys_sm_control_led(2, 0);		
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 2);
	}
	else if(strcmp(mode, "ledYellow_default") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 1);
		sys_sm_control_led(2, 1);
	}
	else if(strcmp(mode, "ledYellow_blink_slow") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 3);
		sys_sm_control_led(1, 3);
	}
	else if(strcmp(mode, "ledYellow_blink_fast") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 2);
		sys_sm_control_led(1, 2);
	}
	else if(strcmp(mode, "ledYellowG_blink_slow") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 1);
		sys_sm_control_led(2, 3);
	}
	else if(strcmp(mode, "ledYellowG_blink_fast") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 1);
		sys_sm_control_led(2, 2);
	}
	else if(strcmp(mode, "ledYellowR_blink_slow") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 1);
		sys_sm_control_led(1, 3);
	}
	else if(strcmp(mode, "ledYellowR_blink_fast") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 1);
		sys_sm_control_led(1, 2);
	}
	else if(strcmp(mode, "ledGreen_default") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 1);
	}
	else if(strcmp(mode, "ledGreen_blink_slow") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 3);
	}
	else if(strcmp(mode, "ledGreen_blink_fast") == 0)
	{
		sys_sm_control_led(2, 0);
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(1, 2);
	}
	else if(strcmp(mode, "rainbow") == 0)
	{
		sys_sm_control_led(2, 0); 
		sys_sm_control_led(1, 0);
		sys_sm_control_led(0, 0);
		sys_sm_control_led(2, 2);
		sys_timer_usleep(250000);
		sys_sm_control_led(1, 2);
	}
	else if(strcmp(mode, "special1") == 0)
	{
		sys_sm_control_led(2, 0); 
		sys_sm_control_led(1, 0); 
		sys_sm_control_led(0, 0); 
		sys_sm_control_led(1, 2);
		sys_sm_control_led(2, 3); 
	}
	else if(strcmp(mode, "special2") == 0)
	{
		sys_sm_control_led(2, 0); 
		sys_sm_control_led(1, 0); 
		sys_sm_control_led(0, 0); 
		sys_sm_control_led(1, 3); 
		sys_sm_control_led(2, 2);
	}

	showMessage("msg_task_completed", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);	
}

int load_ftp()
{
	int slot = 0, load_slot = 0;
	char ip[0x10] = { NULL };
	char name[120], filename[120];
	CellFsStat stat;	

	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(cellFsStat(FTP_SRPX, &stat) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_ftp_sprx_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// Check if it is enabled
	for(slot = 1; slot < MAX_BOOT_PLUGINS; slot++)
	{
		memset(name, 0, sizeof(name));
		memset(filename, 0, sizeof(filename));

		ps3mapi_get_vsh_plugin_info(slot, name, filename);

		if(strlen(name) == 0 && load_slot == 0) 	
			load_slot = slot;

		if(!strcmp(name, FTPD))
		{
			showMessage("msg_ftp_sprx_already_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
			return 1;
		}
	}

	if(!load_slot)
	{
		showMessage("msg_ftp_not_free_slots", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		return 1;
	}

	if(cobra_load_vsh_plugin(load_slot, FTP_SRPX, NULL, 0) >= 0)
	{
		log("ftp.sprx plugin loaded in slot %d\n", load_slot);
			
		memset(ip, 0, sizeof(ip));

		sceNetCtlGetInfoVsh(0x10, ip);

		int string = RetrieveString("msg_ftp_sprx_enabled", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (ip[0] == NULL ? (int)"-" : (int)ip));
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

		return 0;
	}

	showMessage("msg_ftp_sprx_enabled_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}

int unload_ftp()
{
	int slot = 0;
	char name[120], filename[120];

	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	for(slot = 1; slot < 7; slot++)
	{
		memset(name, 0, sizeof(name));

		ps3mapi_get_vsh_plugin_info(slot, name, filename);

		if(!strcmp(name, FTPD))
		{
			ps3mapi_unload_vsh_plugin(name);
			showMessage("msg_ftp_sprx_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			return 0;
		}
	}	

	showMessage("msg_ftp_sprx_not_enabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	return 1;
}

int toggle_trophy_unlocker()
{
	int slot = 0, load_slot = 0;
	char name[120], filename[120];
	CellFsStat stat;	

	if(!check_cobra_version())
	{
		showMessage("msg_syscall8_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}	

	// Check if it is enabled
	for(slot = 1; slot < MAX_BOOT_PLUGINS; slot++)
	{
		memset(name, 0, sizeof(name));
		memset(filename, 0, sizeof(filename));

		ps3mapi_get_vsh_plugin_info(slot, name, filename);

		if(strlen(name) == 0 && load_slot == 0) 	
			load_slot = slot;

		if(!strcmp(name, TROPHYUNLOCKER))
		{
			ps3mapi_unload_vsh_plugin(name);
			showMessage("msg_trun_sprx_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			return 0;
		}
	}

	if(cellFsStat(TROPHYUNLOCKER_SRPX, &stat) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_trun_sprx_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	if(!load_slot)
	{
		showMessage("msg_ftp_not_free_slots", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		return 1;
	}

	if(cobra_load_vsh_plugin(load_slot, TROPHYUNLOCKER_SRPX, NULL, 0) >= 0)
	{
		log("trophyUnlocker.sprx plugin loaded in slot %d\n", load_slot);
		showMessage("msg_trun_sprx_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		return 0;
	}

	showMessage("msg_trun_sprx_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	return 1;
}

void spoof_idps()
{
	char file[120];	
	int fd, done = 0;
	int usb_port;	
	
	uint64_t idps[2];
	uint8_t buffer[0x20];
	uint8_t fp_buf[16], sp_buf[16];

	uint64_t start_offset = 0x80000000003D0000ULL;
	uint64_t end_offset = 0x8000000000500000ULL;	
	uint64_t nr;	
	
	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// Finding file from USB device
	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(file, "/dev_usb%03d/IDPS.txt", usb_port, NULL);
	else 		
		sprintf_(file, IDPS_TMP_FILE, NULL, NULL); // Patch from PS3's internal HDD

	if(cellFsOpen(file, CELL_FS_O_RDONLY, &fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_spoof_idps_file_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(cellFsRead(fd, &buffer, 0x20, &nr) != CELL_FS_SUCCEEDED)
	{
		cellFsClose(fd);
		showMessage("msg_spoof_idps_read_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}		

	cellFsClose(fd);	

	memcpy(sp_buf, buffer + 0x10, 0x10);
	uint64_t second_part = (uint64_t)stoull_((const char*)sp_buf, 0, 0x10);	
	
	memcpy(fp_buf, buffer, 0x10);
	uint64_t first_part = (uint64_t)stoull_((const char*)fp_buf, 0, 0x10);	

	// Ugly fix, fixes wrong stoull output
	saveFile("dummy", &second_part, 8);
	saveFile("dummy", &first_part, 8);

	// Copy IDPS.txt to /dev_hdd0/tmp/IDPS.txt
	saveFile(IDPS_TMP_FILE, &buffer, 0x20);

	memset(idps, 0, 0x10);
	int ret = sys_ss_get_console_id(idps);

	if(ret == EPERM)
		ret = GetIDPS(idps);

	if(ret != CELL_OK)
	{
		showMessage("msg_spoof_idps_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	
	
	for(uint64_t offset = start_offset; offset < end_offset; offset += 4)
	{
		if(lv2_peek(offset) == idps[0] && lv2_peek(offset + 8) == idps[1])
		{			
			lv2_poke(offset, first_part);
			lv2_poke(offset + 8, second_part);

			// Checking if patches are done
			if(lv2_peek(offset) != first_part || lv2_peek(offset + 8) != second_part)
			{
				showMessage("msg_spoof_idps_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			done++;
		}
	}

	if(done < 2)
	{
		showMessage("msg_spoof_idps_lv2_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	showMessage("msg_spoof_idps_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void spoof_psid()
{
	char file[120];	
	int fd, done = 0;
	int usb_port;	
	
	uint64_t psid[2];
	uint8_t buffer[0x20];
	uint8_t fp_buf[16], sp_buf[16];

	uint64_t start_offset = 0x8000000000450000ULL;
	uint64_t end_offset = 0x8000000000500000ULL;	
	uint64_t nr;	

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}
	
	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(file, "/dev_usb%03d/PSID.txt", usb_port, NULL);
	else
		sprintf_(file, PSID_TMP_FILE, NULL, NULL); // Patch from PS3's internal HDD

	if(cellFsOpen(file, CELL_FS_O_RDONLY, &fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_spoof_psid_file_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	if(cellFsRead(fd, &buffer, 0x20, &nr) != CELL_FS_SUCCEEDED)
	{
		cellFsClose(fd);
		showMessage("msg_spoof_psid_read_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	cellFsClose(fd);	

	memcpy(sp_buf, buffer + 0x10, 0x10);
	uint64_t second_part = (uint64_t)stoull_((const char*)sp_buf, 0, 0x10);
	
	memcpy(fp_buf, buffer, 0x10);
	uint64_t first_part = (uint64_t)stoull_((const char*)fp_buf, 0, 0x10);
	
	// Ugly fix, fixes wrong stoull output
	saveFile("dummy", &second_part, 8);
	saveFile("dummy", &first_part, 8);

	// Copy IDPS.txt to /dev_hdd0/tmp/PSID.txt
	saveFile(PSID_TMP_FILE, &buffer, 0x20);

	memset(psid, 0, 0x10);

	int ret = sys_ss_get_open_psid(psid);

	if(ret == EPERM)
		ret = GetPSID(psid);

	if(ret != CELL_OK)
	{
		showMessage("msg_spoof_psid_get_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	
	
	for(uint64_t offset = start_offset; offset < end_offset; offset += 4)
	{
		if(lv2_peek(offset) == psid[0] && lv2_peek(offset + 8) == psid[1])
		{			
			lv2_poke(offset, first_part);
			lv2_poke(offset + 8, second_part);

			// Checking if patches are done
			if(lv2_peek(offset) != first_part || lv2_peek(offset + 8) != second_part)
			{
				showMessage("msg_spoof_psid_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			done++;
		}
	}

	if(!done)
	{
		showMessage("msg_spoof_psid_lv2_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	showMessage("msg_spoof_psid_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

int Patch_ProDG()
{
	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	lv2_poke(PRODG_PATCH_OFFSET, PRODG_PATCH);

	if(lv2_peek(PRODG_PATCH_OFFSET) != PRODG_PATCH)
	{
		showMessage("msg_prodg_patch_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	showMessage("msg_prodg_patch_success", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);

	return 0;
}

// 3141card's PS3 Unlock HDD Space
void unlock_hdd_space()
{
	uint64_t offset1 = 0, offset2 = 0;
	uint64_t value1 = 0;

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV2))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	for(uint64_t i = 0x8000000000580000ULL; i < 0x8000000000640000ULL; i += 8)
	{
		if(lv2_peek(i) == 0xFFFFC000FFFFF000ULL && lv2_peek(i + 0x90) == 0x6C5F6D775F636673ULL)
		{
			offset1 = i - 0x0C;
			offset2 = i + 0x38;

			value1 = lv2_peek32(offset1);

			if(value1 == 0x08)
			{
				// Unlock 
				lv2_poke32(offset1, 0x01);
				lv2_poke32(offset2, 0x01);			

				if(lv2_peek32(offset1) != 0x01 && lv2_peek32(offset2) != 0x01)
					goto error;
			}
			else
			{				
				// Restore
				lv2_poke32(offset1, 0x08);
				lv2_poke32(offset2, 0x00);

				if(lv2_peek32(offset1) != 0x08 && lv2_peek32(offset2) != 0x00)
					goto error;
			}

			showMessage((lv2_peek32(offset1) == 0x08 ? "msg_unlock_hdd_space_restored" : "msg_unlock_hdd_space_unlocked"), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			
			return;
		}		
	}

error:
	showMessage("msg_unlock_hdd_space_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
}

void show_ip()
{
	char ip[0x10] = { NULL };
	sceNetCtlGetInfoVsh(0x10, ip);

	int string = RetrieveString("msg_show_ip", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (ip[0] == NULL ? (int)"-" : (int)ip));
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void getPS3Lifetime()
{
	// Getting PS3 runtime
	uint32_t status, days, hours, minutes, seconds;
	uint32_t run_time,bringup_ct, shutdown_ct, improper_ct;
	int ret = sys_sm_request_be_count((uint32_t*)&status, &run_time, &bringup_ct, &shutdown_ct);

	if(!ret && !status) 
	{
		days = run_time / 86400;
		hours = (run_time-days * 86400) / 3600;
		minutes = ((run_time-days * 86400) - hours * 3600) / 60;
		seconds = ((run_time-days * 86400) - hours * 3600) - minutes * 60;
		improper_ct = bringup_ct - shutdown_ct;
	}
	 else 
	 {
		 showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);		
		 return;
	 }

	int string = RetrieveString("msg_ps3_lifetime", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 256, (wchar_t*)string, days, hours, minutes, seconds, bringup_ct, shutdown_ct, improper_ct);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

int toggle_npsignin_lck()
{
	int ret, fd;
	uint64_t write;
	CellFsStat stat;

	cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);

	if(cellFsStat(NPSIGNIN_LCK, &stat) == CELL_FS_SUCCEEDED)
	{		
		cellFsRename(NPSIGNIN_LCK, NPSIGNIN_LCK_DISABLED);

		ret = cellFsStat(NPSIGNIN_LCK, &stat);
		showMessage(!ret ? "msg_signin_lck_disabled_error" : "msg_signin_lck_disabled", (char *)XAI_PLUGIN, (char*)!ret ? TEX_ERROR : TEX_SUCCESS);		
	}
	else if(cellFsStat(NPSIGNIN_LCK_DISABLED, &stat) == CELL_FS_SUCCEEDED)
	{
		cellFsRename(NPSIGNIN_LCK_DISABLED, NPSIGNIN_LCK);

		ret = cellFsStat(NPSIGNIN_LCK, &stat);
		showMessage(!ret ? "msg_signin_lck_enabled" : "msg_signin_lck_enabled_error", (char *)XAI_PLUGIN, (char*)!ret ? TEX_SUCCESS : TEX_ERROR);
	}
	else
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);		
		

	cellFsUtilUnMount(DEV_BLIND, 0);

	return 0;
}

//	From bucanero's ps3-advanced-toolset (sm_error_log) with some changes
//	https://github.com/bucanero/ps3-advanced-toolset/tree/master/sm_error_log
void sm_error_log()
{
	int error_count = 0, usb_port;
	char file_path[120];
	FILE *fp;
	CellFsStat stat;
	system_info hwinfo;	
	uint8_t pscode[8], status;
	uint32_t run_time,bringup_ct, shutdown_ct;
	uint32_t error_code, error_time;
	uint64_t hardware_info;	
	uint64_t soft_id, patch_id_rom, patch_id_ram;

	sprintf_(file_path, "%s/sm_error.log", (int)TMP_FOLDER);

	fp = fopen_(file_path, "w");
	cellFsChmod(file_path, 0666);

	if(!fp)
	{
		showMessage("msg_sm_error_log_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	// Getting system info
	if(!sys_sm_get_system_info(&hwinfo))
	{		
		fprintf_(fp, "Firmware Version: %01x.%02x (build %d)\n", hwinfo.firmware_version_high, hwinfo.firmware_version_low >> 4, hwinfo.firmware_build);
		fprintf_(fp, "Platform ID: %s\n", hwinfo.platform_id);
	}
	else
	{
		error_count++;
		fprintf_(fp, "%s:%d: sys_sm_get_system_info failed\n", __func__, __LINE__);
	}
	
	// Getting PSCode
	if(!sys_ss_appliance_info_manager_get_ps_code(pscode)) 
	{
		fprintf_(fp, "Product Code: %02X %02X\n", pscode[2], pscode[3]);
		fprintf_(fp, "Product Sub Code: %02X %02X\n", pscode[4], pscode[5]);
	} 
	else 
	{
		error_count++;
		fprintf_(fp, "%s:%d: sys_ss_appliance_info_manager_get_ps_code failed\n", __func__, __LINE__);	
	}

	// Getting HW info
	int ret = sys_sm_get_hw_config(&status, &hardware_info);

	if(!ret && !status) 
		fprintf_(fp, "Hardware Config: %016lX\n", hardware_info);
	else 
	{
		error_count++;
		fprintf_(fp, "%s:%d: sys_sm_get_hw_config failed\n", __func__, __LINE__);	
	}

	// Getting SYSCON version
	ret = sys_sm_request_scversion(&soft_id, &patch_id_rom, &patch_id_ram);

	if(!ret)
		fprintf_(fp, "Syscon Firmware Version: %04lX.%016lX (EEPROM: %016lX)\n", soft_id, patch_id_ram, patch_id_rom);
	else 
	{
		error_count++;
		fprintf_(fp, "%s:%d: sys_sm_request_scversion failed\n", __func__, __LINE__);	
	}

	// Getting PS3 runtime
	ret = sys_sm_request_be_count((uint32_t*)&status, &run_time, &bringup_ct, &shutdown_ct);

	if(!ret && !status) 
	{
		fprintf_(fp, "\nBringup Count: %d, Shutdown Count: %d\n", bringup_ct, shutdown_ct);

		uint32_t days = run_time / 86400;
		uint32_t hours = (run_time-days * 86400) / 3600;
		uint32_t minutes = ((run_time-days * 86400) - hours * 3600) / 60;
		uint32_t seconds = ((run_time-days * 86400) - hours * 3600) - minutes * 60;

		fprintf_(fp, "Runtime: %d Days, %d Hours, %d Minutes, %d Seconds\n", days, hours, minutes, seconds);
	}
	 else 
	 {
		error_count++;
		fprintf_(fp, "\n%s:%d: sys_sm_request_be_count failed\n", __func__, __LINE__);	
	 }

	// Getting SYSCON error log	
	time_t print_time;

	fprintf_(fp, "\nError Log\n");

	for(int i = 0; i < 0x20; i++) 
	{
		ret = sys_sm_request_error_log(i, &status, &error_code, &error_time);

		if(!ret && !status) 
		{
			error_time += 946684800;
			print_time = (time_t) error_time;
			fprintf_(fp, "%02d: %08X  %s", i + 1, error_code, ctime_(&print_time));
		}
		else 
		{
			error_count++;
			fprintf_(fp, "\n%s:%d: sys_sm_request_error_log failed\n", __func__, __LINE__);
			break;
		}
	}

	fclose_(fp);

	// Detecting USB	
	usb_port = get_usb_device();

	if(usb_port != -1 && cellFsStat(file_path, &stat) == CELL_FS_SUCCEEDED)
	{
		void *buffer = malloc_(stat.st_size);

		if(buffer)
		{
			readfile(file_path, (uint8_t *)buffer, stat.st_size);			
			sprintf_(file_path, "/dev_usb%03d/sm_error.log", usb_port);			
			saveFile(file_path, buffer, stat.st_size);
			free_(buffer);
		}
	}

	buzzer(SINGLE_BEEP);
	int string = RetrieveString(error_count ? "msg_sm_error_log_warning_done" : "msg_sm_error_log_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)file_path);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)error_count ? TEX_WARNING : TEX_SUCCESS);
}

//	From sguerrini97's get_token_seed
//	https://github.com/sguerrini97/psl1ghtv2_ports/tree/master/get_token_seed
void get_token_seed()
{	
	char i, file_path[120];
	int usb_port, string;
	CellFsStat stat;
	uint8_t value, seed[TOKEN_SIZE], token[TOKEN_SIZE];	
	uint64_t auth_check_offset, um_read_eeprom_offset;

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	sprintf_(file_path, "%s/get_token_seed.log", (int)TMP_FOLDER);	

	FILE *fp = fopen_(file_path, "w");
	cellFsChmod(file_path, 0666);

	if(!fp)
	{
		showMessage("msg_get_token_seed_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		goto error;
	}	

	// Search offset in LV1
	auth_check_offset = findValueinLV1(0x150000, 0x180000, 0x4BFFFF8888010070ULL);

	um_read_eeprom_offset = findValueinLV1(0xFB000, 0xFF000, 0x3D29FFFB380973CFULL);
	if(!um_read_eeprom_offset)
		um_read_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x3D29FFFB380973CFULL);

	if(!auth_check_offset || !um_read_eeprom_offset)
	{
		log("Error patching LV1\nPlease contact Evilnat to add support for this FW\n");
		goto error;
	}

	auth_check_offset += 0x0C;
	um_read_eeprom_offset += 0x4C;

	lv1_poke32(auth_check_offset, 0x48000050ULL);
	lv1_poke32(um_read_eeprom_offset, 0x48000050ULL);

	log("auth_check_offset: 0x%X\n", (int)auth_check_offset);
	log("um_read_eeprom_offset: 0x%X\n", (int)um_read_eeprom_offset);

	if(lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_READ_EEPROM, QA_FLAG_OFFSET, (uint64_t)&value, 0, 0, 0, 0)) 
	{
		fprintf_(fp, "lv1_ss_update_mgr_if(READ_EPROM) failed\n");
		goto error;
	}

	fprintf_(fp, "QA Flag 0x%02x\n\n", value);

	if(lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_GET_TOKEN_SEED, (uint64_t)token, TOKEN_SIZE, (uint64_t)seed, TOKEN_SIZE, 0, 0)) 
	{
		fprintf_(fp, "lv1_ss_update_mgr_if(GET_TOKEN_SEED) failed\n");
		goto error;
	}

	fprintf_(fp, "TOKEN SEED:\n");

	for(i = 0; i < TOKEN_SIZE; i += 16)
	{
		fprintf_(fp, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			seed[i + 0], seed[i + 1], seed[i + 2], seed[i + 3], seed[i + 4], seed[i + 5], seed[i + 6], seed[i + 7], 
			seed[i + 8], seed[i + 9], seed[i + 10], seed[i + 11], seed[i + 12], seed[i + 13], seed[i + 14], seed[i + 15]);
	}

	fprintf_(fp,"\nTOKEN:\n");
	for(i = 0; i < TOKEN_SIZE; i += 16)
	{
		fprintf_(fp, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			token[i + 0], token[i + 1], token[i + 2], token[i + 3], token[i + 4], token[i + 5],
			token[i + 6], token[i + 7], token[i + 8], token[i + 9], token[i + 10], token[i + 11],
			token[i + 12], token[i + 13], token[i + 14], token[i + 15]);
	}

	fclose_(fp);

	lv1_poke32(auth_check_offset, 0x409E0050ULL);
	lv1_poke32(um_read_eeprom_offset, 0x419D0054ULL);

	// Detecting USB	
	usb_port = get_usb_device();

	if(usb_port != -1 && cellFsStat(file_path, &stat) == CELL_FS_SUCCEEDED)
	{
		void *buffer = malloc_(stat.st_size);

		if(buffer)
		{
			readfile(file_path, (uint8_t *)buffer, stat.st_size);			
			sprintf_(file_path, "/dev_usb%03d/get_token_seed.log", usb_port);			
			saveFile(file_path, buffer, stat.st_size);
			free_(buffer);
		}
	}

	buzzer(SINGLE_BEEP);
	string = RetrieveString("msg_get_token_seed_done", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)file_path);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return;

error:
	showMessage("msg_get_token_seed_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	if(auth_check_offset && um_read_eeprom_offset)
	{
		lv1_poke32(auth_check_offset, 0x409E0050ULL);
		lv1_poke32(um_read_eeprom_offset, 0x419D0054ULL);
	}
	
	fclose_(fp);

	return;
}

void check_ros_bank()
{
	int string;
	uint8_t value = 0;	
	uint64_t auth_check_offset, um_read_eeprom_offset;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	if(!check_flash_type())
	{
		showMessage("msg_dump_rosbank_not_supported", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// Search offset in LV1
	auth_check_offset = findValueinLV1(0x150000, 0x180000, 0x4BFFFF8888010070ULL);

	um_read_eeprom_offset = findValueinLV1(0xFB000, 0xFF000, 0x3D29FFFB380973CFULL);
	if(!um_read_eeprom_offset)
		um_read_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x3D29FFFB380973CFULL);

	if(!auth_check_offset || !um_read_eeprom_offset)
	{
		log("Error patching LV1\nPlease contact Evilnat to add support for this FW\n");
		goto error;
	}

	auth_check_offset += 0x0C;
	um_read_eeprom_offset += 0x4C;

	lv1_poke32(auth_check_offset, 0x48000050ULL);
	lv1_poke32(um_read_eeprom_offset, 0x48000050ULL);

	log("auth_check_offset: 0x%X\n", (int)auth_check_offset);
	log("um_read_eeprom_offset: 0x%X\n", (int)um_read_eeprom_offset);

	if(lv2_ss_update_mgr_if(UPDATE_MGR_PACKET_ID_READ_EEPROM, ACTIVE_ROS_BANK_OFFSET, (uint64_t)&value, 0, 0, 0, 0) != 0)
	{
		showMessage("msg_current_ros_bank_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		goto error;
	}

	string = RetrieveString("msg_current_ros_bank", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(value == 0xFF ? "ros0" : "ros1"));
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

error:
	if(auth_check_offset && um_read_eeprom_offset)
	{
		lv1_poke32(auth_check_offset, 0x409E0050ULL);
		lv1_poke32(um_read_eeprom_offset, 0x419D0054ULL);
	}

	return;
}

int get_temperature_data()
{
	uint32_t temp_cpu_c = 0, temp_rsx_c = 0;
	uint32_t temp_cpu_f = 0, temp_rsx_f = 0;
	uint8_t st, mode, unknown;
	uint8_t fan_speed, speed_percent; 
	uint8_t fan_mode_percent, ps2_mode_percent;
	char fan_mode[120], ps2_mode[120];

	sys_game_get_temperature(0, &temp_cpu_c);
    sys_game_get_temperature(1, &temp_rsx_c);
	temp_cpu_f = celsius_to_fahrenheit(&temp_cpu_c);
	temp_rsx_f = celsius_to_fahrenheit(&temp_rsx_c);	

	sys_sm_get_fan_policy(0, &st, &mode, &fan_speed, &unknown);	
	speed_percent = (fan_speed * 100) / 255;	

	cobra_read_config(cobra_config);
	fan_mode_percent = (cobra_config->fan_speed * 100) / 255;
	ps2_mode_percent = (cobra_config->ps2_speed * 100) / 255;

	// HEN - WEBMAN MOD
	if(!is_hen())
	{
		uint8_t wmconfig[sizeof(WebmanCfg)];
		WebmanCfg *webman_config = (WebmanCfg*) wmconfig;

		// Checking if webMAN MOD is installed
		int ret = readfile(WEBMAN_CFG, wmconfig, sizeof(WebmanCfg));

		fan_mode_percent = (webman_config->man_speed * 100) / 255;

		if(!ret)
		{
			if(webman_config->fanc == 0)
				strncpy(fan_mode, "SYSCON", 6);
			else if(webman_config->fanc == 2)
				strncpy(fan_mode, "AUTO2", 5);
			else if(webman_config->fanc == 1 && webman_config->man_speed == 0)
				strncpy(fan_mode, "DYNAMIC", 7);
			else
				sprintf_(fan_mode, "Manual [%i%%]", fan_mode_percent);

			if(webman_config->fanc == 0)
				strncpy(ps2_mode, "SYSCON", 6);
			else
				sprintf_(ps2_mode, "Manual [%d%%]", webman_config->ps2_rate);
		}
		else		
		{
			strncpy(fan_mode, "-", 1);
			strncpy(ps2_mode, "-", 1);
		}
	}
	else
	{
		// CFW - COBRA
		if(cobra_config->fan_speed == 0 || cobra_config->fan_speed == 1)
			strncpy(fan_mode, "SYSCON", 6);
		else if(cobra_config->fan_speed >= 2 && cobra_config->fan_speed <= 5)
		{
			uint32_t dyn_mode_perc = 0;
			uint32_t dyn_mode_fahrenheit = 0;

			if(cobra_config->fan_speed == 2)
				dyn_mode_perc = 60;
			else if(cobra_config->fan_speed == 3)
				dyn_mode_perc = 65;
			else if(cobra_config->fan_speed == 4)
				dyn_mode_perc = 70;
			else if(cobra_config->fan_speed == 5)
				dyn_mode_perc = 75;

			dyn_mode_fahrenheit = celsius_to_fahrenheit(&dyn_mode_perc);

			sprintf_(fan_mode, "Dynamic [%d°C / %u°F] ", dyn_mode_perc, dyn_mode_fahrenheit);
		}
		else
			sprintf_(fan_mode, "Manual [%i%%]", fan_mode_percent);
	
		if(cobra_config->ps2_speed == 0 || cobra_config->ps2_speed == 1)
			strncpy(ps2_mode, "SYSCON", 6);
		else
			sprintf_(ps2_mode, "Manual [%i%%]", ps2_mode_percent);		
	}

	int string = RetrieveString("msg_temperature_data", (char*)XAI_PLUGIN);		
	
	swprintf_(wchar_string, 240, (wchar_t*)string, 
		temp_cpu_c, temp_cpu_f, 
		temp_rsx_c, temp_rsx_f, 
		(uint8_t)fan_speed, speed_percent,
		(int)fan_mode,
		(int)ps2_mode);	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);	

	return 0;
}

int spoof_mac()
{
	char file[120];	
	int usb_port, fd;	
	int success = 1;

	char final_string[0x100];
	
	uint8_t read_buffer[0x10];
	uint8_t gelic_buffer[0x13];
	uint8_t new_mac_buffer[0x12];

	uint64_t start_offset = 0x8000000000070000ULL;
	uint64_t end_offset = 0x8000000000400000ULL;	
	uint64_t current_mac, new_mac, read;
	uint64_t offset;

	// Check if CFW Syscalls are disabled
	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}
	
	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(file, "/dev_usb%03d/MAC.txt", usb_port, NULL);
	else
		sprintf_(file, MAC_TMP_FILE, NULL, NULL); // Patch from PS3's internal HDD

	if(cellFsOpen(file, CELL_FS_O_RDONLY, &fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		showMessage("msg_spoof_mac_file_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	if(cellFsRead(fd, &read_buffer, 0x0C, &read) != CELL_FS_SUCCEEDED)
	{
		cellFsClose(fd);
		showMessage("msg_spoof_mac_read_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	cellFsClose(fd);	
	
	new_mac = (uint64_t)stoull_((const char*)read_buffer, 0, 0x10);

	// Copy MAC.txt to /dev_hdd0/tmp/MAC.txt
	saveFile(MAC_TMP_FILE, &read_buffer, 0x0C);

	lv2_gelic_eurus_control(0x103F, gelic_buffer, 0x13);	
	sprintf_(final_string, "0000%02X%02X%02X%02X%02X%02X", gelic_buffer[0x0D], gelic_buffer[0x0E], gelic_buffer[0x0F], gelic_buffer[0x10], gelic_buffer[0x11], gelic_buffer[0x12]);
	current_mac = (uint64_t)stoull_((const char*)final_string, 0, 0x10);

	offset = START_OFFSET_MAC;
    while(offset < END_OFFSET_MAC)
    {
        // MAC string found in LV1, patching
        if(lv1_peek(offset) == current_mac)
        {        
            lv1_poke(offset, new_mac); 

            // Checking if is patched correctly
            if(lv1_peek(offset) != new_mac)
			{
				showMessage("msg_spoof_mac_error", (char *)XAI_PLUGIN, (char*)TEX_ERROR);
                return 1;
			}

            success = 0;        
        }

        offset += 4;
    }

	if(!success) 
    {        
        // Set MAC with lv2_gelic_eurus_control
        new_mac_buffer[12] = (new_mac >> 40) & 0xFF;
        new_mac_buffer[13] = (new_mac >> 32) & 0xFF;
        new_mac_buffer[14] = (new_mac >> 24) & 0xFF;
        new_mac_buffer[15] = (new_mac >> 16) & 0xFF;
        new_mac_buffer[16] = (new_mac >> 8) & 0xFF;
        new_mac_buffer[17] = new_mac & 0xFF;

		showMessage("msg_spoof_mac_success", (char *)XAI_PLUGIN, (char*)TEX_SUCCESS);
		
    }

	wait(3);
	rebootXMB(SYS_LV2_REBOOT);

	return 0;
}

void show_ids()
{
	uint8_t idps[0x10];
	char idps_char1[120], idps_char2[120], idps_full[120];	

	memset(idps, 0, 0x10);	

	int ret = sys_ss_get_console_id(idps);

	if(ret == EPERM)
		ret = GetIDPS(idps);

	sprintf_(idps_char1, "%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7]);
	sprintf_(idps_char2, "%02X%02X%02X%02X%02X%02X%02X%02X", idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
	sprintf_(idps_full, "%s\n         %s", (int)idps_char1, (int)idps_char2);

	// PSID
	// ----
	uint8_t psid[0x10];
	char psid_char1[120], psid_char2[120], psid_full[120];

	memset(psid, 0, 0x10);

	ret = sys_ss_get_open_psid(psid);

	if(ret == EPERM)
		ret = GetPSID(psid);	

	sprintf_(psid_char1, "%02X%02X%02X%02X%02X%02X%02X%02X", psid[0], psid[1], psid[2], psid[3], psid[4], psid[5], psid[6], psid[7]);
	sprintf_(psid_char2, "%02X%02X%02X%02X%02X%02X%02X%02X", psid[8], psid[9], psid[10], psid[11], psid[12], psid[13], psid[14], psid[15]);
	sprintf_(psid_full, "%s\n         %s", (int)psid_char1, (int)psid_char2);

	// MAC
	// ---
	char mac_full[120];
	uint8_t gelic_buffer[0x13]; 
	lv2_gelic_eurus_control(0x103F, gelic_buffer, 0x13);
	sprintf_(mac_full, "%02X:%02X:%02X:%02X:%02X:%02X", gelic_buffer[13], gelic_buffer[14], gelic_buffer[15], gelic_buffer[16], gelic_buffer[17], gelic_buffer[18]);

	int string = RetrieveString("msg_show_ids_data", (char*)XAI_PLUGIN);		
	
	swprintf_(wchar_string, 240, (wchar_t*)string, 
		(int)idps_full, 
		(int)psid_full, 
		(int)mac_full);	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);	
}

int dump_ids()
{
	char act[256];
	char mac_string[256], buffer[256], output[256], usb_string[256];	
	char *message = "msg_ids_dumped";
	int ret_idps, ret_psid, file, size;
	uint8_t idps[0x10], psid[0x10], gelic_buffer[0x13];
	uint8_t buf[0x1038];
	uint32_t userID;
	uint64_t write;

	memset(idps, 0, 0x10);
	memset(psid, 0, 0x10);
	memset(gelic_buffer, 0, 0x13);

	// IDPS
	ret_idps = sys_ss_get_console_id(idps);

	if(ret_idps == EPERM)
		ret_idps = GetIDPS(idps);	

	// PSID
	ret_psid = sys_ss_get_open_psid(psid);

	if(ret_psid == EPERM)
		ret_psid = GetPSID(psid);
	
	// MAC		
	lv2_gelic_eurus_control(0x103F, gelic_buffer, 0x13);	
	sprintf_(mac_string, "MAC: %02X:%02X:%02X:%02X:%02X:%02X", gelic_buffer[0x0D], gelic_buffer[0x0E], gelic_buffer[0x0F], gelic_buffer[0x10], gelic_buffer[0x11], gelic_buffer[0x12]);

	log_key("IDPS", idps);
	log_key("PSID", psid);
	log("%s\n", mac_string);

	// Dumping to external device
	int usb_port = get_usb_device();

	if(usb_port == -1)
		sprintf_(output, "/dev_hdd0/tmp/IDs.txt", NULL, NULL);	
	else
	{
		sprintf_(usb_string, "/dev_usb%03d", usb_port);
		sprintf_(output, "/dev_usb%03d/IDs.txt", usb_port, NULL);
	}

	// IDPS
	cellFsOpen(output, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &file, 0, 0);	
	cellFsChmod(output, 0666);
	sprintf_(buffer, "IDPS: %08X%08X%08X%08X\n", (*(int*)idps), *((int*)idps + 1), *((int*)idps + 2), *((int*)idps + 3));
	size = strlen(buffer);
	cellFsWrite(file, buffer, size, &write);

	// idps.bin
	sprintf_(buffer, "/dev_usb%03d/idps.bin", usb_port);
	saveFile(buffer, idps, 0x10);

	// PSID
	sprintf_(buffer, "PSID: %08X%08X%08X%08X\n", (*(int*)psid), *((int*)psid + 1), *((int*)psid + 2), *((int*)psid + 3));
	size = strlen(buffer);
	cellFsWrite(file, buffer, size, &write);

	// MAC
	size = strlen(mac_string);
	cellFsWrite(file, mac_string, size, &write);
	cellFsClose(file);

	// act.dat
	if(usb_port == -1)
		sprintf_(output, "/dev_hdd0/tmp/act.dat", NULL, NULL);	
	else
		sprintf_(output, "/dev_usb%03d/act.dat", usb_port, NULL);	
	
	userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(act, ACT_DAT_PATH, userID, NULL);

	if(readfile(act, buf, 0x1038) == SUCCEEDED)
		saveFile(output, buf, 0x1038);
	else
		message = "msg_ids_dumped2";

	int string = RetrieveString(message, (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(usb_port != -1 ? usb_string : "/dev_hdd0/tmp"));	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
	
	return 0;
}

int patch_xreg_value(char *str, uint32_t value, int size)
{
	uint16_t offsetString = 0;

	char string[256];
	uint8_t *dump = (uint8_t *)malloc_(XREGISTRY_FILE_SIZE);

	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		free__(dump);
		return 1;
	}

	for (int i = 0; i < 0x10000 - strlen(str); i++)
	{
		if (!strcmp((char *)dump + i, str))	
		{
			offsetString = i - 0x15;

			for (int i = 0; i < 0x15000 - 2; i++)
			{      
				if (*(uint32_t *)(dump + i) == offsetString)
				{
					memcpy((dump + i + 9), &value, size);
					saveFile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE);	
					saveFile(XREGISTRY_BACKUP_FILE, dump, XREGISTRY_FILE_SIZE);		
					free__(dump);
					return 0;
				}					
			}
		}		
	}

	return 1;
}

void set_region(int region, uint32_t dvd_region, uint32_t bd_region, uint32_t tvSystem)
{
	int region_str;
	char conv_str[120];	
	xSettingRegistryGetInterface()->saveRegistryRegion(region);
	xSettingBdvdGetInterface()->SetDvdRegionCode(dvd_region);
	xSettingBdvdGetInterface()->SetBdRegionCode(bd_region);
	xSettingBdvdGetInterface()->SetDvdTvSystem(tvSystem);	

	for(int i = 0; i < 14; i++)
	{
		if(region == regionPS3[i].ps3_region)
			region_str = RetrieveString(regionPS3[i].region, (char*)XAI_PLUGIN);			
	}
	
	int string = RetrieveString("msg_region_set", (char*)XAI_PLUGIN);	
	wcstombs_((char *)conv_str, (wchar_t *)region_str, 120 + 1);
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)conv_str);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
}

void set_region_default()
{
	int region_str;
	char conv_str[120];	
	uint8_t pscode[8];

	xSettingRegistryGetInterface()->saveRegistryRegion(0);

	if(!sys_ss_appliance_info_manager_get_ps_code(pscode)) 
	{
		for(int i = 0; i < 13; i++)
		{
			if(pscode[3] == regionPS3[i].ps3_region)
			{
				xSettingBdvdGetInterface()->SetDvdRegionCode(regionPS3[i].dvd_region);
				xSettingBdvdGetInterface()->SetBdRegionCode(regionPS3[i].bd_region);
				break;
			}
		}		
	}

	int string = RetrieveString("msg_region_set", (char*)XAI_PLUGIN);	
	region_str = RetrieveString("msg_default", (char*)XAI_PLUGIN);
	wcstombs_((char *)conv_str, (wchar_t *)region_str, 120 + 1);
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)conv_str);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
}

void toggle_dvdtvsys()
{
	uint32_t value;
	xSettingBdvdGetInterface()->GetDvdTvSystem(&value);	

	xSettingBdvdGetInterface()->SetDvdTvSystem((value == 2 ? 0 : 2));

	int string = RetrieveString("msg_tvsystem", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)(value == 2 ? (int)"NTSC" : (int)"PAL"));
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
}

void check_region_values()
{
	int regionCode, region_str;;
	char dvdRegion[120], bdRegion[120], ps3Region[120], conv_str[120];
	uint32_t dvdRegionCode, bdRegionCode, dvdTvSystem;	

	regionCode = xSettingRegistryGetInterface()->loadRegistryRegion();
	xSettingBdvdGetInterface()->GetDvdRegionCode(&dvdRegionCode);
	xSettingBdvdGetInterface()->GetBdRegionCode(&bdRegionCode);
	xSettingBdvdGetInterface()->GetDvdTvSystem(&dvdTvSystem);

	strcpy(ps3Region, "Unknown");
	strcpy(dvdRegion, "Unknown");
	strcpy(bdRegion, "Unknown");

	// PS3 Region
	for (int i = 0; i < 14; i++)
	{
		if(regionCode == regionPS3[i].ps3_region)
			strcpy(ps3Region, regionPS3[i].region);
	}

	// DVD Region
	for (int i = 0; i < 6; i++)
	{
		if(dvdRegionCode == dvd_video_region[i].dvd_region)
			strcpy(dvdRegion, dvd_video_region[i].region);
	}	

	// BD Region
	for (int i = 0; i < 3; i++)
	{
		if(bdRegionCode == bd_video_region[i].bd_region)
			strcpy(bdRegion, bd_video_region[i].region);
	}

	int string = RetrieveString("msg_check_region", (char*)XAI_PLUGIN);	
	region_str = RetrieveString(ps3Region, (char*)XAI_PLUGIN);
	wcstombs_((char *)conv_str, (wchar_t *)region_str, 120 + 1);
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)conv_str, (int)dvdRegion, (int)bdRegion, (int)(dvdTvSystem == 2 ? "PAL" : "NTSC"));
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
}

void Fix_CBOMB()
{
	#define DATE_2000_01_01	0x00E01D003A63A000ULL
	#define DATE_1970_01_01	0x00DCBFFEFF2BC000ULL
	#define DATE_2023_11_23	0x00E2CAD2ECB78000ULL

	uint64_t clock, diff;
	uint64_t sec, nsec;
	uint64_t a1, a2;
	uint64_t currentTick;	

	uint64_t timedata = 0x00E2CABECEE02000ULL - DATE_2000_01_01;
	uint64_t patchedDate = DATE_2023_11_23;

	_cellRtcGetCurrentTick(&currentTick);
	{ system_call_4(0x362, 0x3002, 0, (uint64_t)&a1, (uint64_t)&a2); }

	if(currentTick < DATE_2023_11_23)
	{
		_cellRtcSetCurrentTick(&patchedDate);	
		sysGetCurrentTime(&sec, &nsec);	
		sys_time_get_rtc(&clock);		
		diff = sec - clock;
		xSettingDateGetInterface()->SaveDiffTime(diff);
	}

	if(!a1)
		sys_ss_secure_rtc(timedata);

	{ system_call_4(0x362, 0x3002, 0, (uint64_t)&a1, (uint64_t)&a2); }
	_cellRtcGetCurrentTick(&currentTick);
	uint64_t result_time2 = (currentTick - DATE_2000_01_01);
	
	uint64_t rtc_clock = a1 * 1000000 + DATE_2000_01_01;

	if(rtc_clock < currentTick)
	{		
		sys_ss_secure_rtc(result_time2);
		showMessage("msg_rtc_fixed", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(rtc_clock > currentTick)
	{
		sysSetCurrentTime(((rtc_clock - DATE_1970_01_01) / 1000000), 0);
		sysGetCurrentTime(&sec, &nsec);	
		sys_time_get_rtc(&clock);		
		diff = sec - clock;
		xSettingDateGetInterface()->SaveDiffTime(diff);
		showMessage("msg_rtc_date_fixed", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);		
	}

	buzzer(SINGLE_BEEP);
}

// Convert 4 bytes in big-endian format, to an unsigned integer.
unsigned int char_arr_BE_to_uint(unsigned char *arr)
{
	return arr[3] + 256 * (arr[2] + 256 * (arr[1] + (256 * arr[0])));
}

void getIV(unsigned char* iv, int sectorNumber)
{
	int num = sectorNumber;

	for (int j = 0; j < 16; j++)
	{
		iv[16 - j - 1] = (int)(num & 0xFF);
		num >>= 8;
	}
}

int decryptEncryptedISO(const char *isoFile)
{
	uint8_t disc_key[0x10] = { 0 };
	uint8_t key_d1[0x10] = { 0x38, 11, 0xcf, 11, 0x53, 0x45, 0x5b, 60, 120, 0x17, 0xab, 0x4f, 0xa3, 0xba, 0x90, 0xed };
    uint8_t iv_d1[0x10] =  { 0x69, 0x47, 0x47, 0x72, 0xaf, 0x6f, 0xda, 0xb3, 0x42, 0x74, 0x3a, 0xef, 0xAA, 0x18, 0x62, 0x87 };

	unsigned char new_iv[0x10];
	char key_path[256];
	int fd, keyfd;
	unsigned char region0[0x1000];	
	uint32_t sectors = 0;
	uint64_t keynread, nread = 0, pos, size;	

	PS3RegionInfo discRegionInfo[0x20];

	sprintf_(key_path, "%s.key", (int)isoFile, NULL);
	if(!cellFsOpen(key_path, CELL_FS_O_RDONLY, &keyfd, NULL, 0))
	{	
		cellFsRead(keyfd, disc_key, 0x10, &keynread);
		log("Found DiscKey\n");
		cellFsClose(keyfd);
	}	

	readfile(isoFile, region0, 0x1000);
	if(!memcmp(disc_key, empty, 0x10))
	{			
		if(!memcmp(&region0[REDUMP_WATERMARK_OFFSET], "Encrypted", 9))
		{
			log("Decrypting ISO: [%s]...\n", (int)isoFile);

			if(memcmp(&region0[REDUMP_KEY_OFFSET], empty, 0x10))
			{
				memcpy(disc_key, &region0[REDUMP_KEY_OFFSET], 0x10);
				AesCbcCfbEncrypt(disc_key, disc_key, 0x10, key_d1, 128, iv_d1);
			}
			else
			{
				log("Key not found!\n");
				return 1;
			}
		}
		else
		{
			log("Encrypted ISO not found!\n");
			return 1;
		}
	}

	int string = RetrieveString("msg_decrypting_iso", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)isoFile);	
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);	
			
	sectors = 1;
	memcpy(&sectors, &region0[0], 4);
	sectors = (sectors * 2) - 1;
	
	for(int i = 0; i < sectors; i++)
	{
		discRegionInfo[i].isEncrypted = (i % 2 == 1);
		discRegionInfo[i].first_address_region = (i == 0 ? 0LL : discRegionInfo[i - 1].last_address_region + 1LL); //(i == 0 ? 0LL : region_info_[i - 1].regions_last_addr + 1LL);
		discRegionInfo[i].last_address_region = char_arr_BE_to_uint(region0 + 0x0C + (i * 4));
	}
	
	if(cellFsOpen(isoFile, CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
		return 1;

	uint32_t *buffer = (uint32_t *)malloc_(0x8000);

	int lba = 0;
	for(int i = 0; i < sectors; i++)
	{	
		if(discRegionInfo[i].isEncrypted)
		{			
			uint64_t total_sector_size = (discRegionInfo[i].last_address_region * 0x800) - (discRegionInfo[i].first_address_region * 0x800);
			uint64_t base_sector = discRegionInfo[i].first_address_region;
			lba = 0;

			uint64_t current_sector = 0;
			while(current_sector < total_sector_size)
			{
				cellFsLseek(fd, (base_sector * 0x800) + current_sector, SEEK_SET, &pos);
				cellFsRead(fd, buffer, 0x8000, &nread);		

				for(int sector_number = 0; sector_number < 0x10; sector_number++)
				{
					getIV(new_iv, base_sector + (lba + sector_number));
					AesCbcCfbDecrypt((uint8_t *)buffer + (sector_number * 0x800), (uint8_t *)buffer + (sector_number * 0x800), 0x800, disc_key, 128, new_iv);
				}		

				cellFsLseek(fd, (base_sector * 0x800) + current_sector, SEEK_SET, &pos);
				cellFsWrite(fd, (uint8_t *)buffer, 0x8000, &size);

				current_sector += 0x8000;
				lba += 0x10;
			}
		}
	}	

	cellFsLseek(fd, 0, SEEK_SET, &pos);
	memcpy(&region0[0xF70], "Decrypted", 9);
	cellFsWrite(fd, &region0, 0x1000, &size);
	free_(buffer);
	cellFsClose(fd);	

	return 0;
}

// 0: HDD
// 1: USB
void decryptRedumpISO(int src)
{
	int decypted_isos = 0;
	int fd, usb_port = 0;
	CellFsDirent dir;
	CellFsStat stat;
	uint64_t read;
	uint8_t region0[0x1000];
	char location[256], iso_file[256];
	
	close_xml_list();

	if(!src)
		strcpy(location, "/dev_hdd0/PS3ISO");
	else
	{
		usb_port = get_usb_device();
		sprintf_(location, "/dev_usb%03d/PS3ISO", usb_port, NULL);
	}	

	if(!cellFsStat(location, &stat))
	{
		if(!cellFsOpendir(location, &fd))
		{
			while(!cellFsReaddir(fd, &dir, &read))
			{		
				if(read == 0)
					break;	

				sprintf_(iso_file, "%s/%s", (int)location, (int)dir.d_name);
				int path_len = strlen(iso_file);	

				if (!strcmp(dir.d_name, ".") || !strcmp(dir.d_name, "..") || dir.d_type == 1)
					continue;	

				if(strcasecmp(iso_file + path_len - 4, ".iso") != 0)
					continue;
								
				readfile(iso_file, region0, 0x1000);		
				if(!memcmp(&region0[REDUMP_WATERMARK_OFFSET], "Decrypted", 9))
					continue;

				if(!decryptEncryptedISO(iso_file))
					decypted_isos++;
			}
		}
	}

	if(decypted_isos)
	{
		int string = RetrieveString("msg_isos_decrypted", (char*)XAI_PLUGIN);	
		swprintf_(wchar_string, 120, (wchar_t*)string, (int)decypted_isos);	
		PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
		buzzer(SINGLE_BEEP);	
	}
	else		
		showMessage("msg_enc_iso_not_found", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	return;	
}

int swap_libaudio()
{
	int ret;
	CellFsStat statinfo;

	if(cellFsStat(DEV_BLIND, &statinfo) != CELL_OK)
	{
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0);
		log_function("xai_plugin", __VIEW__, "cellFsUtilMount", "(/dev_blind) = %x\n", ret);

		if(ret != CELL_OK)
		{
			showMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return ret;
		}
	}

	if(cellFsStat(LIBAUDIO_ORIGINAL, &statinfo) == CELL_OK && cellFsStat(LIBAUDIO_PATCHED, &statinfo) != CELL_OK)
	{
		cellFsRename(LIBAUDIO_SPRX, LIBAUDIO_PATCHED);
		cellFsRename(LIBAUDIO_ORIGINAL, LIBAUDIO_SPRX);
		showMessage("msg_libaudio_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
	}
	else if(cellFsStat(LIBAUDIO_ORIGINAL, &statinfo) != CELL_OK && cellFsStat(LIBAUDIO_PATCHED, &statinfo) == CELL_OK)
	{
		cellFsRename(LIBAUDIO_SPRX, LIBAUDIO_ORIGINAL);
		cellFsRename(LIBAUDIO_PATCHED, LIBAUDIO_SPRX);
		showMessage("msg_libaudio_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	
	}
	else
		showMessage("msg_sort_games_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	

	return 0;
}

void show_bd_info()
{
	int fd, str_country, str_mobo, str_bd;
	char conv_str1[120], conv_str2[120], conv_str3[120], bd_model[40];	
	uint8_t pscode[8], buf[0x38];

	memset(buf, 0, 0x38);

	int ret = sys_storage_open(0x101000000000006ULL, &fd);
	if(ret != CELL_OK)
	{
		showMessage("msg_sys_storage_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}	

    ret = ps3rom_lv2_get_inquiry(fd, buf);
    if(ret != CELL_OK)
	{
		showMessage("msg_sys_storage_open_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}

	sys_storage_close(fd);
	strcpy(bd_model, (char*)(buf + 8));

	if(sys_ss_appliance_info_manager_get_ps_code(pscode)) 
	{
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);	
		return;
	}	

	switch(pscode[3])
	{
		case 0x81:
			str_country = RetrieveString("msg_target_ref", (char*)XAI_PLUGIN);		
			break;
		case 0x82:
			str_country = RetrieveString("msg_target_debug", (char*)XAI_PLUGIN);		
			break;
		case 0x83:
			str_country = RetrieveString("msg_target_jap", (char*)XAI_PLUGIN);		
			break;
		case 0x84:
			str_country = RetrieveString("msg_target_usa", (char*)XAI_PLUGIN);		
			break;
		case 0x85:
			str_country = RetrieveString("msg_target_eur", (char*)XAI_PLUGIN);		
			break;
		case 0x86:
			str_country = RetrieveString("msg_target_kr", (char*)XAI_PLUGIN);		
			break;
		case 0x87:
			str_country = RetrieveString("msg_target_uk", (char*)XAI_PLUGIN);		
			break;
		case 0x88:
			str_country = RetrieveString("msg_target_mex", (char*)XAI_PLUGIN);		
			break;
		case 0x89:
			str_country = RetrieveString("msg_target_oce", (char*)XAI_PLUGIN);		
			break;
		case 0x8A:
			str_country = RetrieveString("msg_target_sea", (char*)XAI_PLUGIN);		
			break;
		case 0x8B:
			str_country = RetrieveString("msg_target_tai", (char*)XAI_PLUGIN);		
			break;
		case 0x8C:
			str_country = RetrieveString("msg_target_rus", (char*)XAI_PLUGIN);		
			break;
		case 0x8D:
			str_country = RetrieveString("msg_target_chi", (char*)XAI_PLUGIN);		
			break;
		case 0x8E:
			str_country = RetrieveString("msg_target_hk", (char*)XAI_PLUGIN);		
			break;
		case 0x8F:
			str_country = RetrieveString("msg_target_br", (char*)XAI_PLUGIN);		
			break;
		case 0xA0:
			str_country = RetrieveString("msg_target_arc", (char*)XAI_PLUGIN);		
			break;
		default:
			str_country = RetrieveString("msg_unknown", (char*)XAI_PLUGIN);		
			break;
	}

	switch(pscode[5])
	{
		case 0x01:
			str_mobo = RetrieveString("msg_cok1", (char*)XAI_PLUGIN);
			break;
		case 0x02:
			str_mobo = RetrieveString("msg_cok2mc", (char*)XAI_PLUGIN);
			break;
		case 0x03:
			str_mobo = RetrieveString("msg_cok2", (char*)XAI_PLUGIN);
			break;
		case 0x04:
			str_mobo = RetrieveString("msg_cok2w", (char*)XAI_PLUGIN);
			break;
		case 0x05:
			str_mobo = RetrieveString("msg_sem", (char*)XAI_PLUGIN);
			break;
		case 0x06:
			str_mobo = RetrieveString("msg_dia1", (char*)XAI_PLUGIN);
			break;
		case 0x07:
			str_mobo = RetrieveString("msg_dia2", (char*)XAI_PLUGIN);
			break;
		case 0x08:
			str_mobo = RetrieveString("msg_ver", (char*)XAI_PLUGIN);
			break;
		case 0x09:
			str_mobo = RetrieveString("msg_dyn", (char*)XAI_PLUGIN);
			break;
		case 0x0A:
			str_mobo = RetrieveString("msg_sur", (char*)XAI_PLUGIN);
			break;
		case 0x0B:
			str_mobo = RetrieveString("msg_jtp", (char*)XAI_PLUGIN);
			break;
		default:
			str_mobo = RetrieveString("msg_unknown", (char*)XAI_PLUGIN);
			break;
	}

	switch(pscode[7])
	{
		case 0x01:			
			str_bd = RetrieveString("msg_bd_410", (char*)XAI_PLUGIN);
			break;
		case 0x04:
			str_bd = RetrieveString("msg_bd_kes400", (char*)XAI_PLUGIN);			
			break;
		case 0x05:
			str_bd = RetrieveString("msg_bd_kes450", (char*)XAI_PLUGIN);			
			break;
		default:
			str_bd = RetrieveString("msg_unknown", (char*)XAI_PLUGIN);
			break;
	}

	int string = RetrieveString("msg_show_bdinfo", (char*)XAI_PLUGIN);		

	wcstombs_((char *)conv_str1, (wchar_t *)str_country, 120 + 1);
	wcstombs_((char *)conv_str2, (wchar_t *)str_mobo, 120 + 1);
	wcstombs_((char *)conv_str3, (wchar_t *)str_bd, 120 + 1);

	swprintf_(wchar_string, 420, (wchar_t*)string, 
		(int)bd_model,
		(int)pscode[3], (int)conv_str1,		
		(int)pscode[5], (int)conv_str2, 
		(int)pscode[7], (int)conv_str3);	

	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_INFO2);	
}

int rap2bin()
{
	char content_id[0x24];
	char str_buffer[120], exdata[120], rap_bin_file[120];

	int string;
	int bin_file_exist, found, count = 0;
	int MAGIC_NUMBER = 0xFAF0FAF0;
	int file, fd, file2, usb_port, fileSize, rap_files;

	uint8_t rap_value[0x10], buffer[0x50], check_value[0x50];
	uint64_t read_dir, write, read, seek;
	CellFsDirent dir;		
	CellFsStat stat;
	
	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(exdata, "/dev_usb%03d/exdata", usb_port, NULL);
	else
		sprintf_(exdata, "/dev_hdd0/exdata", NULL, NULL);

	cellFsMkdir(exdata, 0777);
	cellFsChmod(exdata, 0666);

	sprintf_(rap_bin_file, "%s/rap.bin", (int)exdata);

	bin_file_exist = cellFsStat(rap_bin_file, &stat);

	if(cellFsOpen(rap_bin_file, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &file, 0, 0) != CELL_FS_SUCCEEDED)
	{
		log("RAP2BIN: Unable to create %s\n", rap_bin_file);
		goto error;
	}

	showMessage("msg_rap2bin_imp_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	cellFsChmod(rap_bin_file, 0666);

	if(!cellFsOpendir(exdata, &fd))
	{
		while(!cellFsReaddir(fd, &dir, &read_dir))
		{
			if(read_dir == 0)
				break;	

			found = 0;

			if(strstr(dir.d_name, ".rap") != NULL) 
			{			
				memset(buffer, 0, 0x50);
				strncpy(content_id, dir.d_name, strlen(dir.d_name) - 4);				
				sprintf_(str_buffer, "%s/%s", (int)exdata, (int)dir.d_name);

				if(readfile(str_buffer, rap_value, 0x10) != SUCCEEDED)
				{
					log("RAP2BIN: Error reading %s\n", str_buffer);
					goto error;
				}

				memcpy(buffer, &MAGIC_NUMBER, 4);
				memcpy(buffer + 0x10, content_id, 0x24);
				memcpy(buffer + 0x40, rap_value, 0x10);

				if(cellFsWrite(file, buffer, 0x50, &write) != CELL_FS_SUCCEEDED)
				{
					log("RAP2BIN: Unable to save %s\n", rap_bin_file);
					goto error;
				}

				count += 1;
				//log("RAP2BIN: %s imported successfully\n", str_buffer);
			}			
		}

		if(!count)
		{
			log("RAP2BIN: Failed to add any new RAP file\n");
			goto error;
		}
	}
	else
	{
		log("RAP2BIN: Unable to find RAP files\n");
		goto error;
	}

	cellFsClose(file);
	cellFsClose(file2);
	cellFsClosedir(fd); 

	// Copying to /dev_hdd0/exdata/rap.bin
	if(usb_port != -1)
	{
		if(cellFsStat(rap_bin_file, &stat) == CELL_FS_SUCCEEDED)
		{
			uint8_t *buffer = (uint8_t *)malloc_(stat.st_size);
			readfile(rap_bin_file, buffer, stat.st_size);
			cellFsMkdir(RAP_BIN_HDD_PATH, 0777);
			saveFile(RAP_BIN_HDD_PATH, buffer, stat.st_size);
			free_(buffer);
		}
	}

	buzzer(SINGLE_BEEP);
	log("RAP2BIN: %d RAP files imported successfully\n", count);
	string = RetrieveString("msg_rap2bin_imported", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)count);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;

error:
	buzzer(TRIPLE_BEEP);
	cellFsClose(file);
	cellFsClose(file2);
	cellFsClosedir(fd);

	showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	return 1;
}

int bin2rap()
{
	char content_id[0x24], rap_file[120], exdata[120];
	int string;
	int rap_bin_fd, fileSize, rap_files, usb_port;
	int MAGIC_NUMBER = 0xFAF0FAF0;
	int exported_files = 0;
	uint8_t buffer[0x50], rap_value[0x10];
	uint64_t seek, read, write;
	CellFsStat stat;		

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(rap_file, "/dev_usb%03d/exdata/rap.bin", usb_port, NULL);

	if(cellFsStat(rap_file, &stat) != CELL_FS_SUCCEEDED)
		sprintf_(rap_file, RAP_BIN_HDD_PATH, NULL);

	cellFsStat(rap_file, &stat);

	if(cellFsOpen(rap_file,  CELL_FS_O_RDONLY, &rap_bin_fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		log("BIN2RAP: Unable to open rap.bin\n");
		goto error;
	}	

	fileSize = stat.st_size;
		
	if(!fileSize)
	{
		log("BIN2RAP: No RAP files detected in rap.bin\n");
		goto error;
	}

	rap_files = (fileSize / 0x50);
	log("BIN2RAP: RAP files detected in rap.bin: %d\n", rap_files);		

	usb_port = get_usb_device();

	if(usb_port != -1)
		sprintf_(exdata, "/dev_usb%03d/exdata", usb_port, NULL);
	else
		sprintf_(exdata, "/dev_hdd0/exdata", NULL, NULL);

	cellFsMkdir(exdata, 0777);

	showMessage("msg_rap2bin_exp_wait", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		
	for(int count = 0; count < rap_files; count++)
	{
		memset(buffer, 0, 0x50);
		cellFsLseek(rap_bin_fd, 0x50 * count, SEEK_SET, &seek);

		if(cellFsRead(rap_bin_fd, buffer, 0x50, &read) != CELL_FS_SUCCEEDED)
		{
			log("BIN2RAP: Error reading rap.bin file\n");
			goto error;
		}

		if(memcmp(buffer, &MAGIC_NUMBER, 4) != CELL_FS_SUCCEEDED)
		{
			log("BIN2RAP: Bad magic!\n");
			goto error;
		}

		memcpy(content_id, buffer + 0x10, 0x24);
		memcpy(rap_value, buffer + 0x40, 0x10);
		
		sprintf_(rap_file, "%s/%s.rap", (int)exdata, (int)content_id);

		if(saveFile(rap_file, rap_value, 0x10) != SUCCEEDED)
		{
			log("BIN2RAP: Unable to save %s!\n", rap_file);
			goto error;
		}

		exported_files += 1;
	}			

	buzzer(SINGLE_BEEP);
	cellFsClose(rap_bin_fd);

	log("BIN2RAP: %d files exported successfully\n", exported_files);

	string = RetrieveString("msg_rap2bin_exported", (char*)XAI_PLUGIN);	
	swprintf_(wchar_string, 120, (wchar_t*)string, (int)exported_files);
	PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

	return 0;

error:
	buzzer(TRIPLE_BEEP);
	cellFsClose(rap_bin_fd);

	showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

	return 1;
}
