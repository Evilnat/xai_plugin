#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cell/fs/cell_fs_file_api.h>
#include "cfw_settings.h"
#include "gccpch.h"
#include "savegames.h"
#include "log.h"
#include "functions.h"

#define SAVEGAME_HASH_OFFSET 			(prot_table + 0x90)
#define CONSOLE_ID_HASH_OFFSET 			(prot_table + 0x90 + 0x14)
#define DISC_HASH_OFFSET 				(prot_table + 0x90 + 0x28)
#define AUTHENTICATION_ID_HASH_OFFSET 	(prot_table + 0x90 + 0x3C)

#define PS3MAPI_IDPS_1			 		0x80000000003E2E30ULL
#define PS3MAPI_IDPS_2			 		0x8000000000474AF4ULL
#define PS3MAPI_PSID					0x8000000000474B0CULL

typedef struct
{
	uint64_t size;
    char file_path[120];
    uint8_t savegame_param_sfo_hash[0x14];    
    uint8_t console_id_hash[0x14];  
    uint8_t disc_hash_hash[0x14];  
    uint8_t authentication_id_hash[0x14];  
} sfo_data_t;

typedef struct
{
    uint64_t size;
    char file_path[120];
    uint8_t vector[0x10];
    uint8_t real_hashkey[0x14];
    uint8_t default_hash[0x14];
} pfd_data_t;

static int prot_table = 0;
uint32_t userID = 0;

static uint8_t console_id_key[0x10];

static uint8_t savegame_param_sfo_key[0x14] =
{
	0x0C, 0x08, 0x00, 0x0E, 0x09, 0x05, 0x04, 0x04, 0x0D, 0x01, 
	0x0F, 0x00, 0x04, 0x06, 0x02, 0x02, 0x09, 0x06, 0x0D, 0x03
};

static uint8_t authentication_id[0x08] = 
{
    0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03
};

static uint8_t disc_hash_key[0x10] = 
{
	0xD1, 0xC1, 0xE1, 0x0B, 0x9C, 0x54, 0x7E, 0x68, 
	0x9B, 0x80, 0x5D, 0xCD, 0x97, 0x10, 0xCE, 0x8D
};

static uint8_t keygen_key[0x14] =
{
	0x6B, 0x1A, 0xCE, 0xA2, 0x46, 0xB7, 0x45, 0xFD, 0x8F, 0x93, 
	0x76, 0x3B, 0x92, 0x05, 0x94, 0xCD, 0x53, 0x48, 0x3B, 0x82
};

static uint8_t syscon_manager_key[0x14] = 
{
	0xD4, 0x13, 0xB8, 0x96, 0x63, 0xE1, 0xFE, 0x9F, 
	0x75, 0x14, 0x3D, 0x3B, 0xB4, 0x56, 0x52, 0x74
};

static uint8_t null_iv[] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void load_saves_functions()
{
	setNIDfunc(xUserGetInterface, "xsetting", 0xCC56EB2D);
}

static void generate_entry_hash(uint8_t real_key[0x14], uint8_t *buffer)
{
	uint64_t sha1[160];

	uint64_t entry;
	memcpy(&entry, buffer + 0xB8, 8);

	memset(&sha1, 0, 160);
	sha1_hmac_starts(sha1, real_key, 0x14);

	if(entry != 0)
	{
		sha1_hmac_update(sha1, buffer + prot_table + 0x110 * entry + 8, 0x41);
		sha1_hmac_update(sha1, buffer + prot_table + 0x110 * entry + 0x50, 0xC0);
	}

	sha1_hmac_update(sha1, buffer + prot_table + 8, 0x41);
	sha1_hmac_update(sha1, buffer + prot_table + 0x50, 0xC0);
	sha1_hmac_finish(buffer + Y_TABLE_OFFSET + 0x14 * 8, sha1);
}

int search_data(char *buf, char *str, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16])
{
	int result = -1;
	uint16_t offsetString = 0;
	uint32_t offsetValue = 0;

	for (int i = 0; i < 0x10000 - strlen(str); i++)
	{
		if (!strcmp((char *)buf + i, str))	
		{
			offsetString = i - 0x15;

			for (int i = 0; i < 0x15000 - 2; i++)
			{      
				if (*(uint16_t *)(buf + i) == offsetString && *(uint8_t *)(buf + i + 4) == 0x00 && 
					((type) ? *(uint8_t *)(buf + i + 5) == 0x11 && *(uint8_t *)(buf + i + 6) == 0x02 : 
							  *(uint8_t *)(buf + i + 5) == 0x04 && *(uint8_t *)(buf + i + 6) == 0x01))
				{

					offsetValue = i;
					result = 0;

					if(type && mode == 2) // Reset accountID
					{     
						memcpy((uint8_t *)(buf + (uint32_t)offsetValue + 7), empty, 0x10);
					}
					else if(type && mode) // Set/Overwrite with fake accountID
					{
						if(!overwrite && memcmp((uint8_t *)(buf + (uint32_t)offsetValue + 7), empty, 0x10) != 0)         
							return 1;         

						memcpy((uint8_t *)(buf + (uint32_t)offsetValue + 7), fake_accountid, 0x10);
					}
					else if(type && !mode) // Check if there is no accountID
					{
						memcpy(output, (uint8_t *)(buf + (uint32_t)offsetValue + 7), 0x10);

						if(checkEmpty && memcmp((uint8_t *)(buf + (uint32_t)offsetValue + 7), empty, 0x10) == 0)
							result = 1;
					}
					else if(!type && mode) // Disable auto sign in PSN with empty email/password
					{
						uint32_t disabled = 0;
						memcpy((uint8_t *)(buf + (uint32_t)offsetValue + 7), &disabled, 4);
					}					

					return result;
				}
			}
		}		
	}

	if(!offsetString || !offsetValue)
		return 2;

	return result;
}

int set_accountID(int mode, int overwrite)
{  
	int ret;
    char autoLogin[120], accountid[120];

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	uint8_t account_id[0x10];

    sprintf_(autoLogin, SETTING_AUTOSIGN, userID, NULL);
    sprintf_(accountid, SETTING_ACCOUNTID, userID, NULL);

	uint8_t *dump = (uint8_t *)malloc__(XREGISTRY_FILE_SIZE);	

	if(!dump)
		return 4;

	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		free__(dump);
		return 3;
	}

	ret = search_data((char *)dump, autoLogin, AUTOSIGN, WRITE, 0, 0, account_id);
	if(ret == 2)
	{
		free__(dump);
		return 2;
	}

	ret = search_data((char *)dump, accountid, ACCOUNTID, mode, overwrite, 0, account_id);
	switch(ret)
	{
		free__(dump);

		case 1:
			return 1;
		case 2:
			return 4;
	}

	saveFile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE);

	free__(dump);
	return 0;
}

int patch_savedatas(const char *path)
{
	CellFsStat stat;		

	sfo_data_t sfo_data;
	pfd_data_t pfd_data;

	uint8_t account_id[0x10];

	char path_file[120], acc_char[60];

    uint32_t magicSFO = 0x00505346;
    uint64_t magicPFD = 0x0000000050464442;

	sprintf_(path_file, "%s/PARAM.SFO", (int)path, NULL);	

	char entry[120];
	userID = xUserGetInterface()->GetCurrentUserNumber();	
	sprintf_(acc_char, SETTING_ACCOUNTID, userID, NULL);	

	uint8_t *dump = (uint8_t *)malloc__(XREGISTRY_FILE_SIZE);

	if(!dump)
		return -1;

	if(cellFsStat(path_file, &stat) == SUCCEEDED)
	{
		if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
		{
			free__(dump);
			return 1;
		}

		// Getting accountID from current logged user
		if(search_data((char *)dump, acc_char, ACCOUNTID, READ, 0, 0, account_id))
			return 2;
				
		// Read and retrieve PARAM.SFO data		
        uint8_t *temp_data_sfo = NULL;
		temp_data_sfo = (uint8_t *) malloc__(stat.st_size);

        if(!temp_data_sfo)
			return -1;		

        memcpy(&sfo_data.size, (void *)&stat.st_size, 16);
        strcpy(sfo_data.file_path, path_file);          
		if(readfile(path_file, temp_data_sfo, stat.st_size))
		{
			free__(temp_data_sfo);
			return 3;
		}	

		// PARAM.SFO not valid
		if(memcmp(temp_data_sfo, &magicSFO, 4)) 
		{
			free__(temp_data_sfo);
			return 4;
		}

		// Disable copy protection of savedata
		*(temp_data_sfo + COPY_PROTECTION_OFFSET) = 0;
		
		// Patching with current userID
		userID = SWAP32(userID);
		memcpy(temp_data_sfo + USER_ID_1_OFFSET, &userID, 4);
		memcpy(temp_data_sfo + USER_ID_2_OFFSET, &userID, 4);

		// Patching with current accountID
		memcpy(temp_data_sfo + 0x140, account_id, 0x10);
		memcpy(temp_data_sfo + 0x588, account_id, 0x10);
		
		// Patching with PSID
		uint64_t PSID1 = lv2_peek(PS3MAPI_PSID);
		uint64_t PSID2 = lv2_peek(PS3MAPI_PSID + 8);	

		memcpy(temp_data_sfo + 0x574, (void *)&PSID1, 8);
		memcpy(temp_data_sfo + 0x57C, (void *)&PSID2, 8);		

		// Creating CID key
		uint64_t idps1 = lv2_peek(PS3MAPI_IDPS_1);
		uint64_t idps2 = lv2_peek(PS3MAPI_IDPS_1 + 8);

		memcpy(console_id_key, (void *)&idps1, 8);		
		memcpy(console_id_key + 8, (void *)&idps2, 8);

		// Generate PARAM.SFO hashes
		sha1_hmac(sfo_data.savegame_param_sfo_hash, temp_data_sfo, stat.st_size, savegame_param_sfo_key, 0x14);
		sha1_hmac(sfo_data.console_id_hash, temp_data_sfo, stat.st_size, console_id_key, 0x10);
		sha1_hmac(sfo_data.disc_hash_hash, temp_data_sfo, stat.st_size, disc_hash_key, 0x10);
		sha1_hmac(sfo_data.authentication_id_hash, temp_data_sfo, stat.st_size, authentication_id, 8);	

		free__(dump);

		sprintf_(path_file, "%s/PARAM.PFD", (int)path, NULL);		

		if(cellFsStat(path_file, &stat) == SUCCEEDED)
		{		
			// Read and retrieve PARAM.PFD data		
            uint8_t *temp_data_pfd = NULL;
			temp_data_pfd = (uint8_t *) malloc__(stat.st_size);

            if(!temp_data_pfd)
			{
				free__(temp_data_sfo);
				return -1;
			}

            memcpy(&pfd_data.size, (void *)&stat.st_size, 16);
            strcpy(pfd_data.file_path, path_file);

			if(readfile(path_file, temp_data_pfd, stat.st_size))
			{
				free__(temp_data_sfo);
				free__(temp_data_pfd);
				return 5;
			}

			// PARAM.PFD not valid
			if(memcmp(temp_data_pfd, &magicPFD, 8))
			{
				free__(temp_data_sfo);
				free__(temp_data_pfd);
				return 6;
			}

			// Decrypt PARAM.PFD header
			memcpy(pfd_data.vector, temp_data_pfd + 0x10, 0x10);
			AesCbcCfbDecrypt(temp_data_pfd + 0x20, temp_data_pfd + 0x20, 0x40, syscon_manager_key, 128, pfd_data.vector);

			// Generate real hash key
			uint64_t param_version;		
			memcpy(&param_version, temp_data_pfd + 8, 8);

			if(param_version == 3)
				memcpy(pfd_data.real_hashkey, temp_data_pfd + 0x48, 0x14);
			else
				sha1_hmac(pfd_data.real_hashkey, temp_data_pfd + 0x48, 0x14, keygen_key, 0x14);

            uint64_t reserved = 0;
            memcpy(&reserved, temp_data_pfd + HEADER_SIZE, 8);
            prot_table = HEADER_SIZE + 0x18 + reserved * 8;		

			// Copy PARAM.SFO hashes
			memcpy(temp_data_pfd + SAVEGAME_HASH_OFFSET, sfo_data.savegame_param_sfo_hash, 0x14);
			memcpy(temp_data_pfd + CONSOLE_ID_HASH_OFFSET, sfo_data.console_id_hash, 0x14);
			memcpy(temp_data_pfd + DISC_HASH_OFFSET, sfo_data.disc_hash_hash, 0x14);
			memcpy(temp_data_pfd + AUTHENTICATION_ID_HASH_OFFSET, sfo_data.authentication_id_hash, 0x14);	

			// Generate hash entry for PARAM.SFO            
			generate_entry_hash(pfd_data.real_hashkey, temp_data_pfd);

			// Generate default hash
			sha1_hmac(pfd_data.default_hash, NULL, 0, pfd_data.real_hashkey, 0x14);

			// Generate bottom hash
			sha1_hmac(temp_data_pfd + 0x20, temp_data_pfd + 0x7B60, 0x474, pfd_data.real_hashkey, 0x14);

			// Generate top hash
			sha1_hmac(temp_data_pfd + 0x34, temp_data_pfd + 0x60, 0x1E0, pfd_data.real_hashkey, 0x14);

			// Encrypt header
			AesCbcCfbEncrypt(temp_data_pfd + 0x20, temp_data_pfd + 0x20, 0x40, syscon_manager_key, 128, pfd_data.vector);
			

			// Write new files
			if(saveFile(sfo_data.file_path, temp_data_sfo, sfo_data.size))
			{
				free__(temp_data_sfo);	
				free__(temp_data_pfd);
				return 7;
			}

			if(saveFile(pfd_data.file_path, temp_data_pfd, pfd_data.size))
			{
				free__(temp_data_sfo);	
				free__(temp_data_pfd);
				return 7;
			}

			free__(temp_data_sfo);	
			free__(temp_data_pfd);	

			return SUCCEEDED;		
		}		

		free__(temp_data_sfo);				
	}
	
	return -1;
}

int export_rap()
{	
	int fd, ret, i, round_num, string, usb_port;
	char exdata_path[120], actdat_path[120];
	char license_file[120], contentID[36], exdata_folder[120];

	CellFsDirent dir;	
	CellFsStat statinfo;

	struct rif_t rif;
	struct actdat_t *actdat = NULL;	
	
	uint8_t padding[0x0C];
	uint8_t encrypted[0x10], decrypted[0x10];
	uint8_t idps[0x10];
	uint8_t rifKey[0x10], rapFile[0x10];
	uint8_t *rap_key, *klicensee;
	uint64_t read;

	wchar_t wchar_string[120];
	int rap_created = 0;

	usb_port = get_usb_device();

	if(usb_port == -1)
	{
		showMessage("msg_usb_not_detected", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		return 1;
	}

	sprintf_(exdata_folder, "/dev_usb%03d/exdata", usb_port);
	if(cellFsStat(exdata_folder, &statinfo))
		cellFsMkdir(exdata_folder, 0777);

	if(sys_ss_get_console_id(idps) == EPERM)
	{
		if(GetIDPS(idps) != CELL_OK)
		{
			showMessage("msg_idps_dump_fail", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
			return 1;
		}
	}	

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	sprintf_(exdata_path, "/dev_hdd0/home/%08d/exdata", userID, NULL);

	if(!cellFsOpendir(exdata_path, &fd))
	{
		rap_created = 0;

		while(!cellFsReaddir(fd, &dir, &read))
		{
			if(read == 0)
				break;	

			if (!strcmp(dir.d_name, ".") || !strcmp(dir.d_name, "..") || dir.d_type == 1)
				continue;	

			sprintf_(license_file, "%s/%s", (int)exdata_path, (int)dir.d_name);
			int path_len = strlen(license_file);	

			if(strcasecmp(license_file + path_len - 4, ".rif") != 0 || path_len != 71)
				continue;

			strncpy(contentID, license_file + 31, 40);
			contentID[36] = '\0';

			sprintf_(license_file, "/dev_hdd0/home/%08d/exdata/%s.rif", userID, (int)contentID);

			log("Exporting %s.rap...\n", contentID);

			if(readfile(license_file, (uint8_t *)&rif, 0x98) != CELL_FS_SUCCEEDED)
				goto error;

			sprintf_(actdat_path, ACT_DAT_PATH, userID); 
			actdat = (struct actdat_t*)malloc__(0x1038);

			if(!actdat)
				goto error;

			if(readfile(actdat_path, (uint8_t *)actdat, 0x1038) != CELL_FS_SUCCEEDED)
			{
				showMessage("msg_account_act_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
				goto error;
			}

			ret = AesCbcCfbDecrypt(rif.padding, rif.padding, 0x10, rif_key_const, 128, null_iv);
			ret |= AesCbcCfbEncrypt(encrypted, idps_const, 0x10, idps, 128, null_iv);
			ret |= AesCbcCfbDecrypt(decrypted, &actdat->keyTable[rif.actDatIndex * 0x10], 0x10, encrypted, 128, null_iv);
			ret |= AesCbcCfbDecrypt(rifKey, rif.key, 0x10, decrypted, 128, null_iv);

			if(ret)
				goto error;

			// Converting KLICENSEE to RAP
			uint8_t key[0x10];
			memset(key, 0, 0x10);
			memcpy(key, rifKey, 0x10);			

			for (round_num = 0; round_num < 5; ++round_num) 
			{
			   int o = 0;
			   for (i = 0; i < 16; ++i) 
			   {
				  int p = pbox[i];
				  uint8_t ec2 = e2[p];
				  uint8_t kc = key[p] + ec2;
				  key[p] = kc + (uint8_t)o;
				  if (o != 1 || kc != 0xFF) 
					 o = kc < ec2 ? 1 : 0;
			   }

			   for (i = 1; i < 16; ++i) 
			   {
				  int p = pbox[i];
				  int pp = pbox[i - 1];
				  key[p] ^= key[pp];
			   }

			   for (i = 0; i < 16; ++i) 
				  key[i] ^= e1[i];
			}			
   
			if(AesCbcCfbEncrypt(rap_key, key, 0x10, rap_initial_key, 128, null_iv) != SUCCEEDED)
				goto error;			

			sprintf_(license_file, "/dev_usb%03d/exdata/%s.rap", usb_port, (int)contentID);
			if(saveFile(license_file, rap_key, 0x10) != 0)
			{
				error:
				free__(actdat);
				cellFsClosedir(fd);

				sprintf_(license_file, "%s.rap", (int)contentID);
				string = RetrieveString("msg_rif_create_error", (char*)XAI_PLUGIN);	
				swprintf_(wchar_string, 120, (wchar_t*)string, (int)license_file);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);

				if(rap_created > 1)
				{
					string = RetrieveString("msg_rifs_created", (char*)XAI_PLUGIN);	
					swprintf_(wchar_string, 120, (wchar_t*)string, rap_created);
					PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_ERROR);
				}
				else if(rap_created == 1)
					showMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_ERROR);

				log("Error while exporting %s\n", license_file);

				return 1;
			}

			free__(actdat);
			rap_created++;
		}

		if(rap_created)
		{
			cellFsClosedir(fd);

			if(rap_created > 1)
			{
				string = RetrieveString("msg_rifs_created", (char*)XAI_PLUGIN);	
				swprintf_(wchar_string, 120, (wchar_t*)string, rap_created);
				PrintString(wchar_string, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			}
			else
				showMessage("msg_rif_created", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	

			return 0;
		}
	}

	showMessage("msg_rif_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);	
	cellFsClosedir(fd);
	return 0;
}