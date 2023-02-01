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

void load_saves_functions()
{
	//setNIDfunc(free_, "allocator", 0x77A602DD);
	//setNIDfunc(malloc_, "allocator", 0x759E0635);
	setNIDfunc(xUserGetInterface, "xsetting", 0xCC56EB2D);

	/*(void*&)(free_) = (void*)((int)getNIDfunc("allocator", 0x77A602DD));
	(void*&)(malloc_) = (void*)((int)getNIDfunc("allocator", 0x759E0635));
	(void*&)(xUserGetInterface) = (void*)((int)getNIDfunc("xsetting", 0xCC56EB2D));	*/
}

int savefile(const char *path, void *data, size_t size)
{
	int file;
	uint64_t write;

	cellFsChmod(path, 0666);

	if(cellFsOpen(path, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &file, 0, 0) != SUCCEEDED)
		return -1;

	cellFsWrite(file, data, size, &write);
	cellFsClose(file);

	return SUCCEEDED;	
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

int new_search_data(char *buf, char *str, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16])
{
	int i, result = -1;
	uint16_t offset = 0;

	uint8_t *dump = (uint8_t *)malloc_(XREGISTRY_FILE_SIZE);	
	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		ShowMessage("msg_xreg_open_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		free_(dump);
		return result;
	}

	for (int i = 0; i < 0x10000 - strlen(str); i++)
	{
		if (!strcmp((char *)dump + i, str))	
		{
			offset = i - 0x15;

			for (int i = 0; i < 0x15000 - 2; i++)
			{      
				if (*(uint16_t *)(buf + i) == offset && *(uint8_t *)(buf + i + 4) == 0x00 && 
					((type) ? *(uint8_t *)(buf + i + 5) == 0x11 && *(uint8_t *)(buf + i + 6) == 0x02 : 
							  *(uint8_t *)(buf + i + 5) == 0x04 && *(uint8_t *)(buf + i + 6) == 0x01))
				{
					if(type && mode)
					{
						if(!overwrite && memcmp((uint8_t *)(buf + (uint32_t)offset + 7), empty, 0x10) != 0)         
							return 1;         

						memcpy((uint8_t *)(buf + (uint32_t)offset + 7), fake_accountid, 0x10);
					}
					else if(type && !mode)
					{
						memcpy(output, (uint8_t *)(buf + (uint32_t)offset + 7), 0x10);

						if(checkEmpty && memcmp((uint8_t *)(buf + (uint32_t)offset + 7), empty, 0x10) == 0)
							result = 1;
					}
					else if(!type && mode)
					{
						uint32_t disabled = 0;
						memcpy((uint8_t *)(buf + (uint32_t)offset + 7), &disabled, 4);
					}

					return result;
				}
			}
		}		
	}

	return result;
}

int search_str_buf(char *buf, char *str)
{
	unsigned i;

	for (i = 0; i < 0x10000 - strlen(str); i++)
		if (!strcmp(buf + i, str))		
			return (int)i - 0x15;		

	return 0;
}

int search_value(char *buf, uint16_t header, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16])
{
	int i, result = -1;
	uint32_t offset = 0;

	if(!header)
		return result;

	for (i = 0; i < 0x15000 - 2; i++)
	{      
		if (*(uint16_t *)(buf + i) == header && *(uint8_t *)(buf + i + 4) == 0x00 && 
			((type) ? *(uint8_t *)(buf + i + 5) == 0x11 && *(uint8_t *)(buf + i + 6) == 0x02 : 
			          *(uint8_t *)(buf + i + 5) == 0x04 && *(uint8_t *)(buf + i + 6) == 0x01))					   
		{
			offset = i;
			result = 0;     
			break;
		}
	}

	if(!offset)
		return result;

	if(result == 0)
	{
		if(type && mode)
		{
			if(!overwrite && memcmp((uint8_t *)(buf + (uint32_t)offset + 7), empty, 0x10) != 0)         
				return 1;         

			memcpy((uint8_t *)(buf + (uint32_t)offset + 7), fake_accountid, 0x10);
		}
		else if(type && !mode)
		{
			memcpy(output, (uint8_t *)(buf + (uint32_t)offset + 7), 0x10);

			if(checkEmpty && memcmp((uint8_t *)(buf + (uint32_t)offset + 7), empty, 0x10) == 0)
				result = 1;
		}
		else if(!type && mode)
		{
			uint32_t disabled = 0;
			memcpy((uint8_t *)(buf + (uint32_t)offset + 7), &disabled, 4);
		}

		return result;
	}

	return result;
}

int xreg_data(char *value, int type, int mode, int overwrite, int checkEmpty)
{
    int fd, result = -1; 
    uint16_t offset = 0;
    uint64_t dummy, read, seek;	
    char *buffer = (char *)malloc__(0x2A);  

    if(!buffer)
		return result;

	cellFsChmod(XREGISTRY_FILE, 0666);

    if(cellFsOpen(XREGISTRY_FILE, CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
    {
		free__(buffer);
		return result;
	}  		

    // Get offset
    for(int i = 0; i < 0x10000; i++)
    {       
        cellFsLseek(fd, i, SEEK_SET, &seek);
        cellFsRead(fd, buffer, 0x31 + 1, &read);

        // Found offset
        if(strcmp(buffer, value) == 0) 
        {
            offset = i - 0x15;

            uint8_t *data = NULL;

            // Search value from value table
            for(int i = 0x10000; i < 0x15000; i++)
            {
            	data = (uint8_t *) malloc__(0x17);

                cellFsLseek(fd, i, SEEK_SET, &seek);
                cellFsRead(fd, data, 0x17, &read);
                
                // Found value
                if (memcmp(data, &offset, 2) == 0 && data[4] == 0x00 && 
					((type) ? data[5] == 0x11 && data[6] == 0x02 : 
					          data[5] == 0x04 && data[6] == 0x01))
                {       
                    result = 0;      

                    if(type && mode) // Set/Overwrite with fake accountID
                    {                   
                        if(!overwrite && memcmp(data + 7, empty, 0x10) != SUCCEEDED)
                        {
                            free__(data);
                            free__(buffer);
                            cellFsClose(fd);
                            return 1;
                        }

                        cellFsLseek(fd, i + 7, SEEK_SET, &seek);
                        cellFsWrite(fd, fake_accountid, 0x10, &dummy);
                    }
                    else if(type && !mode) // Check if there is no accountID
                    {
                        //memcpy(&account_id, data + 7, 0x10);

                        if(checkEmpty && memcmp(data + 7, empty, 0x10) != SUCCEEDED)                        
                            result = 1;                                                                    
                    } 
                    else if(!type && mode) // Disable auto sign in PSN with empty email/password
                    {
                        uint32_t disabled = 0;
                        cellFsLseek(fd, i + 7, SEEK_SET, &seek);
                        cellFsWrite(fd, &disabled, 4, &dummy);
                    }                                       
                    else                     
                        memcpy(&userID, data + 7, 4);

                    free__(data);
					free__(buffer);
					cellFsClose(fd);
					return result;
                }

                free__(data);
            }
        }
    }

    free__(buffer);
    cellFsClose(fd);    

    return result;
}

int set_fakeID(int overwrite)
{  
    char autoLogin[120], accountid[120];

	uint32_t userID = xUserGetInterface()->GetCurrentUserNumber();
	uint16_t header = 0, header2 = 0;

    sprintf_(autoLogin, SETTING_AUTOSIGN, userID, NULL);
    sprintf_(accountid, SETTING_ACCOUNTID, userID, NULL);

	uint8_t *dump = (uint8_t *)malloc__(XREGISTRY_FILE_SIZE);	
	if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
	{
		free__(dump);
		return 3;
	}

	header = search_str_buf((char *)dump, autoLogin);
	if(header && search_value((char *)dump, header, AUTOSIGN, WRITE, 0, 0, NULL))
	{
		free__(dump);
		return 2;	
	}

	header2 = search_str_buf((char *)dump, accountid);
    if(header2 && search_value((char *)dump, header, ACCOUNTID, WRITE, overwrite, 0, NULL) != SUCCEEDED)
	{
		free__(dump);
        return 1;
	}

	//savefile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE);
	savefile("/dev_usb000/xRegistry.sys", dump, XREGISTRY_FILE_SIZE);

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

	if(cellFsStat(path_file, &stat) == SUCCEEDED)
	{
		if(readfile(XREGISTRY_FILE, dump, XREGISTRY_FILE_SIZE))
		{
			free__(dump);
			return 1;
		}

		// Getting accountID from current logged user
		/*uint16_t header = search_str_buf((char *)dump, acc_char);
		if(search_value((char *)dump, header, ACCOUNTID, READ, 0, 0, account_id))
			return 2;	*/

		new_search_data((char *)dump, acc_char, ACCOUNTID, READ, 0, 0, account_id);
				
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
			if(savefile(sfo_data.file_path, temp_data_sfo, sfo_data.size))
			{
				free__(temp_data_sfo);	
				free__(temp_data_pfd);
				return 7;
			}

			if(savefile(pfd_data.file_path, temp_data_pfd, pfd_data.size))
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
