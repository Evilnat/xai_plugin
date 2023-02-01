#ifndef _SAVEGAMES_H__
#define _SAVEGAMES_H__

#define AUTOSIGN						0
#define ACCOUNTID						1

#define READ 							0
#define WRITE 							1
#define EMPTY							2

#define HEADER_SIZE 					0x60
#define Y_TABLE_OFFSET  				0x7B60

#define COPY_PROTECTION_OFFSET 			0x150
#define USER_ID_1_OFFSET 				0x570
#define USER_ID_2_OFFSET  				0x584

#define XREGISTRY_FILE 					"/dev_flash2/etc/xRegistry.sys"
#define XREGISTRY_FILE_SIZE				0x40000

#define LOGINUSERID 					"/setting/user/lastLoginUserId"
#define SETTING_AUTOSIGN 				"/setting/user/%08d/npaccount/autoSignInEnable"
#define SETTING_ACCOUNTID 				"/setting/user/%08d/npaccount/accountid"

  #define SWAP32(value)               \
   ((value & 0xff000000ull) >> 24)    \
   | ((value & 0x00ff0000ull) >> 8)   \
   | ((value & 0x0000ff00ull) << 8)   \
   | ((value & 0x000000ffull) << 24)

#define SWAP64(value)  						   \
	((value & 0xff00000000000000ull) >> 56)    \
	| ((value & 0x00ff000000000000ull) >> 40)  \
	| ((value & 0x0000ff0000000000ull) >> 24)  \
	| ((value & 0x000000ff00000000ull) >> 8 )  \
	| ((value & 0x00000000ff000000ull) << 8 )  \
	| ((value & 0x0000000000ff0000ull) << 24)  \
	| ((value & 0x000000000000ff00ull) << 40)  \
	| ((value & 0x00000000000000ffull) << 56)

static uint8_t empty[0x10] = 
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uint8_t fake_accountid[0x10] = 
{
    0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
};

//static uint8_t account_id[0x10];

void load_saves_functions();
int readfile(const char *file, uint8_t *buffer, size_t size);
int savefile(const char *path, void *data, size_t size);
//int search_value(char *buf, uint16_t header, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16]);
int new_search_data(char *buf, char *str, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16]);
//int search_str_buf(char *buf, char *str);
int patch_savedatas(const char *path);
//int xreg_data(char *value, int type, int mode, int overwrite, int checkEmpty);
int set_accountID(int mode, int overwrite);

#endif /* _SAVEGAMES_H__ */