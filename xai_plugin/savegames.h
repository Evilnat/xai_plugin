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

struct rif_t
{
   uint32_t version;           // version
   uint32_t licenseType;       // license type
   uint64_t accountid;         // accountID
   char titleid[0x30];		   // Content ID
   uint8_t padding[0xC];       // Padding for randomness
   uint32_t actDatIndex;       // Key index on act.dat between 0x00 and 0x7F
   uint8_t key[0x10];          // encrypted klicensee
   uint64_t start_timestamp;   // timestamp of when the content was bought
   uint64_t expire_timestamp;  // timestamp for expiration of content (PS+ for example)
   uint8_t r[0x14];            // Unknown
   uint8_t s[0x14];            // Unknown
};

struct actdat_t
{
    uint32_t version;        // version
    uint32_t licenseType;    // license type
    uint64_t accountId;      // accountID
    uint8_t keyTable[0x800]; // Key Table
    uint8_t unknown[0x800];  // Unknown (timestamp,...)
    uint8_t signature[0x28]; // Signature
};

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

static uint8_t rap_initial_key[16] = 
{
	0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF
};

static uint8_t pbox[16] = 
{
	0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09
};

static uint8_t e1[16] = 
{
	0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5
};

static uint8_t e2[16] = 
{
	0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74
};

static uint8_t rif_key_const[0x10] = 
{ 
	0xDA, 0x7D, 0x4B, 0x5E, 0x49, 0x9A, 0x4F, 0x53, 0xB1, 0xC1, 0xA1, 0x4A, 0x74, 0x84, 0x44, 0x3B 
};

static uint8_t idps_const[0x10] =
{ 
	0x5E, 0x06, 0xE0, 0x4F, 0xD9, 0x4A, 0x71, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 
};

void load_saves_functions();
int search_data(char *buf, char *str, int type, int mode, int overwrite, int checkEmpty, uint8_t output[16]);
int patch_savedatas(const char *path);
int set_accountID(int mode, int overwrite);

int export_rap();

#endif /* _SAVEGAMES_H__ */