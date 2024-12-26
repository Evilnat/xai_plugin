#ifndef __OTHEROS_H__
#define __OTHEROS_H__


#define MIN(a, b)	((a) <= (b) ? (a) : (b))

#define SECTORS												16

#define HEADER_MAGIC										"cell_ext_os_area"
#define HEADER_VERSION										1

#define PETITBOOT_NOR										"dtbImage.ps3.bin"
#define PETITBOOT_NAND										"dtbImage.ps3.bin.minimal"

#define DB_MAGIC											0x2D64622DU
#define DB_VERSION											1

#define PARTITION_TABLE_MAGIC1								0x000000000FACE0FFULL
#define PARTITION_TABLE_MAGIC2								0x00000000DEADFACEULL

#define VFLASH5_DEV_ID										0x100000500000001ULL
#define VFLASH5_SECTOR_SIZE									0x200ULL
#define VFLASH5_SECTORS										0xC000ULL
#define VFLASH5_HEADER_SECTORS								0x2ULL
#define VFLASH5_OS_DB_AREA_SECTORS							0x2ULL

#define OS_AREA_SEGMENT_SIZE								0x200

/* VFLASH */
#define VFLASH_DEV_ID										0x100000000000001ULL
#define VFLASH_SECTOR_SIZE									0x200ULL
#define VFLASH_START_SECTOR									0x0ULL
#define VFLASH_SECTOR_COUNT									0x2ULL
#define VFLASH_FLAGS										0x6ULL

#define VFLASH_PARTITION_TABLE_6ND_REGION_OFFSET			0x270ULL
#define VFLASH_6TH_REGION_NEW_SECTOR_COUNT					0xC000ULL

#define VFLASH_PARTITION_TABLE_7TH_REGION_OFFSET			0x300ULL
#define VFLASH_7TH_REGION_NEW_START_SECTOR					0x7FA00ULL

/* NAND FLASH */
#define FLASH_DEV_ID										0x100000000000001ULL
#define FLASH_SECTOR_SIZE									0x200ULL
#define FLASH_START_SECTOR									0x7600ULL
#define FLASH_SECTOR_COUNT									0x2ULL
#define NFLASH_FLAGS										0x6ULL

#define FLASH_PARTITION_TABLE_6ND_REGION_OFFSET				0x270ULL
#define FLASH_6TH_REGION_NEW_START_SECTOR					0x73A00ULL
#define FLASH_6TH_REGION_NEW_SECTOR_COUNT					0x4200ULL

#define FLASH_PARTITION_TABLE_7TH_REGION_OFFSET				0x300ULL
#define FLASH_7TH_REGION_NEW_START_SECTOR					0x77C00ULL
#define FLASH_7TH_REGION_NEW_SECTOR_COUNT					0x200ULL

#define FLASH_REGION_LPAR_AUTH_ID							0x1070000002000001ULL
#define FLASH_REGION_ACL									0x3ULL

#define	GAMEOS_FLAG											0
#define	OTHEROS_FLAG										1

struct storage_device_info 
{
	uint8_t res1[32];
	uint32_t vendor_id;
	uint32_t device_id;
	uint64_t capacity;
	uint32_t sector_size;
	uint32_t media_count;
	uint8_t res2[8];
};

enum os_area_ldr_format 
{
	HEADER_LDR_FORMAT_RAW = 0,
	HEADER_LDR_FORMAT_GZIP = 1,
};

enum os_area_boot_flag 
{
	PARAM_BOOT_FLAG_GAME_OS = 0,
	PARAM_BOOT_FLAG_OTHER_OS = 1,
};

struct os_area_header 
{
	uint8_t magic[16];
	uint32_t version;
	uint32_t db_area_offset;
	uint32_t ldr_area_offset;
	uint32_t res1;
	uint32_t ldr_format;
	uint32_t ldr_size;
	uint32_t res2[6];
};

struct os_area_params 
{
	uint32_t boot_flag;
	uint32_t res1[3];
	uint32_t num_params;
	uint32_t res2[3];

	/* param 0 */
	int64_t rtc_diff;
	uint8_t av_multi_out;
	uint8_t ctrl_button;
	uint8_t res3[6];

	/* param 1 */
	uint8_t static_ip_addr[4];
	uint8_t network_mask[4];
	uint8_t default_gateway[4];
	uint8_t res4[4];

	/* param 2 */
	uint8_t dns_primary[4];
	uint8_t dns_secondary[4];
	uint8_t res5[8];
};

struct os_area_db 
{
	uint32_t magic;
	uint16_t version;
	uint16_t res1;
	uint16_t index_64;
	uint16_t count_64;
	uint16_t index_32;
	uint16_t count_32;
	uint16_t index_16;
	uint16_t count_16;
	uint32_t res2;
	uint8_t res3[1000];
};

int setup_vflash();
int setup_flash();
int install_petitboot();
int set_flag(int flag);

#endif __OTHEROS_H__