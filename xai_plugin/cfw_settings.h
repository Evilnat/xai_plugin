#ifndef _CFW_SETTINGS_H
#define _CFW_SETTINGS_H

#define DEV_BLIND						"/dev_blind"

#define USB_KERNEL						"/dev_usb000/lv2_kernel.self"
#define DBLIND_KERNEL					"/dev_blind/lv2_kernel.self"
#define FLASH_KERNEL					"/dev_flash/lv2_kernel.self"

#define EXT_COBRA						"/dev_blind/sys/ext_cobra"

#define STAGE2_BIN_ENABLED				"/dev_blind/sys/stage2.bin"
#define STAGE2_BIN_DISABLED				"/dev_blind/sys/stage2.bin.bak"
#define STAGE2_BIN_RELEASE				"/dev_blind/sys/stage2.bin.release"
#define STAGE2_BIN_DEBUG				"/dev_blind/sys/stage2.bin.debug"

#define STAGE2_EVILNAT_CEX_ENABLED		"/dev_blind/sys/stage2.cex"
#define STAGE2_EVILNAT_CEX_DISABLED		"/dev_blind/sys/stage2.cex.bak"
#define STAGE2_EVILNAT_CEX_RELEASE		"/dev_blind/sys/stage2.cex.release"
#define STAGE2_EVILNAT_CEX_DEBUG  		"/dev_blind/sys/stage2.cex.debug"
#define STAGE2_EVILNAT_DEX_ENABLED		"/dev_blind/sys/stage2.dex"
#define STAGE2_EVILNAT_DEX_DISABLED		"/dev_blind/sys/stage2.dex.bak"
#define STAGE2_EVILNAT_DEX_RELEASE		"/dev_blind/sys/stage2.dex.release"
#define STAGE2_EVILNAT_DEX_DEBUG  		"/dev_blind/sys/stage2.dex.debug"

#define NPSIGNIN_LCK					"/dev_blind/vsh/resource/npsignin_plugin.lck"

#define RCO_DATE						"/dev_blind/vsh/resource/explore_plugin_full.rco.date"
#define RCO_ORI							"/dev_blind/vsh/resource/explore_plugin_full.rco.ori"
#define RCO_TEMP						"/dev_blind/vsh/resource/explore_plugin_full.rco.tmp"
#define RCO_DEFAULT						"/dev_blind/vsh/resource/explore_plugin_full.rco"

#define REGISTORE_XML					"/dev_blind/vsh/resource/explore/xmb/registory.xml"
#define REGISTORE_XML_TMP				"/dev_blind/vsh/resource/explore/xmb/registory.xml.tmp"

#define TMP_FOLDER						"/dev_hdd0/tmp"
#define LV2_DUMP						"LV2-FW%X.%X%X.bin"
#define LV1_DUMP						"LV1-FW%X.%X%X.bin"
#define RAM_DUMP						"RAM-FW%X.%X%X.bin"
#define VFLASH_DUMP						"VFLASH-FW%X.%X%X.bin"
#define NOR_DUMP						"FLASH-NOR-FW%X.%X%X.bin"
#define NAND_DUMP						"FLASH-NAND-FW%X.%X%X.bin"

#define XREGISTRY_FILE					"/dev_flash2/etc/xRegistry.sys"
#define ACT_DAT_PATH					"/dev_hdd0/home/%08d/exdata/act.dat"

#define TEX_ERROR						"tex_error_ws"
#define TEX_SUCCESS						"tex_check2_ws"
#define TEX_WARNING						"tex_warning"
#define TEX_INFO						"tex_notification_info"
#define TEX_INFO2						"tex_notification_info2"
#define EXPLORE_PLUGIN					"explore_plugin"
#define XAI_PLUGIN						"xai_plugin"

#define FTP_SRPX						"/dev_flash/vsh/module/ftp.sprx"
#define FTPD							"FTPD"
#define MAX_BOOT_PLUGINS 				7

#define LV2							0
#define LV1							1
#define RAM							2

#define SYSCALL_TABLE				0x8000000000363BE0ULL
#define DISABLED					0xFFFFFFFF80010003ULL

#define GPU_CLOCK_PATTERN1			0x0000000100000002ULL
#define GPU_CLOCK_PATTERN2			0x0000000100004028ULL
#define GPU_CLOCK_PATTERN3			0x0000402CULL

#define GPU_DDR3_CLOCK_PATTERN1		0x0000000500000003ULL
#define GPU_DDR3_CLOCK_PATTERN2		0x0000000600004010ULL
#define GPU_DDR3_CLOCK_PATTERN3		0x00004014ULL

#define PRODUCT_MODE_FLAG_OFFSET	0x48C07
#define RECOVERY_MODE_FLAG_OFFSET	0x48C61

#define DUMP_OFFSET					0x2401FC00000ULL
#define DUMP_SIZE					0x40000ULL

#define PRODG_PATCH_OFFSET			0x8000000000003B38ULL
#define PRODG_PATCH					0x386000014E800020ULL

static uint8_t eid2_indiv_seed_[0x40] = 
{		0x74, 0x92, 0xE5, 0x7C, 0x2C, 0x7C, 0x63, 0xF4, 0x49, 0x42, 0x26, 0x8F, 0xB4, 0x1C, 0x58, 0xED, 
        0x66, 0x83, 0x41, 0xF9, 0xC9, 0x7B, 0x29, 0x83, 0x96, 0xFA, 0x9D, 0x82, 0x07, 0x51, 0x99, 0xD8, 
        0xBC, 0x1A, 0x93, 0x4B, 0x37, 0x4F, 0xA3, 0x8D, 0x46, 0xAF, 0x94, 0xC7, 0xC3, 0x33, 0x73, 0xB3, 
        0x09, 0x57, 0x20, 0x84, 0xFE, 0x2D, 0xE3, 0x44, 0x57, 0xE0, 0xF8, 0x52, 0x7A, 0x34, 0x75, 0x3D
};

struct pblock_aes_struct
{
	uint8_t pblock_hdr[0x10];
	uint8_t pblock_des[0x60];
	uint8_t pblock_hash[0x10];
};

struct sblock_aes_struct
{
	uint8_t sblock_hdr[0x10];
	uint8_t sblock_des[0x670];
	uint8_t sblock_hash[0x10];
};

struct eid2_struct
{
	unsigned short pblock_size;
	unsigned short sblock_size;
	uint8_t padding[0x1C];  // 00.... 00 00 / 00 03
	pblock_aes_struct pblock_aes;
	sblock_aes_struct sblock_aes;
};

struct inquiry_block 
{
    uint8_t pkt[0x20];		/* packet command block */ 
    uint32_t pktlen;  
    uint32_t blocks;					
    uint32_t block_size;				
    uint32_t proto;			/* transfer mode */ 
    uint32_t in_out;		/* transfer direction */ 
    uint32_t unknown;
};

enum lv2_atapi_proto 
{
    NON_DATA_PROTO = 0,
    PIO_DATA_IN_PROTO = 1,
    PIO_DATA_OUT_PROTO = 2,
    DMA_PROTO = 3
};

enum lv2_atapi_in_out 
{
    DIR_WRITE = 0,		/* memory -> device */
    DIR_READ = 1		/* device -> memory */
};

struct lv2_atapi_cmnd_block 
{
    uint8_t pkt[0x20];		/* packet command block  */ 
    uint32_t pktlen;  
    uint32_t blocks;					
    uint32_t block_size;				
    uint32_t proto;			/* transfer mode */ 
    uint32_t in_out;		/* transfer direction */ 
    uint32_t unknown;
} __attribute__((packed));

typedef struct _SHACtx
{
	uint8_t data[0x100];
} SHACtx;

#define AES_MAXNR		14

struct aes_key_st 
{
	uint32_t rd_key[4 * (AES_MAXNR + 1)];
	int rounds;
};

typedef struct aes_key_st AES_KEY;

typedef struct function_descriptor 
{
	void	*addr;
	void    *toc;	
} f_desc_t;

int cellFsUtilUnMount(const char *device_path, int r4);
int cellFsUtilMount(const char *device_name, const char *device_fs, const char *device_path, int r6, int write_prot, int r8, int *r9);
int AesCbcCfbEncrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv);
int AesCbcCfbDecrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv);
int aes_omac1(uint8_t *out, uint8_t *input, uint32_t length, uint8_t *key, uint32_t keybits);

int sha1_hmac(uint8_t *hmac_hash, uint8_t *data_in, int32_t data_length, uint8_t *key, int32_t key_length);
int sha1_hmac_starts(uint64_t data[160], uint8_t *key, int32_t key_length);
int sha1_hmac_update(uint64_t data[160], uint8_t *data_in, int32_t data_length);
int sha1_hmac_finish(uint8_t *hmac_hash, uint64_t data[160]);

int GetIDPS(void *idps);

int update_mgr_read_eeprom(int offset, void *buffer);
int update_mgr_write_eeprom(int offset, int value);

void free__(void *ptr);
int malloc__(size_t size);
int memalign__(size_t boundary, size_t size_arg);

void load_cfw_functions();
int RetrieveString(const char *string, const char *plugin);
void PrintString(wchar_t *string, const char *plugin, const char *tex_icon);

void ShowMessage(const char *string, const char *plugin, const char *tex_icon);
int patch_savedata();
int create_rifs();
int getAccountID();
void changeAccountID(int mode, int force);

void backup_license();
void remove_license();

int create_syscalls();
int dump_lv(int lv);
int dumpERK();
int dump_sysrom();
int removeSysHistory();
void checkSyscall(int syscall);

int set_qa(int value);

void fan_speed();

void show_cobra_info();
int save_cobra_fan_cfg(int mode);
int save_ps2_fan_cfg(int mode);

void allow_restore_sc();
void skip_existing_rif();

void check_temp(int mode);

void clean_log();
void log_klic();

void log_secureid();
void enable_recording();
void enable_screenshot();

void override_sfo();

int toggle_cobra();

int toggle_cobra_version();
int toggle_coldboot();
void button_assignment();

void toggle_dlna();

bool enable_hvdbg();

void backup_registry();
void usb_firm_loader();

bool rsod_fix();
int loadKernel();
int filecopy(const char *src, const char *dst);

void remarry_bd();
void toggle_devblind();
void dump_disc_key();

void show_idps();
void dump_idps();

void show_psid();
void dump_psid();

void rebuild_db();

void recovery_mode();
int service_mode();

void applicable_version();
int activate_account();

void check_8th_spe();
void toggle_8th_spe();

//void enable_WhatsNew();

void getClockSpeeds();

void setLed(const char *mode);

void close_xml_list();

int load_ftp();
int unload_ftp();

uint32_t GetCpuClockSpeed();
uint32_t GetGpuClockSpeed();
uint32_t GetGpuGddr3RamClockSpeed();

void spoof_idps();
void spoof_psid();

int Patch_ProDG();
void unlock_hdd_space();

void show_ip();
//int toggle_ext_cobra();
void getPS3Lifetime();

int enable_npsignin_lck();
int disable_npsignin_lck();
void sm_error_log();
void get_token_seed();
void check_ros_bank();

#endif /* _CFW_SETTINGS_H */
