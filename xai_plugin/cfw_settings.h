#ifndef _CFW_SETTINGS_H
#define _CFW_SETTINGS_H

#define STAGE2_BIN_ENABLED		"/dev_blind/sys/stage2.bin"
#define STAGE2_BIN_DISABLED		"/dev_blind/sys/stage2.bin.bak"
#define STAGE2_BIN_RELEASE		"/dev_blind/sys/stage2.bin.release"
#define STAGE2_BIN_DEBUG		"/dev_blind/sys/stage2.bin.debug"

#define RCO_DATE				"/dev_blind/vsh/resource/explore_plugin_full.rco.date"
#define RCO_ORI					"/dev_blind/vsh/resource/explore_plugin_full.rco.ori"
#define RCO_TEMP				"/dev_blind/vsh/resource/explore_plugin_full.rco.tmp"
#define RCO_DEFAULT				"/dev_blind/vsh/resource/explore_plugin_full.rco"

#define REGISTORE_XML			"/dev_blind/vsh/resource/explore/xmb/registory.xml"
#define REGISTORE_XML_TMP		"/dev_blind/vsh/resource/explore/xmb/registory.xml.tmp"

#define TMP_FOLDER				"/dev_hdd0/tmp"
#define LV2_DUMP				"LV2-FW%X.%X%X.bin"
#define LV1_DUMP				"LV1-FW%X.%X%X.bin"
#define XREGISTRY_FILE			"/dev_flash2/etc/xRegistry.sys"
#define ACT_DAT_PATH			"/dev_hdd0/home/%08d/exdata/act.dat"

#define TEX_ERROR				"tex_error_ws"
#define TEX_SUCCESS				"tex_check2_ws"
#define TEX_WARNING				"tex_warning"
#define TEX_INFO				"tex_notification_info"
#define TEX_INFO2				"tex_notification_info2"
#define EXPLORE_PLUGIN			"explore_plugin"
#define XAI_PLUGIN				"xai_plugin"

#define LV2				0
#define LV1				1

#define PRODUCT_MODE_FLAG_OFFSET	0x48C07
#define RECOVERY_MODE_FLAG_OFFSET	0x48C61

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

typedef struct function_descriptor 
{
	void	*addr;
	void    *toc;	
} f_desc_t;

void load_cfw_functions();
int RetrieveString(const char *string, const char *plugin);
void PrintString(wchar_t *string, const char *plugin, const char *tex_icon);

void ShowMessage(const char *string, const char *plugin, const char *tex_icon);
int patch_savedata();
int create_rifs();
int getAccountID();
void changeAccountID(bool force);

void backup_license();
void remove_license();

int create_syscalls();
int dump_lv(int lv);
int dumpERK();
int removeSysHistory();
void checkSyscall(int syscall);

void check_QA();
int set_qa(int value);

void fan_speed();

void show_cobra_info();
int save_cobra_fan_cfg(int mode);
int save_ps2_fan_cfg(int mode);

void allow_restore_sc();
void skip_existing_rif();

void check_temp();

void clean_log();
void log_klic();

void log_secureid();
void enable_recording();
void enable_screenshot();

void override_sfo();

int toggle_cobra();

int toggle_cobra_version();
int toggle_sysconf();
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
void control_led(const char * action);

void show_idps();
void dump_idps();

void show_psid();
void dump_psid();

void rebuild_db();

void recovery_mode();
int service_mode();

void applicable_version();
void activate_account();

void enable_WhatsNew();

void searchDirectory(char *pDirectoryPath, char *fileformat, char *fileout);
void installPKG(char *path);
void downloadPKG(wchar_t *url);

int cellFsUtilUnMount(const char *device_path, int r4);
int cellFsUtilMount(const char *device_name, const char *device_fs, const char *device_path, int r6, int write_prot, int r8, int *r9);

#endif /* _CFW_SETTINGS_H */
