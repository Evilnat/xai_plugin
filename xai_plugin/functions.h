#ifndef __FUNCTIONS__
#define __FUNCTIONS__

#include <stdio.h>
#include "otheros.h"

#define SYS_SHUTDOWN							0x0100
#define SYS_SHUTDOWN2							0x1100
#define SYS_SOFT_REBOOT 						0x0200
#define SYS_HARD_REBOOT							0x1200
#define SYS_LV2_REBOOT							0x8201

#define UPDATE_MGR_PACKET_ID_GET_TOKEN_SEED		0x6009
#define UPDATE_MGR_PACKET_ID_READ_EEPROM		0x600B
#define UPDATE_MGR_PACKET_ID_WRITE_EEPROM		0x600C
#define SPE_8TH_EEPROM_OFFSET					0x48C30
#define ACTIVE_ROS_BANK_OFFSET					0x48C24 

#define SINGLE_BEEP 							0x6
#define DOUBLE_BEEP 							0x36
#define TRIPLE_BEEP 							0x1B6
#define CONTINUOUS_BEEP							0xFFFF

#define LV2										0
#define LV1										1

#define SIGNIN_RCO_LOCK		"/dev_flash/vsh/resource/npsignin_plugin.lck"
#define SIGNIN_RCO_UNLOCK	"/dev_flash/vsh/resource/npsignin_plugin.rco"

typedef struct
{
	uint8_t firmware_version_high;
	uint16_t firmware_version_low;
	uint8_t reserved;
	uint8_t unk1[4];
	char platform_id[8];
	uint32_t firmware_build;
	uint8_t unk2[4];
} __attribute__((__packed__)) system_info;

typedef struct
{
    uint8_t     name[7];
    uint8_t     unknown01;
    uint32_t    unknown02; // random nr?
    uint32_t    zero01;
    uint32_t    unknown03; // 0x28?
    uint32_t    unknown04; // 0xd000e990?
    uint8_t     zero02[16];
    uint64_t    total_sectors;
    uint32_t    sector_size;
    uint32_t    unknown05;
    uint8_t     writable;
    uint8_t     unknown06[3];
    uint32_t    unknown07;
} __attribute__((__packed__)) device_info_t;

typedef struct
{
	uint16_t version; 

	uint8_t padding0[12];

	uint8_t artemis;  
	uint8_t wm_proxy; 
	uint8_t lang;     

	// Scan devices settings
	uint8_t usb0;    
	uint8_t usb1;    
	uint8_t usb2;    
	uint8_t usb3;    
	uint8_t usb6;    
	uint8_t usb7;    
	uint8_t dev_sd;  
	uint8_t dev_ms;  
	uint8_t dev_cf;  
	uint8_t ntfs;    

	uint8_t padding1[5];

	// Scan content settings
	uint8_t refr;  
	uint8_t foot;  
	uint8_t cmask; 

	uint8_t nogrp;   
	uint8_t nocov;   
	uint8_t nosetup; 
	uint8_t rxvid;   
	uint8_t ps2l;    
	uint8_t pspl;    
	uint8_t tid;     
	uint8_t use_filename;  
	uint8_t launchpad_xml; 
	uint8_t launchpad_grp; 
	uint8_t gamei;   
	uint8_t roms;   
	uint8_t noused; 
	uint8_t info;   
	uint8_t npdrm;  
	uint8_t vsh_mc; 
	uint8_t ignore; 
	uint8_t root;   

	uint8_t padding2[11];

	// Start up settings
	uint8_t wmstart; 
	uint8_t lastp;   
	uint8_t autob;   
	char autoboot_path[256]; 
	uint8_t delay;   
	uint8_t bootd;   
	uint8_t boots;   
	uint8_t nospoof; 
	uint8_t blind;   
	uint8_t spp;     
	uint8_t noss;    
	uint8_t nosnd0;  
	uint8_t dsc;     
	uint8_t noBD;    
	uint8_t music;   

	uint8_t padding3[2];

	// Fan control settings
	uint8_t fanc;      
	uint8_t man_speed; 
	uint8_t dyn_temp;  
	uint8_t man_rate;  
	uint8_t ps2_rate;  
	uint8_t nowarn;    
	uint8_t minfan;    
	uint8_t chart;     
	uint8_t maxfan;    

	uint8_t padding4[7];

	// Combo settings
	uint8_t  nopad;      
	uint8_t  keep_ccapi; 
	uint32_t combo;      
	uint32_t combo2;     
	uint8_t  sc8mode;    
	uint8_t  nobeep;     

	uint8_t padding5[20];

	// FTP server settings
	uint8_t  bind;         
	uint8_t  ftpd;         
	uint16_t ftp_port;     
	uint8_t  ftp_timeout;  
	char ftp_password[20];
	char allow_ip[16]; 

	uint8_t padding6[7];

	// Net server settings
	uint8_t  netsrvd;  
	uint16_t netsrvp;  

	uint8_t padding7[13];

	// Net client settings
	uint8_t   netd[5];
	uint16_t  netp[5];
	char neth[5][16];

	uint8_t nsd;
	uint8_t padding8[32];

	// Mount settings
	uint8_t bus;       
	uint8_t fixgame;   
	uint8_t ps1emu;    
	uint8_t autoplay;  
	uint8_t ps2emu;    
	uint8_t ps2config; 
	uint8_t minfo;     
	uint8_t deliso;    
	uint8_t auto_install_pkg; 
	uint8_t app_home;  

	uint8_t padding9[6];

	// Profile settings
	uint8_t profile;          
	char uaccount[9];    
	uint8_t admin_mode;       
	uint8_t unlock_savedata;  

	uint8_t padding10[4];

	// Misc settings
	uint8_t default_restart;  
	uint8_t poll;             

	uint32_t rec_video_format;
	uint32_t rec_audio_format;

	uint8_t auto_power_off; 

	uint8_t ps3mon; 

	uint8_t padding12[4];

	uint8_t homeb; 
	char home_url[255]; 

	uint8_t sman;     
	uint8_t msg_icon; 

	uint8_t padding11[30];

	// Spoof console id
	uint8_t sidps; 
	uint8_t spsid; 
	char vIDPS1[17];
	char vIDPS2[17];
	char vPSID1[17];
	char vPSID2[17];

	uint8_t padding13[24];

	uint8_t resource_id[12];
} __attribute__((packed)) WebmanCfg;

int mount_dev_blind();
int umount_dev_blind();

int lv2_ss_get_cache_of_flash_ext_flag(uint8_t *flag);

bool check_flash_type();

int lv2_storage_get_device_info(uint64_t dev_id, struct storage_device_info *info);
int lv2_storage_open(uint64_t dev_id, uint32_t *dev_handle);
int lv2_storage_close(uint32_t dev_handle);
int lv2_storage_read(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, const void *buf, uint32_t *unknown2, uint64_t flags);
int lv2_storage_write(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, const void *buf, uint32_t *unknown2, uint64_t flags);

int sys_storage_get_device_info(uint64_t device, storage_device_info *device_info);
int sys_storage_get_device_info2(uint64_t device, device_info_t *device_info);
int sys_storage_open(uint64_t dev_id, int *dev_handle);
int sys_storage_close(int fd);
int sys_storage_read(uint32_t dev_handle, uint64_t start_sector, uint64_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint64_t flags);
int sys_storage_read2(int fd, uint32_t start_sector, uint32_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint32_t flags);
int sys_storage_write(int dev_handle, uint64_t start_sector, uint64_t sector_count, uint8_t *buf, uint32_t *sectors_written, uint64_t flags);

int sys_storage_send_device_command(int device_handle, unsigned int command, void *indata, uint64_t inlen, void *outdata, uint64_t outlen);

uint32_t celsius_to_fahrenheit(uint32_t *temp);
int sys_game_get_temperature(int sel, uint32_t *temperature);
int sys_sm_get_fan_policy(uint8_t id, uint8_t *st, uint8_t *mode, uint8_t *speed, uint8_t *unknown);
void sys_sm_set_fan_policy(uint8_t unknown , uint8_t fan_mode, uint8_t fan_speed);

// LV1 Peek/Poke
uint64_t lv1_peek(uint64_t addr);
uint8_t lv1_peek8(uint64_t addr);
uint32_t lv1_peek32(uint64_t addr);
void lv1_poke(uint64_t addr, uint64_t value);
void lv1_poke32(uint64_t addr, uint32_t value);
uint64_t lv1_peek_cobra(uint64_t addr);

// LV2 Peek/Poke
uint64_t lv2_peek(uint64_t addr);
uint8_t lv2_peek8(uint64_t addr); 
uint16_t lv2_peek16(uint64_t addr); 
uint32_t lv2_peek32(uint64_t addr); 
void lv2_poke(uint64_t addr, uint64_t value);
void lv2_poke8(uint64_t addr, uint8_t value); 
void lv2_poke16(uint64_t addr, uint16_t value); 
void lv2_poke32(uint64_t addr, uint32_t value); 

int sys_sm_shutdown(uint16_t op);
void rebootXMB(uint16_t op);

uint32_t GetApplicableVersion(void *data);

void wait(int sleep_time);

int check_cobra_and_syscall();
int get_cobra_fw_version();
int sys_ss_appliance_info_manager_get_ps_code(uint8_t *pscode);

int sys_ss_get_console_id(void *idps);
int sys_ss_get_open_psid(void *psid);

int sys_sm_control_led(uint8_t led_id,uint8_t led_action);
uint32_t sys_sm_request_be_count(uint32_t *status, uint32_t *total_time_in_sec, uint32_t *power_on_counter, uint32_t *power_off_counter);
int sys_sm_get_hw_config(uint8_t *res, uint64_t *hw_config);
int sys_sm_request_scversion(uint64_t *SoftID, uint64_t *old_PatchID, uint64_t *new_PatchID);

uint8_t check_firmware(uint32_t *version);
int sys_sm_get_system_info(system_info *unknown0);
uint32_t lv2_ss_update_mgr_if(uint32_t packet_id, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int sys_sm_request_error_log(uint8_t offset, uint8_t *unknown0, uint32_t *unknown1, uint32_t *unknown2);

int checkSyscalls(int mode);

void buzzer(uint8_t mode);

int check_flash_free_space();

int lv2_gelic_eurus_control(uint16_t cmd, uint8_t *cmdbuf, uint64_t cmdbuf_size);

int is_hen();
int sys_ss_secure_rtc(uint64_t time);
int sysGetCurrentTime(uint64_t *sec, uint64_t *nsec);
int sysSetCurrentTime(uint64_t sec, uint64_t nsec);
int sys_time_get_rtc(uint64_t *real_time_clock);

#endif