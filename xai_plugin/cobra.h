#ifndef _COBRA_H
#define _COBRA_H

#include <stdio.h>
#include <string.h>
#include "cobra.h"

#define PLUGINS_TXT_FILE_ENABLED	"/dev_hdd0/boot_plugins.txt"
#define PLUGINS_TXT_FILE_DISABLED	"/dev_hdd0/boot_plugins.txt.bak"

#define COBRA_USB_FLAG				"/dev_blind/sys/usb_flag"
#define COBRA_USB_FLAG2				"/dev_flash/sys/usb_flag"

#define FAN_DISABLED	0
#define FAN_SYSCON		1
#define DYNAMIC_FAN_60	2
#define DYNAMIC_FAN_65	3
#define DYNAMIC_FAN_70	4
#define DYNAMIC_FAN_75	5
#define FAN_MANUAL		0x70
#define FAN_MAX			0xFF

// Manual Mode
#define FAN_MANUAL_40	0x67
#define FAN_MANUAL_45	0x75
#define FAN_MANUAL_50	0x80
#define FAN_MANUAL_55	0x8E
#define FAN_MANUAL_60	0x9B
#define FAN_MANUAL_65	0xA8
#define FAN_MANUAL_70	0xB5
#define FAN_MANUAL_75	0xC0
#define FAN_MANUAL_80	0xCE
#define FAN_MANUAL_85	0xDA
#define FAN_MANUAL_90	0xE7
#define FAN_MANUAL_95	0xF4

// PS2 Mode
#define FAN_PS2_40		0x66
#define FAN_PS2_50		0x80
#define FAN_PS2_60		0x9A
#define FAN_PS2_70		0xB4
#define FAN_PS2_80		0xCE
#define FAN_PS2_90		0xE8

#define SC_COBRA_SYSCALL8                        			 8
#define SYSCALL8_OPCODE_PS3MAPI             			0x7777

#define SYSCALL8_OPCODE_DISABLE_COBRA					0x0000
#define SYSCALL8_OPCODE_ENABLE_COBRA					0x0001

#define SYSCALL8_DISABLE_COBRA_CAPABILITY				0x0002
#define SYSCALL8_DISABLE_COBRA_STATUS					0x0003
#define SYSCALL8_DISABLE_COBRA_OK						0x5555

#define SYSCALL8_OPCODE_GET_VERSION						0x7000
#define SYSCALL8_OPCODE_GET_VERSION2					0x7001

#define SYSCALL8_OPCODE_GET_DISC_TYPE					0x7020
#define SYSCALL8_OPCODE_READ_PS3_DISC					0x7021
#define SYSCALL8_OPCODE_FAKE_STORAGE_EVENT				0x7022
#define SYSCALL8_OPCODE_GET_EMU_STATE					0x7023
#define SYSCALL8_OPCODE_MOUNT_PS3_DISCFILE				0x7024
#define SYSCALL8_OPCODE_MOUNT_DVD_DISCFILE				0x7025
#define SYSCALL8_OPCODE_MOUNT_BD_DISCFILE				0x7026
#define SYSCALL8_OPCODE_MOUNT_PSX_DISCFILE				0x7027
#define SYSCALL8_OPCODE_MOUNT_PS2_DISCFILE				0x7028
#define SYSCALL8_OPCODE_MOUNT_DISCFILE_PROXY			0x6808
#define SYSCALL8_OPCODE_UMOUNT_DISCFILE					0x702C
#define SYSCALL8_OPCODE_MOUNT_ENCRYPTED_IMAGE			0x702D

#define SYSCALL8_OPCODE_GET_ACCESS						0x8097
#define SYSCALL8_OPCODE_REMOVE_ACCESS					0x8654

#define SYSCALL8_OPCODE_READ_COBRA_CONFIG				0x7050
#define SYSCALL8_OPCODE_WRITE_COBRA_CONFIG				0x7051

#define SYSCALL8_OPCODE_SET_PSP_UMDFILE					0x9003
#define SYSCALL8_OPCODE_SET_PSP_DECRYPT_OPTIONS			0x9002
#define SYSCALL8_OPCODE_READ_PSP_HEADER					0x1028
#define SYSCALL8_OPCODE_READ_PSP_UMD					0x1029
#define SYSCALL8_OPCODE_PSP_PRX_PATCH					0x204C
#define SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART		0x3008
#define SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART	0x3009
#define SYSCALL8_OPCODE_PSP_CHANGE_EMU					0x9752

#define SYSCALL8_OPCODE_COBRA_USB_COMMAND				0x7714

#define SYSCALL8_OPCODE_AIO_COPY_ROOT					0x6637
#define SYSCALL8_OPCODE_MAP_PATHS						0x7964

#define SYSCALL8_OPCODE_VSH_SPOOF_VERSION				0x2C0F

#define SYSCALL8_OPCODE_LOAD_VSH_PLUGIN					0x1EE7
#define SYSCALL8_OPCODE_USE_PS2NETEMU					0x1EE9
#define SYSCALL8_OPCODE_UNLOAD_VSH_PLUGIN				0x364F

#define SYSCALL8_OPCODE_DRM_GET_DATA					0x6A11

#define SYSCALL8_OPCODE_SEND_POWEROFF_EVENT				0x6CDD

// PS3MAPI
#define PS3MAPI_OPCODE_GET_CORE_VERSION                 0x0011
#define PS3MAPI_OPCODE_GET_CORE_MINVERSION              0x0012
#define PS3MAPI_OPCODE_GET_FW_TYPE                      0x0013
#define PS3MAPI_OPCODE_GET_FW_VERSION                   0x0014

#define PS3MAPI_OPCODE_GET_ALL_PROC_PID					0x0021
#define PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID				0x0022
#define PS3MAPI_OPCODE_GET_PROC_BY_PID					0x0023
#define PS3MAPI_OPCODE_GET_CURRENT_PROC					0x0024
#define PS3MAPI_OPCODE_GET_CURRENT_PROC_CRIT			0x0025

#define PS3MAPI_OPCODE_GET_PROC_MEM						0x0031
#define PS3MAPI_OPCODE_SET_PROC_MEM						0x0032
#define PS3MAPI_OPCODE_PROC_PAGE_ALLOCATE				0x0033

#define PS3MAPI_OPCODE_GET_PROC_MODULE_INFO				0x0040
#define PS3MAPI_OPCODE_GET_ALL_PROC_MODULE_PID			0x0041
#define PS3MAPI_OPCODE_GET_PROC_MODULE_NAME				0x0042
#define PS3MAPI_OPCODE_GET_PROC_MODULE_FILENAME			0x0043
#define PS3MAPI_OPCODE_LOAD_PROC_MODULE					0x0044
#define PS3MAPI_OPCODE_UNLOAD_PROC_MODULE				0x0045
#define PS3MAPI_OPCODE_UNLOAD_VSH_PLUGIN				0x0046 
#define PS3MAPI_OPCODE_GET_VSH_PLUGIN_INFO				0x0047 
#define PS3MAPI_OPCODE_GET_PROC_MODULE_SEGMENTS			0x0048 
#define PS3MAPI_OPCODE_GET_VSH_PLUGIN_BY_NAME			0x004F

#define PS3MAPI_OPCODE_GET_IDPS                         0x0081
#define PS3MAPI_OPCODE_SET_IDPS                         0x0082
#define PS3MAPI_OPCODE_GET_PSID                         0x0083
#define PS3MAPI_OPCODE_SET_PSID                         0x0084
#define PS3MAPI_OPCODE_CHECK_SYSCALL                    0x0091
#define PS3MAPI_OPCODE_DISABLE_SYSCALL      			0x0092
#define PS3MAPI_OPCODE_PDISABLE_SYSCALL8    			0x0093
#define PS3MAPI_OPCODE_PCHECK_SYSCALL8 					0x0094
#define PS3MAPI_OPCODE_CREATE_CFW_SYSCALLS				0x0095
#define PS3MAPI_OPCODE_ALLOW_RESTORE_SYSCALLS			0x0096
#define PS3MAPI_OPCODE_GET_RESTORE_SYSCALLS				0x0097
#define PS3MAPI_OPCODE_SWAP_PS2_ICON_COLOR 				0x0098
#define PS3MAPI_OPCODE_REMOVE_HOOK						0x0101
#define PS3MAPI_OPCODE_SUPPORT_SC8_PEEK_POKE			0x1000
#define PS3MAPI_OPCODE_LV2_PEEK							0x1006
#define PS3MAPI_OPCODE_LV2_POKE							0x1007
#define PS3MAPI_OPCODE_LV1_PEEK							0x1008
#define PS3MAPI_OPCODE_LV1_POKE							0x1009

#define PS3MAPI_OPCODE_SET_ACCESS_KEY					0x2000
#define PS3MAPI_OPCODE_REQUEST_ACCESS					0x2001

#define PS3MAPI_OPCODE_AUTO_DEV_BLIND					0x2221
#define PS3MAPI_OPCODE_PHOTO_GUI						0x2222

#define PS3MAPI_OPCODE_GET_FAN_SPEED					0x2233
#define PS3MAPI_OPCODE_SET_CUSTOM_FAN_SPEED	 			0x2234
#define PS3MAPI_OPCODE_SET_FAN_SPEED					0x2235
#define PS3MAPI_OPCODE_SET_PS2_FAN_SPEED				0x2236

#define PS3MAPI_OPCODE_GET_SKIP_EXISTING_RIF			0x2240
#define PS3MAPI_OPCODE_SKIP_EXISTING_RIF				0x2241

#define PS3MAPI_OPCODE_RING_BUZZER 						0x2245

#define PS3MAPI_OPCODE_CREATE_RIF 		 				0x2249

#define PS3MAPI_OPCODE_GAMEBOOT 						0x2250
#define PS3MAPI_OPCODE_EPILEPSY_WARNING					0x2251
#define PS3MAPI_OPCODE_COLDBOOT 						0x2252
#define PS3MAPI_OPCODE_TROPHY 							0x2253

#define SYSCALL8_OPCODE_STEALTH_TEST					0x3993
#define SYSCALL8_OPCODE_STEALTH_ACTIVATE    			0x3995
#define SYSCALL8_STEALTH_OK								0x5555 

#define PS3MAPI_OPCODE_SUPPORT_SC8_PEEK_POKE_OK			0x6789

// HEN
#define SYSCALL8_OPCODE_POKE_LV2						0x7003
#define SYSCALL8_OPCODE_IS_HEN							0x1337
#define SYSCALL8_OPCODE_HEN_REV							0x1339
#define SYSCALL8_OPCODE_GET_MAP_PATH					0x7967
#define SYSCALL8_OPCODE_UNMAP_PATH						0x7962

#ifdef DEBUG
// These debug opcode changed to odd numbers in version 7.0 to minmize crashes with lv1 peek apps
#define SYSCALL8_OPCODE_DUMP_STACK_TRACE				0x5003
#define SYSCALL8_OPCODE_GENERIC_DEBUG					0x5005
#define SYSCALL8_OPCODE_PSP_SONY_BUG					0x5007
#endif

typedef struct
{
	uint16_t size;
	uint16_t checksum;
	uint8_t bd_video_region;
	uint8_t dvd_video_region;
	uint8_t ps2softemu;
	uint32_t spoof_version;
	uint32_t spoof_revision;
	uint8_t fan_speed; 		    // 0 = Disabled | 1 = SYSCON | Dynamic Fan Controller (2 = Max 60°C | 3 = Max 65°C | 4 = Max 70°C | 5 = Max 75°C) | 0x33 to 0xFF = Manual
	uint8_t ps2_speed;		    // 0 = Disabled | 1 = SYSCON | 0x60 | 0x65 | 0x70 | 0x75 | 0x80 | 0x85 | 0x90
	uint8_t allow_restore_sc;   // 0 = Does not allow to restore CFW syscalls | 1 = Allow to restore CFW syscalls 
	uint8_t skip_existing_rif;  // 0 = Does not skip if .rif already exists | 1 = Skip if .rif already exists
	uint8_t color_disc; 	    // 0 = Default (PS2 DVD: yellow disc icon - PS2 CD: blue disc icon) | 1 = PS2 CD/DVD: blue disc icon
	uint8_t syscalls_mode;      // 0 = CFW syscalls are enabled on boot (Default) | 1 = Fully disable CFW syscalls on boot | 2 = Keep PS3M_API Features only
	uint8_t gameboot_mode; 	    // 0 = Disabled (Default) | 1 = Enabled
	uint8_t epilepsy_warning;   // 0 = Disabled (Default) | 1 = Enabled
	uint8_t coldboot_mode; 	    // 0 = Enabled (Default)  | 1 = Disabled 
	uint8_t hidden_trophy_mode; // 0 = Enabled (Default)  | 1 = Disabled (Will show hidden trophy data)
	uint8_t rap_mode; 			// 0 = Disabled (Default) | 1 = Enabled (Load licenses from rap.bin)
} __attribute__((packed)) CobraConfig;

int check_syscall8();
int check_cobra_version();

int cobra_read_config(CobraConfig *cfg);
int cobra_write_config(CobraConfig *cfg);

int sys_get_version(uint32_t *version);
int sys_get_version2(uint16_t *version);

void toggle_plugins();
int toggle_cobra();
void toggle_external_cobra();
int toggle_cobra_version();

int cobra_load_vsh_plugin(int slot, char *path, void *arg, uint32_t arg_size);
int ps3mapi_unload_vsh_plugin(char* name);
int ps3mapi_get_vsh_plugin_info(unsigned int slot, char *name, char *filename);

void create_cfw_syscalls();

#endif /* _COBRA_H */

