#ifndef __CEX2DEX_H__
#define __CEX2DEX_H__

#define EID_ROOT_KEY_HDD0				"/dev_hdd0/tmp/eid_root_key"

#define VSH_SELF_DEFAULT				"/dev_blind/vsh/module/vsh.self"
#define VSH_SELF_CEX					"/dev_blind/vsh/module/vsh.self.cex"
#define VSH_SELF_DEX					"/dev_blind/vsh/module/vsh.self.dex"

#define XMB_SPRX_DEFAULT				"/dev_blind/vsh/module/xmb_plugin.sprx"
#define XMB_SPRX_CEX					"/dev_blind/vsh/module/xmb_plugin.sprx.cex"
#define XMB_SPRX_DEX					"/dev_blind/vsh/module/xmb_plugin.sprx.dex"

#define SYSCONF_SPRX_DEFAULT			"/dev_blind/vsh/module/sysconf_plugin.sprx"
#define SYSCONF_SPRX_CEX				"/dev_blind/vsh/module/sysconf_plugin.sprx.cex"
#define SYSCONF_SPRX_DEX				"/dev_blind/vsh/module/sysconf_plugin.sprx.dex"

#define SOFTWARE_UPDATE_SPRX_DEFAULT	"/dev_blind/vsh/module/software_update_plugin.sprx"
#define SOFTWARE_UPDATE_SPRX_CEX		"/dev_blind/vsh/module/software_update_plugin.sprx.cex"
#define SOFTWARE_UPDATE_SPRX_DEX		"/dev_blind/vsh/module/software_update_plugin.sprx.dex"

#define FLASH_DEVICE_NAND	0x0100000000000001ULL
#define FLASH_DEVICE_NOR	0x0100000000000004ULL
#define FLASH_FLAGS			0x22ULL

#define DEX_OFFSET			0x800000000030F3B0ULL
#define CEX_OFFSET			0x80000000002ED818ULL

#define CEX					0x4345580000000000ULL
#define DEX					0x4445580000000000ULL

#define FLASH_NOR			1
#define FLASH_NAND			0

#define KEY_BITS(ks)		(ks * 8)
#define INDIV_CHUNK_SIZE	0x40
#define ISO_ROOT_KEY_SIZE	0x20
#define ISO_ROOT_IV_SIZE	0x10
#define IDPS_SIZE			0x10

#define SECTORS				16

#define NOR_BYTES			0x1000000
#define NAND_BYTES			0x10000000

#define CEX_TO_DEX			0
#define DEX_TO_CEX			1

int recieve_eid5_idps(uint8_t output[0x10]);
int check_targetid(int mode);
void get_ps3_info();
int dump_flash();
void cex2dex(int mode);
void swap_kernel();

int spoof_with_eid5();
int toggle_xmbplugin();
int toggle_vsh();
int toggle_sysconf();

#endif __CEX2DEX_H__