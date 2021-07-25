#ifndef __FUNCTIONS__
#define __FUNCTIONS__

#include <stdio.h>

#define SYS_SHUTDOWN		0x0100
#define SYS_SHUTDOWN2		0x1100
#define SYS_SOFT_REBOOT 	0x0200
#define SYS_HARD_REBOOT		0x1200
#define SYS_LV2_REBOOT		0x8201

#define SIGNIN_RCO_LOCK			"/dev_flash/vsh/resource/npsignin_plugin.lck"
#define SIGNIN_RCO_UNLOCK		"/dev_flash/vsh/resource/npsignin_plugin.rco"

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
} __attribute__((packed)) device_info_t;

int mount_dev_blind();
int umount_devblind();

int lv2_ss_get_cache_of_flash_ext_flag(uint8_t *flag);

bool check_flash_type();

int sys_storage_get_device_info(uint64_t device, device_info_t *device_info);

int sys_storage_read2(int fd, uint32_t start_sector, uint32_t sectors, uint8_t *bounce_buf, uint32_t *sectors_read, uint32_t flags);
int sys_storage_open(uint64_t id, int *fd);
int sys_storage_close(int fd);

int sys_storage_send_device_command(int device_handle, unsigned int command, void *indata, uint64_t inlen, void *outdata, uint64_t outlen);

uint32_t celsius_to_fahrenheit(uint32_t *temp);
int sys_game_get_temperature(int sel, uint32_t *temperature);
int sys_sm_get_fan_policy(uint8_t id, uint8_t *st, uint8_t *mode, uint8_t *speed, uint8_t *unknown);
void sys_sm_set_fan_policy(uint8_t unknown , uint8_t fan_mode, uint8_t fan_speed);

uint64_t lv1_peek(uint64_t addr);
void lv1_poke( uint64_t addr, uint64_t val);
uint64_t peekq(uint64_t addr);
uint8_t peekq8(uint64_t address);
uint16_t peekq16(uint64_t address);
uint32_t peekq32(uint64_t address);
void pokeq( uint64_t addr, uint64_t val);
void pokeq8(uint64_t addr, uint8_t value);
void pokeq16(uint64_t addr, uint16_t value);
void pokeq32(uint64_t address, uint32_t value);

int sys_sm_shutdown(uint16_t op);
void xmb_reboot(uint16_t op);

uint32_t GetApplicableVersion(void *data);

void wait(int sleep_time);
int check_cobra();

int check_cobra_and_syscall();
int get_cobra_fw_version();

int sys_ss_get_console_id(void *idps);
int sys_ss_get_open_psid(void *psid);

int sys_sm_control_led(uint8_t led_id,uint8_t led_action);

uint8_t check_firmware(uint32_t *version);
uint64_t check_kernel(uint64_t *type);

int check_syscalls();

#endif