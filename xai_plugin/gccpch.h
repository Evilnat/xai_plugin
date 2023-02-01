// gccpch.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently.
// gccpch.h.gch will contain the pre-compiled type information

#include <stdio.h>
#include "x3.h"
#include "xRegistry.h"
#include "cfw_settings.h"

#ifndef __GCCPCH__
#define __GCCPCH__

#define __VIEW__ "ACT0"

#define setNIDfunc(name, module, nid) (void*&)(name) = (void*)((int)getNIDfunc(module, nid))

// TODO: reference additional headers your program requires here
void *getNIDfunc(const char *vsh_module, uint32_t fnid);
int GetPluginInterface(const char *pluginname, int interface_);
int LoadPlugin(char *pluginname, void *handler);

int read_product_mode_flag(void *data);

// NID Functions prx
static int (*FindPlugin)(const char *plugin);
static int (*plugin_GetInterface)(int view,int interface);
static int (*plugin_SetInterface)(int view, int interface, void *Handler);
static int (*plugin_SetInterface2)(int view, int interface, void *Handler);

// NID Functions cfw_settings
static int (*getDiscHashKey)(void*);
static int (*authDisc)();
static int (*cellFsUtilityMount)(const char *device_name, const char *device_fs, const char *device_path, int r6, int write_prot, int r8, int *r9) = 0;
static int (*cellSsAimGetDeviceId)(void *buffer) = 0;
static int (*cellSsAimGetOpenPSID)(void *buffer) = 0;
static int (*Authenticate_BD_Drive)(int cmd) = 0;

static int (*loadModule)(int *fd, char *path, int r5, int r6, int *memorycontainer) = 0;
static int (*ejectDisc)() = 0;
static int (*startJob)(void *job, int(*handler1)(), void *param1, int r6, int r7, uint8_t(*handler2)()) = 0;
static uint8_t *(*getLoadedPlugins)() = 0;

static int (*cellCryptoPuAesCbcCfb128Encrypt)(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv) = 0;
static int (*cellCryptoPuAesCbcCfb128Decrypt)(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv) = 0;
static int (*cellCryptoPuAesEncKeySet)(AES_KEY *aes_key, const unsigned char *user_key, const int bits) = 0;
static int (*cellCryptoPuAesOmac1Mode)(uint8_t *out, uint8_t *input, uint32_t length, uint8_t *key, uint32_t keybits) = 0;

static int (*cellCryptoPuSha1Hmac)(uint8_t *hmac_hash, uint8_t *data_in, int32_t data_length, uint8_t *key, int32_t key_length) = 0;
static int (*cellCryptoPuSha1HmacInit)(uint64_t data[160], uint8_t *key, int32_t key_length) = 0;
static int (*cellCryptoPuSha1HmacTransform)(uint64_t data[160], uint8_t *data_in, int32_t data_length) = 0;
static int (*cellCryptoPuSha1HmacFinal)(uint8_t *hmac_hash, uint64_t data[160]) = 0;

static int (*getPadBattery)(int portNo, uint8_t *status_level) = 0;

static int (*update_mgr_read_eprom)(int offset, void *buffer);      
static int (*update_mgr_write_eprom)(int offset, int value);
static int (*vshmain_74A54CBF)(int r3) = 0;
static int (*vshmain_5F5729FB)(int r3) = 0;

static int (*xBDVDGetInstance)();

static xsetting_D0261D72_class*(*xSettingRegistryGetInterface)() = 0;
static xsetting_AF1F161_class*(*xSettingSystemInfoGetInterface)() = 0;
static xsetting_CC56EB2D_class*(*xUserGetInterface)() = 0;

static void (*NotifyWithTexture)(int32_t, const char *eventName, int32_t, int32_t *texture, int32_t*, const char*, const char*, float, const wchar_t *text, int32_t, int32_t, int32_t);
static uint32_t (*FindTexture)(int32_t *texptr, uint32_t plugin, const char *name);

static void (*free_)(void *);
static void *(*malloc_)(size_t);
static void *(*memalign_)(size_t boundary, size_t size_arg);

static size_t (*wcstombs_)(char *dest, const wchar_t *src, size_t max);
static uint64_t (*stoull_)(const char *ptr, char **endptr, int base);

static FILE *(*fopen_)(const char *filename, const char *mode);
static int (*fclose_)(FILE *stream);
static int (*fprintf_)(FILE *stream, const char *format, ...);
static char *(*ctime_)(const time_t *timer);

static void (*xRegistrySetValue)(unsigned int handle, unsigned int path, unsigned int value, unsigned int size, int unk) = 0;
static int (*xRegistryGetValue)(unsigned int a1, unsigned int a2, unsigned int a3, unsigned int a4, unsigned int a5, unsigned int a6) = 0;
static void (*xGetDefaultInstance)(int a1, int *a2, void *a3, void *a4, void *a5, void *a6) = 0;

static int (*FindString)(int plugin, const char *text);
static uint32_t (*sceNetCtlGetInfoVsh)(uint32_t size, const char *ip);

static int (*cellFsUtilUmount)(const char *device_path, int r4) = 0;

class xai_plugin_interface_action
{	
	public:
		static void xai_plugin_action(const char *action);
};

static void *xai_plugin_action_if[3] = { (void*)xai_plugin_interface_action::xai_plugin_action, 0, 0 };

class xai_plugin_interface
{
	public:	
		static void xai_plugin_init(int view);
		static int xai_plugin_start(void *view);
		static int xai_plugin_stop(void);
		static void xai_plugin_exit(void);
};

static void *xai_plugin_functions[4] = 
{
	(void*)xai_plugin_interface::xai_plugin_init,
	(void*)xai_plugin_interface::xai_plugin_start,
	(void*)xai_plugin_interface::xai_plugin_stop,
	(void*)xai_plugin_interface::xai_plugin_exit
};

#endif
