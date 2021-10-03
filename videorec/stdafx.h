// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

// TODO: reference additional headers your program requires here
static int (*View_Find)(const char *);
static int (*vsh_sprintf)( char*, const char*,...);
static int (*npdr_handler_opd)(const void *buf, unsigned int bufsize);
static int (*plugin_GetInterface)(int view,int interface);
static int (*plugin_SetInterface)(int view, int interface, void * Handler);
static int (*paf_11E195B3_opd)(int view, char * objectname);

static int (*ps3_savedata_plugin_init)(void*);
static int (*sub_CEF84_opd)(int view);

int recording_start(char * action);
static int (*vsh_37857F3F)(int) = 0;
static int (*vsh_F399CA36)(int) = 0;
static int (*vsh_E7C34044)(int) = 0;
static int (*vshmain_A4338777)() = 0;
static int * (*vshmain_75A22E21)() = 0;
static int (*xCore_GetInterface)() = 0;
static int (*xCB_Interface__GetInterface)(int) = 0;
static int (*xCBMini_GetInterface)(int) = 0;

static void * fake_plugin_action_if[3] = { (void*)recording_start, 0, 0 };

static int (*vshtask_A02D46E7)(int, const char *);
static void notify(char * param);
static void notify(const char * format, int param1);

static int (*vshmain_6D5FC398)(int dev_type, int port_num, int intr_type); // BeginInGameXMB

static int (*reco_open)(int);

#define MB(x)		(x*(1024*1024))

struct sfo_hdr
{
	int magic;
	int version;
	int key_table_start;
	int data_table_start;
	int table_entries;
};
struct index_table
{
	short key_1_offset;
	short data_1_fmt;
	int data_1_len;
	int data_1_max_len;
	int data_1_offset;
};

#pragma hdrstop
