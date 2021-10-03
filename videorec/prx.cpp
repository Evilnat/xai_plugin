#include "stdafx.h"
#include "ps3_savedata_plugin.h"
#include "game_plugin.h"
#include "rec_plugin.h"
#include "x3.h"
#include "impose_plugin.h"

#include <cellstatus.h>
#include <sys/prx.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#include <sys/paths.h>
#include <sys/fs.h>
#include <sys/fs_external.h>
#include <cell/cell_fs.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/memory.h>
#include <sysutil/sysutil_rec.h>
#include <cell/rtc.h>
#include <sys/timer.h>
#include <sys/ppu_thread.h>
#include <cell/pad.h>

#include "recording_settings.h"

SYS_MODULE_INFO( videorec, 0, 1, 1);
SYS_MODULE_START( _videorec_prx_entry );
SYS_MODULE_STOP( _videorec_prx_stop );
SYS_MODULE_EXIT( _videorec_prx_exit );

SYS_LIB_DECLARE_WITH_STUB( LIBNAME, SYS_LIB_AUTO_EXPORT|SYS_LIB_WEAK_IMPORT, STUBNAME );
SYS_LIB_EXPORT( _videorec_export_function, LIBNAME );

SYS_LIB_EXPORT( _videorec_export_function_video_rec, LIBNAME );
SYS_LIB_EXPORT( _videorec_export_function_klicensee, LIBNAME );
SYS_LIB_EXPORT( _videorec_export_function_secureid, LIBNAME );
SYS_LIB_EXPORT( _videorec_export_function_sfoverride, LIBNAME );

void * getNIDfunc(const char * vsh_module, uint32_t fnid)
{	
	// 0x10000 = ELF
	// 0x10080 = segment 2 start
	// 0x10200 = code start	

	uint32_t table = (*(uint32_t*)0x1008C) + 0x984; // vsh table address
	
	while(((uint32_t)*(uint32_t*)table) != 0)
	{
		uint32_t* export_stru_ptr = (uint32_t*)*(uint32_t*)table; // ptr to export stub, size 2C, "sys_io" usually... Exports:0000000000635BC0 stru_635BC0:    ExportStub_s <0x1C00, 1, 9, 0x39, 0, 0x2000000, aSys_io, ExportFNIDTable_sys_io, ExportStubTable_sys_io>
			
		const char* lib_name_ptr =  (const char*)*(uint32_t*)((char*)export_stru_ptr + 0x10);
				
		if(strncmp(vsh_module,lib_name_ptr,strlen(lib_name_ptr)) == 0)
		{
			// we got the proper export struct
			uint32_t lib_fnid_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x14);
			uint32_t lib_func_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x18);
			uint16_t count = *(uint16_t*)((char*)export_stru_ptr + 6); // amount of exports

			for(int i = 0; i < count; i++)
			{
				if(fnid == *(uint32_t*)((char*)lib_fnid_ptr + i * 4))				
					return (void*&)*((uint32_t*)(lib_func_ptr) + i);				
			}
		}

		table = table + 4;
	}

	return 0;
}

void hook_func(void * original,void * backup, void * hook_function)
{
	memcpy(backup,original,8); // copy original function offset + toc
	memcpy(original, hook_function ,8); // replace original function offset + toc by hook
}
void restore_func(void * original,void * backup)
{
	memcpy(original,backup,8); // copy original function offset + toc
}
int console_write(const char * s)
{ 
	uint32_t len;
	system_call_4(403, 0, (uint64_t) s, std::strlen(s), (uint64_t) &len);
	return_to_user_prog(int);
}
void log(char * buffer)
{
	console_write(buffer);
	int size = strlen(buffer);
	CellFsErrno err;
	int fd;
	uint64_t nrw;
	
	if(cellFsOpen("/dev_hdd0/tmp/cfw_settings.log", CELL_FS_O_RDWR|CELL_FS_O_CREAT|CELL_FS_O_APPEND, &fd, NULL, 0) != CELL_OK)
	{
		//notify("unable to open.");
	}
	else
	{
		if(cellFsWrite(fd, buffer, size, &nrw) !=CELL_OK)
		{
			//notify("unable to write.");
		}
		else
		{
			//notify("data written.");
		}
	}
	err = cellFsClose(fd);
}
void log(char * format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}
void log(char * format, char * param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}
void log_key(char * keyname,void * key)
{
	log("%s: ",keyname);log("%08X",*(int*)key);log("%08X",*((int*)key+1));log("%08X",*((int*)key+2));log("%08X\n",*((int*)key+3));
}
void log_data(const void * buffer, int bufsize)
{	
	//log("Dumping Data:\n");
	char tmp[0x30];
	for(int i=0;i<bufsize;i=i+0x10)
	{
		log("%08X  ", ((int)buffer)+i);
		for(int j=0;j<0x10;j++)
		{
			char * o = (char*)buffer + i + j;
			log("%02X ",(unsigned char)(*o));
		}
		for(int j=0;j<0x10;j++)
		{
			char * o = (char*)buffer + i + j;
			log("%c",(unsigned char)(*o));
		}
		//log(hex_dump(tmp,((int)buffer)+i,0x10));
		log("\n");
	}
}



// An exported function is needed to generate the project's PRX stub export library
extern "C" int _videorec_export_function(void)
{
    return CELL_OK;
}

bool recording_hooked = false;
extern "C" int _videorec_export_function_video_rec(void)
{	

}





bool klic_hooked = false;
int npdr_handler(const void * buffer, unsigned int bufsize){};
int (*npdr_handler_)(const void * buffer, unsigned int bufsize)=npdr_handler;
int npdr_handler_hook(const void * buffer,unsigned int bufsize)
{
	log_key("klicensee",(void*)((int)buffer+0xA4));
	log("File: ");log((char*)((int)buffer+0xB4));log("\n");
	return npdr_handler_(buffer,bufsize);
}
extern "C" int _videorec_export_function_klicensee(void)
{
	if(klic_hooked == false)
	{
		hook_func((void*)npdr_handler_opd, (void*)npdr_handler_ ,(void*)npdr_handler_hook );
		klic_hooked = true;
		return CELL_OK;
	}
	else
	{
		restore_func((void*)npdr_handler_opd,(void*)npdr_handler_);
		klic_hooked = false;
		return 1;
	}
}





bool securfileid_hooked = false;
int (*DoUnk13_)(int*,int*,char*,int,void *) = 0;
int ps3_interface_function13_hook(int* r3,int* r4,char* r5,int r6,void * key)
{
	log(" Filename: %s\n",r5);
	log_key("Secure File ID",key);
	return DoUnk13_(r3,r4,r5,r6,key);
}
int ps3_savedata_plugin_init__(void * view){};
int (*ps3_savedata_plugin_init_bk)(void * view) = ps3_savedata_plugin_init__;
int ps3_savedata_plugin_init_hook(void * view)
{
	ps3_savedata_plugin_game_interface * ps3_savedata_interface;
	
	ps3_savedata_interface = (ps3_savedata_plugin_game_interface *) plugin_GetInterface(View_Find("ps3_savedata_plugin"),1);
	if(ps3_savedata_interface->DoUnk13 != ps3_interface_function13_hook)
	{
		DoUnk13_ = ps3_savedata_interface->DoUnk13;
		ps3_savedata_interface->DoUnk13 = ps3_interface_function13_hook;
		log("Secure File Id Hook placed.\n");
	}

	return ps3_savedata_plugin_init_bk(view);
}
extern "C" int _videorec_export_function_secureid(void)
{
	if(securfileid_hooked==false)
	{
		hook_func((void*)ps3_savedata_plugin_init, (void*)ps3_savedata_plugin_init_bk ,(void*)ps3_savedata_plugin_init_hook );
		securfileid_hooked = true;
		return CELL_OK;
	}
	else
	{
		restore_func((void*)ps3_savedata_plugin_init, (void*)ps3_savedata_plugin_init_bk);
		securfileid_hooked = false;
		return 1;
	}
}





bool sfoverride_hooked = false;
bool print_sysver = false;
bool print_attribute = false;
int x3_0xD277E345_(int r3,int * index_table, int * out){};
int (*x3_0xD277E345_bk)(int r3,int * index_table, int * out) = x3_0xD277E345_;
int x3_0xD277E345_hook(int r3,int * index_table, int * out)
{
	int ret = x3_0xD277E345_bk(r3,index_table,out);
	if(ret == CELL_OK)
	{
		if(print_sysver == true)
		{
			print_sysver = false;
			char * str = (char*)(*out);
			log("PS3_SYSTEM_VER: %s\n",str);
			str[0] = 0; // fallback 00.00 :D
			strcpy(str,"02.8000"); // lets just use some lower firmware :)
		}
		if(print_attribute == true)
		{
			print_attribute = false;
			int * str = (int*)(*out);
			log("ATTRIBUTE: %08x\n",*str);
			*str = *str | 0xA5000000;
		}
	}
}
int x3_0xA06976E_(int r3,int * index_table, int * out, int * r6, int * max_len){};
int (*x3_0xA06976E_bk)(int r3,int * index_table, int * out, int * r6, int * max_len) = x3_0xA06976E_;
int x3_0xA06976E_hook(int r3,int * index_table, int * out, int * r6, int * max_len)
{	
	if(*out != 0)
	{
		char * str = (char*)(*out);
		if(strcmp(str,"PS3_SYSTEM_VER")==0)
		{
			//print_sysver = true;
		}
		if(strcmp(str,"ATTRIBUTE")==0)
		{
			print_attribute = true;
		}
	}

	int ret = x3_0xA06976E_bk(r3,index_table,out,r6,max_len);
	return ret;
}
int GetItemFromMetaList_(int metalist,int item, char * objectfield, int * out){};
int (*GetItemFromMetaList_bk)(int metalist,int item, char * objectfield, int * out) = GetItemFromMetaList_;
int GetItemFromMetaList_hook(int metalist,int item, char * objectfield, int * out)
{
	int ret = GetItemFromMetaList_bk(metalist,item,objectfield,out);
	if(ret == CELL_OK)
	{
		if(out[2] != 0)
		{
			if(strcmp(objectfield,"Game:Game.ps3SystemVer") == 0)
			{
				//log("Game:Game.ps3SystemVer: %s\n",(char*)out[2]);
				//((char*)(out[2]))[0] = 0;
			}
			if(strcmp(objectfield,"Game:Game.attribute") == 0)
			{
				log("Game:Game.attribute: %x\n",*(int*)out[2]);
				*(int*)out[2] = *(int*)out[2] | 0xA5;
				log_data(out,0x10);
			}
			//log("ObjectField: "); 
			//log(objectfield);
			//log(" -> ");
			//log((char*)out[2]);
			//log("\n");
		}
	}
	return ret;
}
int GetItemFromMetaList_Mini_(int metalist,int item, char * objectfield, int * out){};
int (*GetItemFromMetaList_bk_Mini)(int metalist,int item, char * objectfield, int * out) = GetItemFromMetaList_Mini_;
int GetItemFromMetaList_hook_Mini(int metalist,int item, char * objectfield, int * out)
{
	int ret = GetItemFromMetaList_bk_Mini(metalist,item,objectfield,out);
	if(ret == CELL_OK)
	{
		if(out[2] != 0)
		{
			if(strcmp(objectfield,"Game:Game.ps3SystemVer") == 0)
			{
				//log("Game:Game.ps3SystemVer: %s\n",(char*)out[2]);
				//((char*)(out[2]))[0] = 0;
			}
			if(strcmp(objectfield,"Game:Game.attribute") == 0)
			{
				log("Game:Game.attribute: %x\n",*(int*)out[2]);
				*(int*)out[2] = *(int*)out[2] | 0xA5;
			}
			//log("ObjectField: "); 
			//log(objectfield);
			//log(" -> ");
			//log((char*)out[2]);
			//log("\n");
		}
	}
	return ret;
}

#define PSPREMOTEPLAYV1 1
#define PSPREMOTEPLAYV2 4
#define VITAREMOTEPLAY	0x80
#define SYSTEMBGM		0x20

int sys_game_get_system_sw_version() 
{
	system_call_0(376);
	return_to_user_prog(int);
}

#define swap(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))
#define swap16(x) ((((x) & 0xFF00) >> 8) | (((x) << 8) & 0x00FF))

void override_sfo(void * buf)
{
	sfo_hdr * hdr = (sfo_hdr*)buf;	
	void * key_table = (void*)((int)buf + ((int)swap(hdr->key_table_start)));
	void * data_table = (void*)((int)buf + ((int)swap(hdr->data_table_start)));
	void * idx_table = (void*)((int)buf + 0x14);

	for(int i = 0; i < swap(hdr->table_entries); i++)
	{			
		index_table * idx = (index_table *)((int)idx_table + i*0x10 );		
		
		char * key_1 =  (char*)((int)key_table + ((int)swap16(idx->key_1_offset)));
		
		uint8_t * data_1 = (uint8_t*)((int)data_table + ((int)swap(idx->data_1_offset)));
		
		if(strcmp(key_1,"ATTRIBUTE") == 0)
		{
			log("Activate Flags:\n");
			log("[x] PSP Remote Play (v1)\n");
			log("[x] PSP Remote Play (v2)\n");
			log("[x] Vita Remote Play\n");
			log("[x] InGame System BGM\n");
			data_1[0] = data_1[0] | (PSPREMOTEPLAYV1 | PSPREMOTEPLAYV2 | VITAREMOTEPLAY |SYSTEMBGM );
		}
		if(strcmp(key_1,"PS3_SYSTEM_VER") == 0)
		{
			int sw_version = sys_game_get_system_sw_version();
			log("system sdk_version: %d\n", sw_version);

			int sfo_version = 0;
			sfo_version = ((((data_1[1]) - 0x30) & 0x0F) * 10000) + ((((data_1[3]) - 0x30) & 0x0F) * 1000) + ((((data_1[4]) - 0x30) & 0x0F) * 100);

			log("sfo sdk_version: %d\n", sfo_version);

			if( sfo_version > sw_version )
			{
				//log("PS3_SYSTEM_VER change to 1.0\n");
				//strcpy(key_1,"01.0000");				
			}
		}
	}
}
bool reading_sfo = false;
int cellFsOpen_(const char *path,int flags,int *fd,void *arg,uint64_t size){};
int (*cellFsOpen_bk)(const char *path,int flags,int *fd,void *arg,uint64_t size) = cellFsOpen_;
int cellFsOpen_hook(const char *path,int flags,int *fd,void *arg,uint64_t size)
{
	reading_sfo = false;
	if(strcmp(path,"/dev_hdd0/tmp/cfw_settings.log") == 0)
	{
		return cellFsOpen_bk(path,flags,fd,arg,size);
	}
	else
	{
		if(strcmp(path,"/dev_bdvd/PS3_GAME/PARAM.SFO")==0)//strstr(path,".SFO") != 0)
		{
			//log("cellFsOpen(%s)\n",(char*)path);
			reading_sfo = true;
		}
		return cellFsOpen_bk(path,flags,fd,arg,size);
	}	
}
int cellFsRead_(int fd, void *buf, uint64_t nbytes, uint64_t *nread){};
int (*cellFsRead_bk)(int fd, void *buf, uint64_t nbytes, uint64_t *nread) = cellFsRead_;
int cellFsRead_hook(int fd, void *buf, uint64_t nbytes, uint64_t *nread)
{
	if(reading_sfo == true)
	{
		if(nbytes > 0x200)
		{
			//log("cellFsRead(%x,",(int) buf);
			//log("%x)\n",(int)nbytes);
			int ret = cellFsRead_bk(fd,buf,nbytes,nread);
			//log_data(buf,nbytes);
			override_sfo(buf);
			return ret;
		}
	}
	return cellFsRead_bk(fd,buf,nbytes,nread);
}
extern "C" int _videorec_export_function_sfoverride(void)
{	
	if(sfoverride_hooked==false)
	{
		hook_func((void*)((int)getNIDfunc("sys_fs",0x718BF5F8)), (void*)cellFsOpen_bk ,(void*)cellFsOpen_hook );
		hook_func((void*)((int)getNIDfunc("sys_fs",0x4D5FF8E2)), (void*)cellFsRead_bk ,(void*)cellFsRead_hook );
		hook_func((void*)((int)getNIDfunc("x3",0xA06976E)), (void*)x3_0xA06976E_bk ,(void*)x3_0xA06976E_hook );
		hook_func((void*)((int)getNIDfunc("x3",0xD277E345)), (void*)x3_0xD277E345_bk ,(void*)x3_0xD277E345_hook );

		int *x3interface =  (int*)xCB_Interface__GetInterface(xCore_GetInterface());
		hook_func((void*)x3interface[39], (void*)GetItemFromMetaList_bk ,(void*)GetItemFromMetaList_hook );

		x3interface =  (int*)xCBMini_GetInterface(xCore_GetInterface());
		hook_func((void*)x3interface[39], (void*)GetItemFromMetaList_bk_Mini ,(void*)GetItemFromMetaList_hook_Mini );

		sfoverride_hooked = true;
		return CELL_OK;
	}
	else
	{
		restore_func((void*)((int)getNIDfunc("sys_fs",0x718BF5F8)), (void*)cellFsOpen_bk );
		restore_func((void*)((int)getNIDfunc("sys_fs",0x4D5FF8E2)), (void*)cellFsRead_bk );
		restore_func((void*)((int)getNIDfunc("x3",0xA06976E)), (void*)x3_0xA06976E_bk);
		restore_func((void*)((int)getNIDfunc("x3",0xD277E345)), (void*)x3_0xD277E345_bk);
		
		int *x3interface =  (int*)xCB_Interface__GetInterface(xCore_GetInterface());
		restore_func((void*)x3interface[39], (void*)GetItemFromMetaList_bk);

		x3interface =  (int*)xCBMini_GetInterface(xCore_GetInterface());
		restore_func((void*)x3interface[39], (void*)GetItemFromMetaList_bk_Mini);

		sfoverride_hooked = false;
		return 1;
	}
}

void notify(char * param)
{
	log(param);	log("\n");	
	vshtask_A02D46E7(0, param);
}

void notify(const char * format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp); log("\n");	
	vshtask_A02D46E7(0, tmp);
}

extern "C" int _videorec_prx_entry(void)
{
	(void*&)(vsh_sprintf) = (void*)((int)getNIDfunc("stdc",0x273B9711));
	
	(void*&)(vshmain_75A22E21) = (void*)((int)getNIDfunc("vshmain",0x75A22E21)); 	
	(void*&)(sub_CEF84_opd) = (void*)((int)getNIDfunc("vshmain",0x74105666)); 
	(void*&)(vshmain_6D5FC398) = (void*)((int)getNIDfunc("vshmain",0x6D5FC398)); 
	(uint32_t*&)sub_CEF84_opd -= (10*2);// game_plugin loading	
	(void*&)(vshmain_A4338777) = (void*)((int)getNIDfunc("vshmain",0xA4338777));// Get XMB Status Flag
	(void*&)(npdr_handler_opd) = (void*)((int)getNIDfunc("vshmain",0x302125E4));
	(uint32_t*&)npdr_handler_opd -= (10*2);// original NPDR-Handler
	(void*&)(ps3_savedata_plugin_init) = (void*)((int)getNIDfunc("vshmain",0xBEF63A14)); 
	(uint32_t*&)ps3_savedata_plugin_init -= (0x130*2);
	(void*&)(reco_open) = (void*)((int)getNIDfunc("vshmain",0xBEF63A14));
	(uint32_t*&)reco_open -= (50*2);
	// fetch recording utility vsh options
	int* func_start = (int*&)(*((int*&)reco_open));
	func_start += 3;
	int dword1 = ((*func_start) & 0x0000FFFF) - 1;
	func_start += 2;
	recOpt = (uint32_t*)((dword1 << 16) + ((*func_start) & 0x0000FFFF));//(uint32_t*)0x72EEC0;
	
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask",0xA02D46E7)); // notification message func

	(void*&)(View_Find) = (void*)((int)getNIDfunc("paf",0xF21655F3));
	(void*&)(plugin_GetInterface) = (void*)((int)getNIDfunc("paf",0x23AFB290));
	(void*&)(plugin_SetInterface) = (void*)((int)getNIDfunc("paf",0xA1DC401));
	(void*&)(paf_11E195B3_opd) = (void*)((int)getNIDfunc("paf",0x11E195B3));

	(void*&)(vsh_37857F3F) = (void*)((int)getNIDfunc("vsh",0x37857F3F));		 // createMemoryContainer
	(void*&)(vsh_E7C34044) = (void*)((int)getNIDfunc("vsh",0xE7C34044));		 // getMemoryContainer
	(void*&)(vsh_F399CA36) = (void*)((int)getNIDfunc("vsh",0xF399CA36));		 // destroyMemoryContainer
	
	(void*&)(xCore_GetInterface) = (void*)((int)getNIDfunc("x3",0x16FA740A));
	(void*&)(xCB_Interface__GetInterface) = (void*)((int)getNIDfunc("mms_db",0x8EC9A2A7));
	(void*&)(xCBMini_GetInterface) = (void*)((int)getNIDfunc("mms_db",0xEA4FCE1B));

    return SYS_PRX_RESIDENT;
}

extern "C" int _videorec_prx_stop(void)
{
	if(securfileid_hooked==true)
	{
		restore_func((void*)ps3_savedata_plugin_init, (void*)ps3_savedata_plugin_init_bk); securfileid_hooked=false;
	}
	if(klic_hooked == true)
	{
		restore_func((void*)npdr_handler_opd,(void*)npdr_handler_); klic_hooked = false;
	}
	if(recording_hooked == true)
	{
		//restore_func((void*)sub_CEF84_opd, (void*)sub_CEF84_); recording_hooked = false;
		//restore_func((void*)vshmain_6D5FC398, (void*)vshmain_6D5FC398_);
	}
    return SYS_PRX_STOP_OK;
}

extern "C" int _videorec_prx_exit(void)
{
    return SYS_PRX_STOP_SUCCESS;
}
