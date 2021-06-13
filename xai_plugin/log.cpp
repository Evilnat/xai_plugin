#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "cfw_settings.h"
#include "gccpch.h"

#include <cell/fs/cell_fs_file_api.h>
#include <cell/rtc.h>

char log_path[0x100]; 

int (*vshtask_A02D46E7)(int, const char *);

void load_log_functions()
{	
	(void*&)(vsh_sprintf) = (void*)((int)getNIDfunc("stdc", 0x273B9711));
	(void*&)(vsh_swprintf) = (void*)((int)getNIDfunc("stdc", 0x62BF1D6C));	
}

int console_write(const char *s)
{ 
	uint32_t len;
	system_call_4(403, 0, (uint64_t) s, std::strlen(s), (uint64_t) &len);
	return_to_user_prog(int);
}

void log_data(const void *buffer, int bufsize)
{	
	char tmp[0x30];
	log("Dumping Data:\n");
	
	for(int i = 0 ; i < bufsize; i = i + 0x10)
	{
		log("%08X  ", ((int)buffer) + i);
		for(int j = 0; j < 0x10; j++)
		{
			char *o = (char*)buffer + i + j;
			log("%02X ",(unsigned char)(*o));
		}
		for(int j = 0; j < 0x10; j++)
		{
			char *o = (char*)buffer + i + j;
			log("%c",(unsigned char)(*o));
		}

		log("\n");
	}
}

int sprintf_(char *str, const char *format, int v1, int v2)
{
	return vsh_sprintf(str, format, v1, v2);
}

int sprintf_(char *str, const char *format, int v1, int v2, int v3)
{
	return vsh_sprintf(str, format, v1, v2, v3);
}

int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4)
{
	return vsh_sprintf(str, format, v1, v2, v3, v4);
}

int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5)
{
	return vsh_sprintf(str, format, v1, v2, v3, v4, v5);
}

int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8)
{
	return vsh_sprintf(str, format, v1, v2, v3, v4, v5, v6, v7, v8);
}

int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15, int v16)
{
	return vsh_sprintf(str, format, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16);
}

int swprintf_(wchar_t *str, size_t size, const wchar_t *format)
{
	return vsh_swprintf(str, size, format);
}

int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1)
{
	return vsh_swprintf(str, size, format, v1);
}

int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2)
{
	return vsh_swprintf(str, size, format, v1, v2);
}

int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3)
{
	return vsh_swprintf(str, size, format, v1, v2, v3);
}

int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4)
{
	return vsh_swprintf(str, size, format, v1, v2, v3, v4);
}

void log(char *format, float param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void log(char *format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void log(char *format, const char *param1)
{
	log(format, (char*)param1);
}

void log(char *format, char *param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void log(char *format, unsigned char param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void log(char *format, const wchar_t *param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void setlogpath(char *path)
{
	strcpy(log_path, path);
}

char *getlogpath()
{
	return log_path;
}

void log(char *buffer)
{
	console_write(buffer);
	int size = strlen(buffer);
	CellFsErrno err;
	int fd;
	uint64_t nrw;
	
	if(cellFsOpen(log_path, CELL_FS_O_RDWR | CELL_FS_O_CREAT | CELL_FS_O_APPEND, &fd, NULL, 0) != CELL_OK)
	{
		//notify("unable to open.");
	}
	else
	{
		if(cellFsWrite(fd, buffer, size, &nrw) != CELL_OK)
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

void log_key(char *keyname, void *key)
{
	log("%s: ", keyname);
	log("%08X", *(int*)key);
	log("%08X", *((int*)key + 1));
	log("%08X", *((int*)key + 2));
	log("%08X\n", *((int*)key + 3));
}

void log(char *pluginname, char *view, const char *function)
{	
	CellRtcDateTime t;
	cellRtcGetCurrentClockLocalTime(&t);
	
	char buffer[0x120];

	vsh_sprintf(buffer,"%04d-%02d-%02d %02d:%02d:%02d [%s] : %s : %s", t.year, t.month, t.day, t.hour, t.minute, t.second, pluginname, view, function);

	log(buffer);
}

void log_function(char *pluginname, char *view, const char *function, char *format, int param1) 
{
	log(pluginname, view, function);
	log(format, param1);
}

void log_function(char *pluginname,char *view, const char *function, char *format, const char*param1) 
{
	log(pluginname, view, function);
	log(format, param1);
}

void notify(const char *format, int param1, int param2)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp); 
	log("\n");	
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char *format, int param1, int param2, int param3)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3);
	log(tmp); 
	log("\n");	
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char *format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp); 
	log("\n");	
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(char *param)
{
	log(param);	
	log("\n");	

	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, param);
}


void dump_file(const char *path, void *buffer, int size)
{
	CellFsErrno err;
	int fd;
	uint64_t nrw;
					
	if(cellFsOpen(path, CELL_FS_O_RDWR | CELL_FS_O_CREAT, &fd, NULL, 0) != CELL_OK)	
		notify("unable to open.");	
	else
	{
		if(cellFsWrite(fd, buffer, size, &nrw) != CELL_OK)		
			notify("unable to write.");		
		else		
			notify("data written.");		
	}

	err = cellFsClose(fd);
}