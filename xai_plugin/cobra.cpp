#include <sys/memory.h>
#include <cell/fs/cell_fs_file_api.h>
#include "gccpch.h"
#include "cfw_settings.h"
#include "functions.h"
#include "log.h"
#include "rebug.h"
#include "cobra.h"

#define EINVAL (2133571399L)

int check_syscall8()
{
	system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_CHECK_SYSCALL, 8); 
	return_to_user_prog(int);
}

int check_cobra_version()
{		
	uint16_t version;
	sys_get_version2(&version);
	return version;
}

int cobra_read_config(CobraConfig *cfg)
{
	if(!cfg) 
		return EINVAL;

	memset((uint8_t*)cfg, 0, sizeof(CobraConfig));

	cfg->size = sizeof(CobraConfig);
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_READ_COBRA_CONFIG, (uint64_t)(uint32_t)cfg);
	return (int)p1;
}

int cobra_write_config(CobraConfig *cfg)
{
	if(!cfg) 
		return EINVAL;

	cfg->size = sizeof(CobraConfig);
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_WRITE_COBRA_CONFIG, (uint64_t)(uint32_t)cfg);
	return (int)p1;
}

int sys_get_version(uint32_t *version)
{
	system_call_2(8, SYSCALL8_OPCODE_GET_VERSION, (uint64_t)version);
    return_to_user_prog(uint32_t);
}

int sys_get_version2(uint16_t *version)
{
    system_call_2(8, SYSCALL8_OPCODE_GET_VERSION2, (uint32_t)version);
	//system_call_3(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_COBRA_VERSION, (uint32_t)version);  	
	
    return_to_user_prog(uint16_t);
}

int cobra_load_vsh_plugin(int slot, char *path, void *arg, uint32_t arg_size)
{
	system_call_5(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_LOAD_VSH_PLUGIN, slot, (uint64_t)(uint32_t)path, (uint64_t)(uint32_t)arg, arg_size);
	return (int)p1;
}

int cobra_unload_vsh_plugin(int slot)
{
	system_call_2(SC_COBRA_SYSCALL8, SYSCALL8_OPCODE_UNLOAD_VSH_PLUGIN, slot);
	return (int)p1;
}

void toggle_plugins()
{
	int ret;
	CellFsStat stat;

	if(cellFsStat(PLUGINS_TXT_FILE_ENABLED, &stat) == CELL_FS_SUCCEEDED)
	{
		ret = cellFsRename(PLUGINS_TXT_FILE_ENABLED, PLUGINS_TXT_FILE_DISABLED);

		if(ret != CELL_OK)		
			ShowMessage("msg_disable_plugins_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_disable_plugins_success", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
	else if(cellFsStat(PLUGINS_TXT_FILE_DISABLED, &stat) == CELL_FS_SUCCEEDED)
	{
		ret = cellFsRename(PLUGINS_TXT_FILE_DISABLED, PLUGINS_TXT_FILE_ENABLED);
		
		if(ret != CELL_OK)		
			ShowMessage("msg_enable_plugins_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_enable_plugins_success", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			
	}
	else
		ShowMessage("msg_plugins_not_found", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

int toggle_cobra()
{
	int ret = 1;

	CellFsStat statinfo;

	if(cellFsStat(DEV_BLIND, &statinfo) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	// Evilnat CFW
	if(cellFsStat(STAGE2_EVILNAT_CEX_ENABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_EVILNAT_DEX_ENABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_EVILNAT_CEX_ENABLED, STAGE2_EVILNAT_CEX_DISABLED);
		ret |= cellFsRename(STAGE2_EVILNAT_DEX_ENABLED, STAGE2_EVILNAT_DEX_DISABLED);

		if(ret != CELL_OK)
			ShowMessage("msg_cant_disable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

		return ret;
	}
	else if(cellFsStat(STAGE2_EVILNAT_CEX_DISABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_EVILNAT_DEX_DISABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_EVILNAT_CEX_DISABLED, STAGE2_EVILNAT_CEX_ENABLED);
		ret |= cellFsRename(STAGE2_EVILNAT_DEX_DISABLED, STAGE2_EVILNAT_DEX_ENABLED);

		if(ret != CELL_OK)
			ShowMessage("msg_cant_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);			

		return ret;
	}

	// Rebug CFW
	if(cellFsStat(STAGE2_CEX_ENABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_ENABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_DISABLED);
		ret |= cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_DISABLED);

		if(ret != CELL_OK)
			ShowMessage("msg_cant_disable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		

		return ret;
	}
	else if(cellFsStat(STAGE2_CEX_DISABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_DISABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_CEX_DISABLED, STAGE2_CEX_ENABLED);
		ret |= cellFsRename(STAGE2_DEX_DISABLED, STAGE2_DEX_ENABLED);

		if(ret != CELL_OK)
			ShowMessage("msg_cant_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		

		return ret;
	}
	
	// Standard CFW
	if(cellFsStat(STAGE2_BIN_ENABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_DISABLED);

		if(ret != CELL_OK)		
			ShowMessage("msg_cant_disable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_disabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);	

		return ret;
	} 
	else if(cellFsStat(STAGE2_BIN_DISABLED, &statinfo) == CELL_OK)
	{
		ret = cellFsRename(STAGE2_BIN_DISABLED, STAGE2_BIN_ENABLED);

		if(ret != CELL_OK)		
			ShowMessage("msg_cant_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		else
			ShowMessage("msg_cobra_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		

		return ret;
	}	

	log_function("xai_plugin", __VIEW__, "cellFsUtilUnMount", "(/dev_blind) = %x\n", cellFsUtilUnMount(DEV_BLIND, 0));
	ShowMessage("msg_stage2_not_found", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	return 1;	
}

int toggle_cobra_version()
{
	char fw_type[16];
	int ret = 1;
	CellFsStat statinfo;

	if(cellFsStat(DEV_BLIND, &statinfo) != CELL_OK)
	{
		if(cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", DEV_BLIND, 0, 0, 0, 0) != CELL_OK)
		{
			ShowMessage("msg_devblind_mount_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}

	// Evilnat CFW
	if(cellFsStat(STAGE2_EVILNAT_CEX_ENABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_EVILNAT_DEX_ENABLED, &statinfo) == CELL_OK)
	{
		if(cellFsStat(STAGE2_EVILNAT_CEX_DEBUG, &statinfo) == CELL_OK && cellFsStat(STAGE2_EVILNAT_DEX_DEBUG, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_EVILNAT_CEX_ENABLED, STAGE2_EVILNAT_CEX_RELEASE);
			ret |= cellFsRename(STAGE2_EVILNAT_CEX_DEBUG, STAGE2_EVILNAT_CEX_ENABLED);

			ret |= cellFsRename(STAGE2_EVILNAT_DEX_ENABLED, STAGE2_EVILNAT_DEX_RELEASE);
			ret |= cellFsRename(STAGE2_EVILNAT_DEX_DEBUG, STAGE2_EVILNAT_DEX_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_debug_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_debug_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			return ret;
		}
		else if(cellFsStat(STAGE2_EVILNAT_CEX_RELEASE, &statinfo) == CELL_OK && cellFsStat(STAGE2_EVILNAT_DEX_RELEASE, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_EVILNAT_CEX_ENABLED, STAGE2_EVILNAT_CEX_DEBUG);
			ret |= cellFsRename(STAGE2_EVILNAT_CEX_RELEASE, STAGE2_EVILNAT_CEX_ENABLED);

			ret |= cellFsRename(STAGE2_EVILNAT_DEX_ENABLED, STAGE2_EVILNAT_DEX_DEBUG);
			ret |= cellFsRename(STAGE2_EVILNAT_DEX_RELEASE, STAGE2_EVILNAT_DEX_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_release_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_release_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			return ret;
		}
	}

	// Rebug CFW
	if(cellFsStat(STAGE2_CEX_ENABLED, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_ENABLED, &statinfo) == CELL_OK)
	{
		if(cellFsStat(STAGE2_CEX_DEBUG, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_DEBUG, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_RELEASE);
			ret |= cellFsRename(STAGE2_CEX_DEBUG, STAGE2_CEX_ENABLED);

			ret |= cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_RELEASE);
			ret |= cellFsRename(STAGE2_DEX_DEBUG, STAGE2_DEX_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_debug_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_debug_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			return ret;
		}
		else if(cellFsStat(STAGE2_CEX_RELEASE, &statinfo) == CELL_OK && cellFsStat(STAGE2_DEX_RELEASE, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_CEX_ENABLED, STAGE2_CEX_DEBUG);
			ret |= cellFsRename(STAGE2_CEX_RELEASE, STAGE2_CEX_ENABLED);

			ret |= cellFsRename(STAGE2_DEX_ENABLED, STAGE2_DEX_DEBUG);
			ret |= cellFsRename(STAGE2_DEX_RELEASE, STAGE2_DEX_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_release_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_release_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			return ret;
		}
	}

	// Standard CFW
	if(cellFsStat(STAGE2_BIN_ENABLED, &statinfo) == CELL_OK)
	{
		if(cellFsStat(STAGE2_BIN_DEBUG, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_RELEASE);
			ret |= cellFsRename(STAGE2_BIN_DEBUG, STAGE2_BIN_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_debug_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_debug_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);		

			return ret;
		}
		else if(cellFsStat(STAGE2_BIN_RELEASE, &statinfo) == CELL_OK)
		{
			ret = cellFsRename(STAGE2_BIN_ENABLED, STAGE2_BIN_DEBUG);
			ret |= cellFsRename(STAGE2_BIN_RELEASE, STAGE2_BIN_ENABLED);

			if(ret != CELL_OK)
				ShowMessage("msg_cobra_release_error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			else
				ShowMessage("msg_cobra_release_enabled", (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);

			return ret;
		}
	}
	
	cellFsUtilUnMount(DEV_BLIND, 0);
	ShowMessage("msg_please_enable_cobra", (char*)XAI_PLUGIN, (char*)TEX_ERROR);

	return 1;
}
