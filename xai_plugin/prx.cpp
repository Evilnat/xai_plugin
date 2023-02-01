#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/ppu_thread.h>
#include <sys/prx.h>
#include "xmb_plugin.h"
#include "log.h"
#include "cfw_settings.h"
#include "cobra.h"
#include "gccpch.h"
#include "functions.h"
#include "rebug.h"
#include "qa.h"
#include "savegames.h"
#include "cex2dex.h"
#include "eeprom.h"

SYS_MODULE_INFO(xai_plugin, 0, 1, 1);
SYS_MODULE_START(_xai_plugin_prx_entry);
SYS_MODULE_STOP(_xai_plugin_prx_stop);
SYS_MODULE_EXIT(_xai_plugin_prx_exit);

SYS_LIB_DECLARE_WITH_STUB(LIBNAME, SYS_LIB_AUTO_EXPORT, STUBNAME);
SYS_LIB_EXPORT(_xai_plugin_export_function, LIBNAME);

xmb_plugin_xmm0 * xmm0_interface;
xmb_plugin_xmb2 * xmb2_interface;
xmb_plugin_mod0 * mod0_interface;

sys_ppu_thread_t thread_id = 0;
const char * action_thread;

int LoadPlugin(char *pluginname, void *handler)
{
	log_function("xai_plugin", "1", __FUNCTION__, "(%s)\n", pluginname);
	return xmm0_interface->LoadPlugin3(xmm0_interface->GetPluginIdByName(pluginname), handler, 0); 
}

int GetPluginInterface(const char *pluginname, int interface_)
{
	return plugin_GetInterface(FindPlugin(pluginname), interface_);
}

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
				
		if(strncmp(vsh_module, lib_name_ptr, strlen(lib_name_ptr)) == 0)
		{
			// we got the proper export struct
			uint32_t lib_fnid_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x14);
			uint32_t lib_func_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x18);
			uint16_t count = *(uint16_t*)((char*)export_stru_ptr + 6); // amount of exports

			for(int i = 0; i < count; i++)
			{
				if(fnid == *(uint32_t*)((char*)lib_fnid_ptr + i * 4))								
					return (void*&)*((uint32_t*)(lib_func_ptr) + i); // take adress from OPD				
			}
		}

		table = table + 4;
	}

	return 0;
}

int load_functions()
{	
	setNIDfunc(FindPlugin, "paf", 0xF21655F3);
	setNIDfunc(plugin_GetInterface, "paf", 0x23AFB290);
	setNIDfunc(plugin_SetInterface, "paf", 0xA1DC401);
	setNIDfunc(plugin_SetInterface2, "paf", 0x3F7CB0BF);

	load_log_functions();
	load_cfw_functions();
	load_saves_functions();
	
	xmm0_interface = (xmb_plugin_xmm0 *)GetPluginInterface("xmb_plugin", 'XMM0');
	xmb2_interface = (xmb_plugin_xmb2 *)GetPluginInterface("xmb_plugin", 'XMB2');
	
	setlogpath("/dev_hdd0/tmp/cfw_settings.log"); // Default path

	uint8_t data;
	int ret = read_product_mode_flag(&data);

	if(ret == CELL_OK)
	{
		if(data != 0xFF)		
			setlogpath("/dev_usb/cfw_settings.log"); // To get output data		
	}

	return 0;
}

// An exported function is needed to generate the project's PRX stub export library
extern "C" int _xai_plugin_export_function(void)
{
    return CELL_OK;
}

extern "C" int _xai_plugin_prx_entry(size_t args, void *argp)
{	
	load_functions();
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
	plugin_SetInterface2(*(unsigned int*)argp, 1, xai_plugin_functions);

    return SYS_PRX_RESIDENT;
}

extern "C" int _xai_plugin_prx_stop(void)
{
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
    return SYS_PRX_STOP_OK;
}

extern "C" int _xai_plugin_prx_exit(void)
{
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
    return SYS_PRX_STOP_OK;
}

void xai_plugin_interface::xai_plugin_init(int view)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	plugin_SetInterface(view, 'ACT0', xai_plugin_action_if);
}

int xai_plugin_interface::xai_plugin_start(void * view)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	return SYS_PRX_START_OK; 
}

int xai_plugin_interface::xai_plugin_stop(void)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	return SYS_PRX_STOP_OK;
}

void xai_plugin_interface::xai_plugin_exit(void)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
}

static void plugin_thread(uint64_t arg)
{
	// Shutdown options
	if(strcmp(action_thread, "shutdown_action") == 0)	
		xmb_reboot(SYS_SHUTDOWN);	
	else if(strcmp(action_thread, "soft_reboot_action") == 0)	
		xmb_reboot(SYS_SOFT_REBOOT);
	else if(strcmp(action_thread, "hard_reboot_action") == 0)	
		xmb_reboot(SYS_HARD_REBOOT);
	else if(strcmp(action_thread, "lv2_reboot_action") == 0)	
		xmb_reboot(SYS_LV2_REBOOT);

	// Cobra options	
	else if(strcmp(action_thread, "cobra_info") == 0)	
		show_cobra_info();
	else if(strcmp(action_thread, "check_syscall8") == 0)	
		checkSyscall(SC_COBRA_SYSCALL8);		
	else if(strcmp(action_thread, "create_rif_license") == 0)	
		create_rifs();		
	else if(strcmp(action_thread, "create_syscalls") == 0)	
		create_syscalls();
	else if(strcmp(action_thread, "enable_ftp") == 0)
		load_ftp();
	else if(strcmp(action_thread, "disable_ftp") == 0)
		unload_ftp();
	else if(strcmp(action_thread, "allow_restore_sc") == 0)	
		allow_restore_sc();	
	else if(strcmp(action_thread, "skip_existing_rif") == 0)	
		skip_existing_rif();	
	/*else if(strcmp(action_thread, "enable_whatsnew") == 0)	
		enable_WhatsNew();*/
	else if(strcmp(action_thread, "cobra_version") == 0)
	{		
		if(toggle_cobra_version() == CELL_OK)
		{
			wait(2);
			xmb_reboot(SYS_HARD_REBOOT);
		}
	}
	else if(strcmp(action_thread, "cobra_mode") == 0)
	{
		if(toggle_cobra() == CELL_OK)
		{
			wait(2);
			xmb_reboot(SYS_HARD_REBOOT);
		}
	}
	else if(strcmp(action_thread, "toggle_plugins") == 0)
		toggle_plugins();
	else if(strcmp(action_thread, "enable_npsignin_lck") == 0)	
		enable_npsignin_lck();
	else if(strcmp(action_thread, "disable_npsignin_lck") == 0)	
		disable_npsignin_lck();
	/*else if(strcmp(action_thread, "toggle_ext_cobra") == 0)
		toggle_ext_cobra();*/


	// PSN Tools
	else if(strcmp(action_thread, "disable_syscalls") == 0)	
		removeSysHistory();		
	else if(strcmp(action_thread, "spoof_targetid") == 0)	
		spoof_with_eid5();	
	else if(strcmp(action_thread, "spoof_idps") == 0)	
		spoof_idps();
	else if(strcmp(action_thread, "spoof_psid") == 0)	
		spoof_psid();
	else if(strcmp(action_thread, "show_accountid") == 0)
		getAccountID();		
	else if(strcmp(action_thread, "set_accountid") == 0)
		changeAccountID(WRITE, 0);
	else if(strcmp(action_thread, "set_accountid_overwrite") == 0)
		changeAccountID(WRITE, 1);
	else if(strcmp(action_thread, "remove_accountid") == 0)
		changeAccountID(EMPTY, 1);
	else if(strcmp(action_thread, "activate_account") == 0)	
		activate_account();	
	else if(strcmp(action_thread, "backup_license") == 0)
		backup_license();
	else if(strcmp(action_thread, "remove_license") == 0)
		remove_license();
	else if(strcmp(action_thread, "patch_savedata") == 0)	
		patch_savedata();	

	// Fan Modes
	else if(strcmp(action_thread, "fan_mode_disabled") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_DISABLED) == 0)			
			ShowMessage("msg_cobra_fan_mode_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_syscon") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_SYSCON) == 0)
			ShowMessage("msg_cobra_fan_mode_syscon", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_max") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MAX) == 0)
			ShowMessage("msg_cobra_fan_mode_max", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Dynamic Modes
	else if(strcmp(action_thread, "fan_mode_60") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_60) == 0)
			ShowMessage("msg_cobra_fan_dynamic_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_65") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_65) == 0)
			ShowMessage("msg_cobra_fan_dynamic_65", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_70") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_70) == 0)
			ShowMessage("msg_cobra_fan_dynamic_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_75") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_75) == 0)
			ShowMessage("msg_cobra_fan_dynamic_75", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Manual Modes
	else if(strcmp(action_thread, "fan_manual_40") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_40) == 0)
			ShowMessage("msg_cobra_fan_manual_40", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_45") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_45) == 0)
			ShowMessage("msg_cobra_fan_manual_45", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_50") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_50) == 0)
			ShowMessage("msg_cobra_fan_manual_50", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_55") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_55) == 0)
			ShowMessage("msg_cobra_fan_manual_55", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_60") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_60) == 0)
			ShowMessage("msg_cobra_fan_manual_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_65") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_65) == 0)
			ShowMessage("msg_cobra_fan_manual_65", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_70") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_70) == 0)
			ShowMessage("msg_cobra_fan_manual_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_75") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_75) == 0)
			ShowMessage("msg_cobra_fan_manual_75", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_80") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_80) == 0)
			ShowMessage("msg_cobra_fan_manual_80", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_85") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_85) == 0)
			ShowMessage("msg_cobra_fan_manual_85", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_90") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_90) == 0)
			ShowMessage("msg_cobra_fan_manual_90", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_95") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_95) == 0)
			ShowMessage("msg_cobra_fan_manual_95", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// PS2 Fan modes
	else if(strcmp(action_thread, "fan_ps2mode_disabled") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_DISABLED) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_syscon") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_SYSCON) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_syscon", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_40") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_40) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_40", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_50") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_50) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_50", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_60") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_60) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_70") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_70) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_80") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_80) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_80", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_90") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_90) == 0)
			ShowMessage("msg_cobra_fan_ps2mode_90", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Basic options	
	else if(strcmp(action_thread, "ps3_lifetime") == 0)	
		getPS3Lifetime();
	else if(strcmp(action_thread, "fan_speed") == 0)	
		fan_speed();
	else if(strcmp(action_thread, "show_temp_celsius") == 0)	
		check_temp(0);
	else if(strcmp(action_thread, "show_temp_fahrenheit") == 0)	
		check_temp(1);
	else if(strcmp(action_thread, "show_idps") == 0)	
		show_idps();			
	else if(strcmp(action_thread, "show_psid") == 0)	
		show_psid();
	else if(strcmp(action_thread, "show_ip") == 0)	
		show_ip();
	else if(strcmp(action_thread, "show_clocks") == 0)	
		getClockSpeeds();
	else if(strcmp(action_thread, "toggle_coldboot") == 0)
	{
		CellFsStat statinfo;

		if(toggle_coldboot() == CELL_OK)
			ShowMessage((cellFsStat("/dev_flash/vsh/resource/coldboot.raf.ori", &statinfo) == CELL_OK) ? "msg_mod_coldboot_enabled" : "msg_ori_coldboot_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}	
	/*else if(strcmp(action_thread, "toggle_sysconf_rco") == 0)
	{
		CellFsStat statinfo;

		if(toggle_sysconf() == CELL_OK)
			ShowMessage((cellFsStat("/dev_flash/vsh/resource/sysconf_plugin.rco.ori", &statinfo) == CELL_OK) ? "msg_mod_sysconf_enabled" : "msg_ori_sysconf_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}*/

	// Buzzer Options
	else if(strcmp(action_thread, "buzzer_single") == 0)
		buzzer(SINGLE_BEEP);
	else if(strcmp(action_thread, "buzzer_double") == 0)
		buzzer(DOUBLE_BEEP);
	else if(strcmp(action_thread, "buzzer_triple") == 0)
		buzzer(TRIPLE_BEEP);
	else if(strcmp(action_thread, "buzzer_continuous") == 0)
		buzzer(CONTINUOUS_BEEP);

	// CEX2DEX Options
	else if(strcmp(action_thread, "convert_cex") == 0)
		cex2dex(0);
	else if(strcmp(action_thread, "convert_dex") == 0)
		cex2dex(1);
	else if(strcmp(action_thread, "swap_kernel") == 0)
		swap_kernel();
	else if(strcmp(action_thread, "check_targetid") == 0)			
		check_targetid(0);
	else if(strcmp(action_thread, "swap_ip_xmb") == 0)			
		toggle_xmbplugin();
	else if(strcmp(action_thread, "toggle_vsh") == 0)			
		toggle_vsh();
	else if(strcmp(action_thread, "toggle_sysconf") == 0)			
		toggle_sysconf();
	else if(strcmp(action_thread, "cex2dex_showinfo") == 0)
		get_ps3_info();

	// Led Options
	else if(strcmp(action_thread, "set_led_off") == 0)
		setLed("ledOff");
	else if(strcmp(action_thread, "set_led_red") == 0) 
		setLed("ledRed_default");
	else if(strcmp(action_thread, "set_led_red_slow") == 0) 
		setLed("ledRed_blink_slow");
	else if(strcmp(action_thread, "set_led_red_fast") == 0) 
		setLed("ledRed_blink_fast");
	else if(strcmp(action_thread, "set_led_green") == 0) 
		setLed("ledGreen_default");
	else if(strcmp(action_thread, "set_led_green_slow") == 0) 
		setLed("ledGreen_blink_slow");
	else if(strcmp(action_thread, "set_led_green_fast") == 0) 
		setLed("ledGreen_blink_fast");
	else if(strcmp(action_thread, "set_led_yellow") == 0) 
		setLed("ledYellow_default");
	else if(strcmp(action_thread, "set_led_yellow_slow") == 0) 
		setLed("ledYellow_blink_slow");
	else if(strcmp(action_thread, "set_led_yellow_fast") == 0) 
		setLed("ledYellow_blink_fast");
	else if(strcmp(action_thread, "set_led_yellowg_slow") == 0) 
		setLed("ledYellowG_blink_slow");
	else if(strcmp(action_thread, "set_led_yellowg_fast") == 0) 
		setLed("ledYellowG_blink_fast");
	else if(strcmp(action_thread, "set_led_yellowr_slow") == 0) 
		setLed("ledYellowR_blink_slow");
	else if(strcmp(action_thread, "set_led_yellowr_fast") == 0) 
		setLed("ledYellowR_blink_fast");
	else if(strcmp(action_thread, "set_led_rainbow") == 0) 
		setLed("rainbow");
	else if(strcmp(action_thread, "set_led_special1") == 0) 
		setLed("special1");
	else if(strcmp(action_thread, "set_led_special2") == 0) 
		setLed("special2");

	// QA options
	else if(strcmp(action_thread, "check_qa") == 0)
		read_qa_flag();
	else if(strcmp(action_thread, "enable_qa") == 0)
		set_qa(1);
	else if(strcmp(action_thread, "disable_qa") == 0)
		set_qa(0);

	// xRegistry options	
	else if(strcmp(action_thread, "backup_registry") == 0)	
		backup_registry();	
	else if(strcmp(action_thread, "button_assignment") == 0)
		button_assignment();	

	// Rebug options	
	/*else if(strcmp(action_thread, "normal_mode") == 0)	
	{
		if(normal_mode() == CELL_OK)
		{
			ShowMessage("msg_normal_mode", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			wait(2);
			xmb_reboot(SYS_SOFT_REBOOT);
		}
	}
	else if(strcmp(action_thread, "rebug_mode") == 0)	
	{
		if(rebug_mode() == CELL_OK)
		{
			ShowMessage("msg_rebug_mode", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			wait(2);
			xmb_reboot(SYS_SOFT_REBOOT);
		}
	}
	else if(strcmp(action_thread, "debugsettings_mode") == 0)		
		debugsettings_mode();	
	else if(strcmp(action_thread, "xmb_plugin") == 0)	
	{
		if(toggle_xmb_plugin() == CELL_OK)
		{
			wait(3);
			xmb_reboot(SYS_SOFT_REBOOT);
		}
	}
	else if(strcmp(action_thread, "xmb_mode") == 0)	
	{
		if(toggle_xmb_mode() == CELL_OK)
		{
			wait(3);
			xmb_reboot(SYS_SOFT_REBOOT);
		}
	}*/
	/*else if(strcmp(action_thread, "download_toolbox") == 0)	
		download_toolbox();*/
	/*else if(strcmp(action_thread, "install_toolbox") == 0)	
		install_toolbox();*/

	// Advanced Tools options
	else if(strcmp(action_thread, "rsod_fix") == 0)
	{		
		if(rsod_fix() == true)
			xmb_reboot(SYS_HARD_REBOOT);
	}	
	else if(strcmp(action_thread, "service_mode") == 0)
	{
		if(!service_mode())
			xmb_reboot(SYS_HARD_REBOOT);
	}	
	else if(strcmp(action_thread, "remarry_bd") == 0)			
		remarry_bd();	
	else if(strcmp(action_thread, "check_ros_bank") == 0)			
		check_ros_bank();	
	else if(strcmp(action_thread, "check_8th_spe") == 0)			
		check_8th_spe();	
	else if(strcmp(action_thread, "toggle_8th_spe") == 0)			
		toggle_8th_spe();
	else if(strcmp(action_thread, "patch_prodg") == 0)	
		Patch_ProDG();
	else if(strcmp(action_thread, "toggle_devblind") == 0)			
		toggle_devblind();	
	else if(strcmp(action_thread, "load_kernel") == 0)	
		loadKernel();	
	
	// Dump Tools options	
	else if(strcmp(action_thread, "clean_log") == 0)	
		clean_log();
	else if(strcmp(action_thread, "dump_idps") == 0)	
		dump_idps();	
	else if(strcmp(action_thread, "dump_psid") == 0)	
		dump_psid();		
	else if(strcmp(action_thread, "dump_erk") == 0)	
		dumpERK();		
	else if(strcmp(action_thread, "dump_lv2") == 0)	
		dump_lv(LV2);		
	else if(strcmp(action_thread, "dump_lv1") == 0)	
		dump_lv(LV1);
	else if(strcmp(action_thread, "dump_ram") == 0)	
		dump_lv(RAM);
	else if(strcmp(action_thread, "dump_sysrom") == 0)	
		dump_sysrom();
	else if(strcmp(action_thread, "dump_eeprom") == 0)	
		dump_eeprom();
	else if(strcmp(action_thread, "dump_syscon_log") == 0)	
		sm_error_log();
	else if(strcmp(action_thread, "get_token_seed") == 0)	
		get_token_seed();
	else if(strcmp(action_thread, "dump_flash") == 0)	
		dump_flash();
	else if(strcmp(action_thread, "log_klic") == 0)	
		log_klic();	
	else if(strcmp(action_thread, "log_secureid") == 0)	
		log_secureid();	
	else if(strcmp(action_thread, "dump_disc_key") == 0)	
		dump_disc_key();

	// OtherOS options
	else if(strcmp(action_thread, "otheros_resize") == 0)	
	{
		if(check_flash_type())
			setup_vflash();
		else
			setup_flash();
	}
	else if(strcmp(action_thread, "otheros_petitboot") == 0)
		install_petitboot();
	else if(strcmp(action_thread, "otheros_flag") == 0)
		set_flag(OTHEROS_FLAG);
	else if(strcmp(action_thread, "gameos_flag") == 0)
		set_flag(GAMEOS_FLAG);
	
	// Recovery options
	else if(strcmp(action_thread, "applicable_version") == 0)	
		applicable_version();	
	else if(strcmp(action_thread, "fs_check") == 0)	
		sys_sm_shutdown(SYS_SOFT_REBOOT);
	else if(strcmp(action_thread, "rebuild_db") == 0)
		rebuild_db();
	else if(strcmp(action_thread, "toggle_hdd_space") == 0)
		unlock_hdd_space();
	else if(strcmp(action_thread, "recovery_mode") == 0)
		recovery_mode();
			
	// Unused options
	/*else if(strcmp(action_thread, "enable_screenshot") == 0)			
		enable_screenshot();		
	else if(strcmp(action_thread, "enable_recording") == 0)	
		enable_recording();	
	else if(strcmp(action_thread, "override_sfo") == 0)		
		override_sfo();					
	else if(strcmp(action_thread, "enable_hvdbg") == 0)
	{
		if(enable_hvdbg() == true)
			xmb_reboot(SYS_HARD_REBOOT);
	}
	else if(strcmp(action_thread, "usb_firm_loader") == 0)	
		usb_firm_loader();	
	else if(strcmp(action_thread, "toggle_dlna") == 0)	
		toggle_dlna();	*/
	
	sys_ppu_thread_exit(0);
}

void xai_plugin_interface_action::xai_plugin_action(const char * action)
{	
	thread_id = 0;

	log_function("xai_plugin", __VIEW__, __FUNCTION__, "(%s)\n", action);
	action_thread = action;
	sys_ppu_thread_create(&thread_id, plugin_thread, 0, 3000, 0x4000, 0, "xai_thread");
}
