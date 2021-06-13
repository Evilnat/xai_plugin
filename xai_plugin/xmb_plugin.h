// Mysis xmb_plugin.h v0.1
enum plugins
{
	system_plugin = 0x00,
	xmb_plugin = 0x01,
	explore_plugin = 0x02,
	category_setting_plugin = 0x03,
	user_plugin = 0x04,
	sysconf_plugin = 0x05,
	netconf_plugin = 0x06,
	software_update_plugin = 0x07,
	edy_plugin = 0x08,
	print_plugin = 0x09,
	deviceconf_plugin = 0x0A,
	photoviewer_plugin = 0x0B,
	audioplayer_plugin = 0x0D,
	sacd_plugin = 0x0E,
	eula_cddb_plugin = 0x0F,
	videoplayer_plugin = 0x10,
	bdp_plugin = 0x11,
	bdp_disccheck_plugin = 0x12,
	bdp_storage_plugin = 0x13,
	game_plugin = 0x14,
	gamedata_plugin = 0x15,
	game_ext_plugin = 0x16,
	ps3_savedata_plugin = 0x17,
	vmc_savedata_plugin = 0x18,
	checker_plugin = 0x19,
	premo_plugin = 0x1A,
	webbrowser_plugin = 0x1B,
	webrender_plugin = 0x1C,
	//xai_plugin = 0x1D,
	friendim_plugin = 0x1E,
	friendml_plugin = 0x1F,
	avc_plugin = 0x20,
	avc2_text_plugin = 0x21,
	nas_plugin = 0x22,
	npsignin_plugin = 0x23,
	np_trophy_plugin = 0x24,
	np_trophy_ingame=0x25,
	friendtrophy_plugin = 0x26,
	profile_plugin = 0x27,
	videodownloader_plugin = 0x28,
	download_plugin = 0x29,
	thumthum_plugin = 0x2A,
	micon_lock_plugin = 0x2B,
	dlna_plugin = 0x2C,
	strviewer_plugin = 0x2D,
	playlist_plugin = 0x2F,
	newstore_plugin = 0x31,
	hknw_plugin = 0x32,
	kensaku_plugin = 0x34,
	regcam_plugin = 0x35,
	idle_plugin = 0x36,
	filecopy_plugin = 0x37,
	wboard_plugin = 0x38,
	poweroff_plugin = 0x39,
	videoeditor_plugin = 0x3A,
	scenefolder_plugin = 0x3B,
	eula_hcopy_plugin = 0x3C,
	mtpinitiator_plugin = 0x3E,
	campaign_plugin = 0x3F,
	remotedownload_plugin = 0x40
};

class xmb_plugin_xmm0
{
	public:
		int (*GetPluginIdByName)(char *);
		char* (*GetPluginNameById)(int); 
		int (*IsPluginViewAvailable)(int);
		int (*LoadPlugin3)(int, void *, int);
		int (*LoadPlugin4)(int *);
		int (*Shutdown)(int,void *, int);
		int (*DoUnk6)(int *); // shutdown as well?
		int (*DoUnk7)(int);
		int (*ActivatePlugin)(int) ;
		int (*DoUnk9)(int);
		int (*DoUnk10)(int);
		int (*DoUnk11)(int, int);
		int (*DoUnk12)(int, int, int);
		int (*DoUnk13)(int *);
		int (*DoUnk14)(int *);
		int (*DoUnk15)(int *);
		uint64_t (*GetModuleLoadOpinion)(int);
		void* (*SetModuleLoadOpinion)(int, uint64_t);
		int (*DoUnk18)(void *, int);
		int (*DoUnk19)(void *, int);
		int (*DoUnk20)(int *, int *);
		int (*DoUnk21)(int, int);
		int (*DoUnk22)(int);
		int (*DoUnk23)(const char *, int);
		int (*DoUnk24)(const char *, int);
		int (*DoUnk25)();
}; 


class xmb_plugin_xmb2
{
	public:
		int (*DoUnk0)(int);
		int (*DoUnk1)(int,int);
		int (*DoUnk2)(int, float);
		int (*DoUnk3)();
		int (*DoUnk4)();
		float (*DoUnk5)(float);
		float (*DoUnk6)();
		int (*DoUnk7)(int,int);
		int (*DoUnk8)();
		int (*DoUnk9)(int*,void*,const wchar_t *);
		int (*DoUnk10)();
		int (*DoUnk11)(int);
		int (*DoUnk12)(int);
		int (*DoUnk13)();
		int (*DoUnk14)();
		int (*DoUnk15)(int,int);
		int (*DoUnk16)(int, int, int);
		int (*DoUnk17)();
		int (*DoUnk18)(int,float,float);
		int (*DoUnk19)(int,int);
		int (*DoUnk20)(void *);
		int (*DoUnk21)(void *);
		int (*DoUnk22)(const wchar_t *);
		void * (*DoUnk23)();
		int (*DoUnk24)();
		void * (*DoUnk25)();
		int (*DoUnk26)(int);
		int (*DoUnk27)();
		int (*DoUnk28)(const char *);
		int (*DoUnk29)();
		int (*DoUnk30)(void *, int*);
		int (*DoUnk31)(int);
		int (*DoUnk32)(int);
}; 


class xmb_plugin_mod0
{
	public:
		int (*DoUnk0)();
		int (*DoUnk1)(); 
		int (*DoUnk2)(); 
		int (*DoUnk3)(); 
		int (*DoUnk4)(); 
}; 