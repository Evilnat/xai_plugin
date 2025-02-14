#ifndef _REBUG_H
#define _REBUG_H

#define STAGE2_CEX_ENABLED				"/dev_blind/rebug/cobra/stage2.cex"
#define STAGE2_CEX_DISABLED				"/dev_blind/rebug/cobra/stage2.cex.bak"
#define STAGE2_CEX_RELEASE				"/dev_blind/rebug/cobra/stage2.cex.release"
#define STAGE2_CEX_DEBUG  				"/dev_blind/rebug/cobra/stage2.cex.debug"
#define STAGE2_DEX_ENABLED				"/dev_blind/rebug/cobra/stage2.dex"
#define STAGE2_DEX_DISABLED				"/dev_blind/rebug/cobra/stage2.dex.bak"
#define STAGE2_DEX_RELEASE				"/dev_blind/rebug/cobra/stage2.dex.release"
#define STAGE2_DEX_DEBUG  				"/dev_blind/rebug/cobra/stage2.dex.debug"

#define STAGE2_DEH_ENABLED				"/dev_blind/rebug/cobra/stage2.deh"
#define STAGE2_DEH_DISABLED				"/dev_blind/rebug/cobra/stage2.deh.bak"
#define STAGE2_DEH_RELEASE				"/dev_blind/rebug/cobra/stage2.deh.release"
#define STAGE2_DEH_DEBUG  				"/dev_blind/rebug/cobra/stage2.deh.debug"

#define STAGE2_EVILNAT_CEX_ENABLED		"/dev_blind/sys/stage2.cex"
#define STAGE2_EVILNAT_CEX_DISABLED		"/dev_blind/sys/stage2.cex.bak"
#define STAGE2_EVILNAT_CEX_RELEASE		"/dev_blind/sys/stage2.cex.release"
#define STAGE2_EVILNAT_CEX_DEBUG  		"/dev_blind/sys/stage2.cex.debug"
#define STAGE2_EVILNAT_DEX_ENABLED		"/dev_blind/sys/stage2.dex"
#define STAGE2_EVILNAT_DEX_DISABLED		"/dev_blind/sys/stage2.dex.bak"
#define STAGE2_EVILNAT_DEX_RELEASE		"/dev_blind/sys/stage2.dex.release"
#define STAGE2_EVILNAT_DEX_DEBUG  		"/dev_blind/sys/stage2.dex.debug"

#define VSH_SELF						"/dev_blind/vsh/module/vsh.self"
#define VSH_SWP							"/dev_blind/vsh/module/vsh.self.swp"
#define VSH_NRM							"/dev_blind/vsh/module/vsh.self.nrm"

#define VSH_DSP							"/dev_blind/vsh/module/vsh.self.dexsp"
#define VSH_CSP							"/dev_blind/vsh/module/vsh.self.cexsp"

#define IDX_DAT							"/dev_blind/vsh/etc/index.dat"
#define IDX_SWP							"/dev_blind/vsh/etc/index.dat.swp"
#define IDX_NRM							"/dev_blind/vsh/etc/index.dat.nrm"

#define VER_TXT							"/dev_blind/vsh/etc/version.txt"
#define VER_SWP							"/dev_blind/vsh/etc/version.txt.swp"
#define VER_NRM							"/dev_blind/vsh/etc/version.txt.nrm"

#define SYSCONF_SPRX					"/dev_blind/vsh/module/sysconf_plugin.sprx"
#define SYSCONF_SPRX_CEX				"/dev_blind/vsh/module/sysconf_plugin.sprx.cex"
#define SYSCONF_SPRX_DEX				"dev_blind/vsh/module/sysconf_plugin.sprx.dex"

#define XMB_PLUGIN_SPRX					"/dev_blind/vsh/module/xmb_plugin.sprx"
#define XMB_PLUGIN_SPRX_CEX				"/dev_blind/vsh/module/xmb_plugin.sprx.cex"
#define XMB_PLUGIN_SPRX_DEX				"/dev_blind/vsh/module/xmb_plugin.sprx.dex"

#define SYSCONF_PLUGIN_RCO				"/dev_blind/vsh/resource/sysconf_plugin.rco"
#define SYSCONF_PLUGIN_RCO_CEX			"/dev_blind/vsh/resource/sysconf_plugin.rco.cex"
#define SYSCONF_PLUGIN_RCO_DEX			"/dev_blind/vsh/resource/sysconf_plugin.rco.dex"

int toggle_xmb_plugin();
int toggle_xmb_mode();
int normal_mode();
int rebug_mode();
int debugsettings_mode();

//void download_toolbox();
//void install_toolbox();

#endif /* _REBUG_H */