#ifndef _XREGISTRY_H
#define _XREGISTRY_H

// Mysis xRegistry.h v0.1
class xsetting_AF1F161_class
{
	public:
		int (*GetProductCode)();
		int (*GetProductSubCode)(); // Model Type, Mobo Id
		int (*GetUnk1)(void *); // uint8_t [0x1C] { hdmi, ieee802.11, msslot, sdslot, cfslot }
		int (*SetUnk2)(void *);
		int (*GetEnterButtonAssign)(int *);
		int (*SetEnterButtonAssign)(int);
		int (*GetLicenseArea)(int *);
		int (*SetSystemInitialize)(int);
		int (*GetSystemInitialize)(int *);
		int (*SetSystemLanguage)(int);
		int (*GetSystemLanguage)(int *);
		int (*SetSystemNickname)(char *);
		int (*GetSystemNickname)(char *, int *); // nick, length
		int (*SetSystemCharacterCodeOem)(int);
		int (*GetSystemCharacterCodeOem)(int *);
		int (*SetSystemCharacterCodeOemValue)(int);
		int (*GetSystemCharacterCodeOemValue)(int *);
		int (*SetsystemCharacterCodeAnsi)(int);
		int (*GetSystemCharacterCodeAnsi)(int *);
		int (*ResetNicknameDvdRegionDlnaFlag)(void);
		int (*SetSystemNotificationEnabled)(int);
		int (*GetSystemNotificationEnabled)(int *);
		int (*SetSystemDiscBootFirstEnabled)(int);
		int (*GetSystemDiscBootFirstEnabled)(int *);
		int (*SetSystemSoundEffectEnabled)(int);
		int (*GetSystemSoundEffectEnabled)(int *);
		int (*unk_new)(void *, void *);
		int (*unk_delete)(void *, void *);
}; 

class xsetting_CC56EB2D_class
{
	public:
		int32_t (*xUserInitialize)(void);
		int32_t (*xUserFinalize)(void);
		int32_t (*xUserGetNumOfUser)(void);
		int32_t (*xUserGetDefaultLoginUser)(void);
		int32_t (*xUserSetDefaultLoginUser)(int);
		int32_t (*xUserGetLastLoginUser)(void);
		int32_t (*xUserGetUserIdList)(int *,int);
		int32_t (*xUserCreateUser)(char *,int, int *);
		int32_t (*xUserCreateUserWithNPAccountInfo)(int); // Need more
		int32_t (*xUserDeleteUser)(int);
		int32_t (*xUserGetUserInfo)(void); // Need more
		int32_t (*xUserSetUserInfo)(void); // Need more
		int32_t (*GetCurrentUserNumber)(void);
		int32_t (*sub_486A58)(void);
		int32_t (*xUserLogin)(int);
		int32_t (*xUserLogout)(int);
		int32_t (*GetRegistryValue)(uint32_t userid, uint32_t packetid, int *value);
		int32_t (*GetRegistryString)(uint32_t userid, uint32_t packetid, char * value, uint32_t maxlen);
		int32_t (*SetRegistryValue)(uint32_t userid, uint32_t packetid, uint32_t value);
		int32_t (*SetRegistryString)(uint32_t userid, uint32_t packetid, char *value, uint32_t maxlen);	

		int GetRegistryNpGuestCountry(char *value)	{return GetRegistryString(GetCurrentUserNumber(), 0x82, value, 2);}
		int GetRegistryNpGuestLang(char *value)	{return GetRegistryString(GetCurrentUserNumber(), 0x83, value, 2);}
		int GetRegistryNpGuestBirth() {int value; GetRegistryValue(GetCurrentUserNumber(), 0x84, &value); return value;}
		int GetRegistryFocusMask() {int value; GetRegistryValue(GetCurrentUserNumber(), 0x8D, &value); return value;}

		int SetRegistryNpGuestCountry(char *value)	{return SetRegistryString(GetCurrentUserNumber(), 0x82, value, 2);}
		int SetRegistryNpGuestLang(char * value) {return SetRegistryString(GetCurrentUserNumber(), 0x83, value, 2);}
		int SetRegistryNpGuestBirth(int value) {int v; SetRegistryValue(GetCurrentUserNumber(), 0x84, value);}
		int SetRegistryFocusMask(int value) {int v; SetRegistryValue(GetCurrentUserNumber(), 0x8D, value);}
};

class xsetting_D0261D72_class
{
	public:
		int (*saveAvcInitialCameraMode)(int);
		int (*loadAvcInitialCameraMode)(int *);
		int (*saveNpEnvironment)(char *, int *); // env, len
		int (*loadNpEnvironment)(char *, int *); // env, len
		int (*saveRegistryIntValue)(int, int); // id, value
		int (*loadRegistryIntValue)(int, int*); // id, value
		int (*saveRegistryStringValue)(int, char *, int); // id, string, len
		int (*loadRegistryStringValue)(int, char *, int); // id, string, len
		int (*Setunk1)(int);
		int (*Getunk2)(int, int *);
		int (*Setunk3)(int, int);

		int loadRegistryAvcVgaLastBitrate()	{ int v; loadRegistryIntValue(0x00, &v);return v; }
		int loadRegistryGameLevel0Control()	{ int v; loadRegistryIntValue(0x01, &v);return v; }
		int loadRegistryNetworkServiceControl()	{ int v; loadRegistryIntValue(0x02, &v);return v; }
		int loadRegistryCddaServer()	{ int v; loadRegistryIntValue(0x03, &v);return v; }
		int loadRegistryGameBgmPlayback()	{ int v; loadRegistryIntValue(0x04, &v);return v; }
		int loadRegistryGameBgmVolume()	{ int v; loadRegistryIntValue(0x05, &v);return v; }
		int loadRegistryDummyBgmPlayer()	{ int v; loadRegistryIntValue(0x06, &v);return v; }
		int loadRegistryDynamicNormalizer()	{ int v; loadRegistryIntValue(0x07, &v);return v; }
		int loadRegistryNpDebug()	{ int v; loadRegistryIntValue(0x08, &v);return v; }
		int loadRegistryNpTitleId(char * titleid,int max_len)	{ return loadRegistryStringValue(0x09,titleid,max_len); }
		int loadRegistryNavOnly()	{ int v; loadRegistryIntValue(0x0A, &v);return v; }
		int loadRegistryNpAdClockDiff()	{ int v; loadRegistryIntValue(0x0B, &v);return v; }
		int loadRegistryDebugDrmError()	{ int v; loadRegistryIntValue(0x0C, &v);return v; }
		int loadRegistryDebugDrmClock()	{ int v; loadRegistryIntValue(0x0D, &v);return v; }
		int loadRegistryDebugConsoleBind()	{ int v; loadRegistryIntValue(0x0E, &v);return v; }
		int loadRegistryDebugIngameCommerce2()	{ int v; loadRegistryIntValue(0x0F, &v);return v; }
		int loadRegistryDebugSFForce()	{ int v; loadRegistryIntValue(0x10, &v);return v; }
		int loadRegistryDebugSFManifest()	{ int v; loadRegistryIntValue(0x11, &v);return v; }
		int loadRegistryDebugSFManifestURL(char * titleid,int max_len)	{ return loadRegistryStringValue(0x12,titleid,max_len); }
		int loadRegistryNpGeoFiltering()	{ int v; loadRegistryIntValue(0x13, &v);return v; }
		int loadRegistryGameUpdateImposeTest()	{ int v; loadRegistryIntValue(0x14, &v);return v; }
		int loadRegistryGameUpdateForceOverwrite()	{ int v; loadRegistryIntValue(0x15, &v);return v; }
		int loadRegistryFakeNpSnsThrottle()	{ int v; loadRegistryIntValue(0x16, &v);return v; }
		int loadRegistryFakeNpSnsThrottleWaitSeconds()	{ int v; loadRegistryIntValue(0x17, &v);return v; }
		int loadRegistryTppsProxyFlag()	{ int v; loadRegistryIntValue(0x18, &v);return v; }
		int loadRegistryTppsProxyServer(char * proxy,int max_len)	{ return loadRegistryStringValue(0x19,proxy,max_len); }
		int loadRegistryTppsProxyPort()	{ int v; loadRegistryIntValue(0x1A, &v);return v; }
		int loadRegistryTppsProxyUserName(char * username,int max_len)	{ return loadRegistryStringValue(0x1B,username,max_len); }
		int loadRegistryTppsProxyPassword(char * password,int max_len)	{ return loadRegistryStringValue(0x1C,password,max_len); }
		int loadRegistryRegion()	{ int v; loadRegistryIntValue(0x1D, &v);return v; }
		int loadRegistryNotificationTrophy()	{ int v; loadRegistryIntValue(0x1E, &v);return v; }
		int loadRegistryLicenseArea()	{ int v; loadRegistryIntValue(0x1F, &v);return v; }
		int loadRegistryHddSerial(char * hddserial)	{ return loadRegistryStringValue(0x20,hddserial,0x3D); }
		int loadRegistryCoreDump()	{ int v; loadRegistryIntValue(0x21, &v);return v; }
		int loadRegistryCoreDumpOptionTrigger()	{ int v; loadRegistryIntValue(0x22, &v);return v; }
		int loadRegistryCoreDumpOptionFileGen()	{ int v; loadRegistryIntValue(0x23, &v);return v; }
		int loadRegistryCoreDumpOptionExeCtrl()	{ int v; loadRegistryIntValue(0x24, &v);return v; }
		int loadRegistryMatEnable()	{ int v; loadRegistryIntValue(0x25, &v);return v; }
		int loadRegistryUpdateServerUrl(char * url,int max_len)	{ return loadRegistryStringValue(0x26,url,max_len); }
		int loadRegistryFakeLimitSize()	{ int v; loadRegistryIntValue(0x27, &v);return v; }
		int loadRegistryFakeFreeSpace()	{ int v; loadRegistryIntValue(0x28, &v);return v; }
		int loadRegistryFakeSavedataOwner()	{ int v; loadRegistryIntValue(0x29, &v);return v; }
		int loadRegistryFakeHddSpeed()	{ int v; loadRegistryIntValue(0x2A, &v);return v; }
		int loadRegistryDebugGameType()	{ int v; loadRegistryIntValue(0x2B, &v);return v; }
		int loadRegistryDebugBootPath()	{ int v; loadRegistryIntValue(0x2C, &v);return v; }
		int loadRegistryDebugDirName(char * path,int max_len)	{ return loadRegistryStringValue(0x2D,path,max_len); }
		int loadRegistryAppHomeBootPath()	{ int v; loadRegistryIntValue(0x2E, &v);return v; }
		int loadRegistryWolDex()	{ int v; loadRegistryIntValue(0x2F, &v);return v; }
		int loadRegistryDispHddSpace()	{ int v; loadRegistryIntValue(0x30, &v);return v; }
		int loadRegistryAutoNetworkUpdate()	{ int v; loadRegistryIntValue(0x31, &v);return v; }
		int loadRegistryAutoPowerOff()	{ int v; loadRegistryIntValue(0x32, &v);return v; }
		int loadRegistryAutoPowerOffEx()	{ int v; loadRegistryIntValue(0x33, &v);return v; }
		int loadRegistryAutoPowerOffDebug()	{ int v; loadRegistryIntValue(0x34, &v);return v; }
		int loadRegistryHdmiControl()	{ int v; loadRegistryIntValue(0x35, &v);return v; }
		int loadRegistryHdmiControlEx()	{ int v; loadRegistryIntValue(0x36, &v);return v; }
		int loadRegistryPowerOnDiscBoot()	{ int v; loadRegistryIntValue(0x37, &v);return v; }
		int loadRegistryPowerOnReset()	{ int v; loadRegistryIntValue(0x38, &v);return v; }
		int loadRegistryDisable15Timeout()	{ int v; loadRegistryIntValue(0x39, &v);return v; }
		int loadRegistryDebugSystemUpdate()	{ int v; loadRegistryIntValue(0x3A, &v);return v; }
		int loadRegistryFakePlus()	{ int v; loadRegistryIntValue(0x3B, &v);return v; }
		int loadRegistryTurnOffWarning()	{ int v; loadRegistryIntValue(0x3C, &v);return v; }
		int loadRegistryBootMode(char * bootmode,int max_len)	{ return loadRegistryStringValue(0x3D,bootmode,max_len); }
		int loadRegistryCrashreportCrepo()	{ int v; loadRegistryIntValue(0x3E, &v);return v; }
		int loadRegistryCrashreportReporterStatus()	{ int v; loadRegistryIntValue(0x3F, &v);return v; }
		int loadRegistryCrashreportVshGeneratorEnableFlag()	{ int v; loadRegistryIntValue(0x40, &v);return v; }
		int loadRegistryDateTimeAutoCorrection()	{ int v; loadRegistryIntValue(0x41, &v);return v; }
		int loadRegistryAutobootStartTime()	{ int v; loadRegistryIntValue(0x42, &v);return v; }
		int loadRegistryEdyDebug()	{ int v; loadRegistryIntValue(0x43, &v);return v; }
		int loadRegistryUpConvert()	{ int v; loadRegistryIntValue(0x44, &v);return v; }
		int loadRegistryFnrLevel()	{ int v; loadRegistryIntValue(0x45, &v);return v; }
		int loadRegistryBnrLevel()	{ int v; loadRegistryIntValue(0x46, &v);return v; }
		int loadRegistryMnrLevel()	{ int v; loadRegistryIntValue(0x47, &v);return v; }
		int loadRegistrySequentialPlay()	{ int v; loadRegistryIntValue(0x48, &v);return v; }
		int loadRegistryHD50HzOutput()	{ int v; loadRegistryIntValue(0x49, &v);return v; }
		int loadRegistryOutputExtMenu()	{ int v; loadRegistryIntValue(0x4A, &v);return v; }
		int loadRegistryOutputExtFunc()	{ int v; loadRegistryIntValue(0x4B, &v);return v; }
		int loadRegistryDtcpIpSettingMenu()	{ int v; loadRegistryIntValue(0x4C, &v);return v; }
		int loadRegistryHddCaptionLanguage()	{ int v; loadRegistryIntValue(0x4D, &v);return v; }
		int loadRegistryHddSoundLanguage()	{ int v; loadRegistryIntValue(0x4E, &v);return v; }
		int loadRegistryClosedCaption()	{ int v; loadRegistryIntValue(0x4F, &v);return v; }
		int loadRegistryEmuUpConvert()	{ int v; loadRegistryIntValue(0x50, &v);return v; }
		int loadRegistryEmuSmoothing()	{ int v; loadRegistryIntValue(0x51, &v);return v; }
		int loadRegistryMinisUpConvert()	{ int v; loadRegistryIntValue(0x52, &v);return v; }
		int loadRegistryPspemuViewmode()	{ int v; loadRegistryIntValue(0x53, &v);return v; }
		int loadRegistryPspemu3dDisplay()	{ int v; loadRegistryIntValue(0x54, &v);return v; }
		int loadRegistryPspemu3dDepthAdjust()	{ int v; loadRegistryIntValue(0x55, &v);return v; }
		int loadRegistryPspemu3dMenu()	{ int v; loadRegistryIntValue(0x56, &v);return v; }
		int loadRegistryPspemuAdhocModeWlan()	{ int v; loadRegistryIntValue(0x57, &v);return v; }
		int loadRegistryPspemuAdhocModeCh()	{ int v; loadRegistryIntValue(0x58, &v);return v; }
		int loadRegistryPs2emuSaveUtility()	{ int v; loadRegistryIntValue(0x59, &v);return v; }
		int loadRegistryPs2softemuFunc()	{ int v; loadRegistryIntValue(0x5A, &v);return v; }
		int loadRegistryPs2BgCaution()	{ int v; loadRegistryIntValue(0x5B, &v);return v; }
		int loadRegistryCameraPlfreq()	{ int v; loadRegistryIntValue(0x5C, &v);return v; }
		int loadRegistryTvCategory()	{ int v; loadRegistryIntValue(0x5D, &v);return v; }
		int loadRegistryHomeInstaller()	{ int v; loadRegistryIntValue(0x5E, &v);return v; }
		int loadRegistryHomeQAMode()	{ int v; loadRegistryIntValue(0x5F, &v);return v; }
		int loadRegistryDummyInGameXMB()	{ int v; loadRegistryIntValue(0x60, &v);return v; }
		int loadRegistryYconExplained()	{ int v; loadRegistryIntValue(0x61, &v);return v; }
		int loadRegistryXaiDebugFlag()	{ int v; loadRegistryIntValue(0x62, &v);return v; }
		int loadRegistryAdServerURL(char * url,int max_len)	{ return loadRegistryStringValue(0x63,url,max_len); }
		int loadRegistryAdCatalogVersion(char * version,int max_len)	{ return loadRegistryStringValue(0x64,version,max_len); }
		int loadRegistryAdEnableNotification()	{ int v; loadRegistryIntValue(0x65, &v);return v; }
		int loadRegistryUploadDebug()	{ int v; loadRegistryIntValue(0x66, &v);return v; }
		int loadRegistryNetAutoDlDebug()	{ int v; loadRegistryIntValue(0x67, &v);return v; }
		int loadRegistryNetAutoDlFlag()	{ int v; loadRegistryIntValue(0x68, &v);return v; }
		int loadRegistryNetAutoDlTime()	{ int v; loadRegistryIntValue(0x69, &v);return v; }
		int loadRegistryNetAutoDlFunc()	{ int v; loadRegistryIntValue(0x6A, &v);return v; }
		int loadRegistryNetEmulationType()	{ int v; loadRegistryIntValue(0x6B, &v);return v; }   // questionable
		int loadRegistryNetAdhocSsidPrefix(char * prefix,int max_len)	{ return loadRegistryStringValue(0x6C,prefix,max_len); }
		int loadRegistryPadVibrationEnable()	{ int v; loadRegistryIntValue(0x6D, &v);return v; }
		int loadRegistryPadAutoPowerOff()	{ int v; loadRegistryIntValue(0x6E, &v);return v; }
		int loadRegistryPadMagnetometer()	{ int v; loadRegistryIntValue(0x6F, &v);return v; }
		int loadRegistrySound0Initial()	{ int v; loadRegistryIntValue(0x70, &v);return v; }
		int loadRegistrySound1UsbHeadSetSound()	{ int v; loadRegistryIntValue(0x71, &v);return v; }   // questionable
		int loadRegistryDlnaFlag()	{ int v; loadRegistryIntValue(0x72, &v);return v; }		
		int loadRegistryDlnaDtcpipDevCert()	{ int v; loadRegistryIntValue(0x73, &v);return v; }   // questionable
		int loadRegistryBrowserTrendEula()	{ int v; loadRegistryIntValue(0x74, &v);return v; }
		int loadRegistryBrowserTrendEnable()	{ int v; loadRegistryIntValue(0x75, &v);return v; }
		int loadRegistryBrowserTrendLastTime()	{ int v; loadRegistryIntValue(0x76, &v);return v; }
		int loadRegistryBrowserTrendTtl()	{ int v; loadRegistryIntValue(0x77, &v);return v; }
		int loadRegistryBrowserTrendRegistered()	{ int v; loadRegistryIntValue(0x78, &v);return v; }
		int loadRegistryBrowserHeapSize()	{ int v; loadRegistryIntValue(0x79, &v);return v; }
		int loadRegistryBrowserDebugMenu()	{ int v; loadRegistryIntValue(0x7A, &v);return v; }
		int loadRegistryBrowserType()	{ int v; loadRegistryIntValue(0x7B, &v);return v; }
		int loadRegistryWboardBaseUri(char * uri,int max_len)	{ return loadRegistryStringValue(0x7C,uri,max_len); }
		int loadRegistrySmssTargetServer()	{ int v; loadRegistryIntValue(0x7D, &v);return v; }
		int loadRegistrySmssResultOutput()	{ int v; loadRegistryIntValue(0x7E, &v);return v; }
		int loadRegistryDisplayForceEnable3D()	{ int v; loadRegistryIntValue(0x7F, &v);return v; }
		int loadRegistryDisplayScreenSize()	{ int v; loadRegistryIntValue(0x80, &v);return v; }
		int loadRegistryDisplayDeepColor()	{ int v; loadRegistryIntValue(0x81, &v);return v; }		
		int saveRegistryDlnaFlag(int v)	{ return saveRegistryIntValue(0x72, v); }
};

#endif /* _XREGISTRY_H */