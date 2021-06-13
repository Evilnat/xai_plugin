// Mysis game_plugin.h v0.1
class game_plugin_interface
{
public:
	int (*DoUnk0)(); // set Widget "page_game_main" and activate
	int (*DoUnk1)(void *); // uint8_t [0x5B8]
	int (*DoUnk2)(void *); // uint8_t [0x230]
	int (*DoUnk3)(int); // 3 = "CB" Category
	int (*DoUnk4)(int, void *); // uint8_t [0x1A0]
	int (*DoUnk5)();
	int (*DoUnk6)();
	int (*DoUnk7)();
	int (*DoUnk8)(void *); // uint8_t [0x114]
	int (*DoUnk9)(void *); // uint8_t [0x80]
	int (*DoUnk10)(char *); // char [8]
	int (*DoUnk11)(unsigned long, int);
	int (*DoUnk12)();
	int (*DoUnk13)();
	int (*DoUnk14)();
	int (*GetExecAppType)(int *, int *); // apptype, extended type?
	int (*DoUnk16)(int *);
	int (*DoUnk17)();
	int (*DoUnk18)(int *, char *); // char [0x20]
	int (*DoUnk19)(int *, char *, char *); // char [0x20]
	int (*DoUnk20)(void *); // uint8_t [0x5B8]
	int (*DoUnk21)();
	int (*commerce2ExecuteStoreBrowse)(int,char *, int, int); //targetType,targetId,flags,userdata
	int (*DoUnk23)(void *); // uint8_t [0xA4]
	int (*DoUnk24)(void *); // uint8_t [0xA4]
	int (*wakeupWithGameExit)(char *, int); // char [0x800], userdata
	int (*commerce2Reboot4PrgDl)(int); // taskId
	int (*DoUnk27)(char *); // [0x800]
	int (*DoUnk28)();
	int (*DoUnk29)(void *); // [0xxA4]
	int (*commerce2GetOptions)(int *); // userdata
	int (*GetUsrdataOnGameExit)(int *);
	int (*GetManualPath)(char *); // [0x80]
	int (*DoUnk33)();
	int (*DoUnk34)(char *); // [0x20]
	int (*DoUnk35)(char *); // [0x20]
	int (*DoUnk36)(int, char *); // no size check
	int (*DoUnk37)();
	int (*DoUnk38)(unsigned long);
	int (*DoUnk39)(char *); // titleId[0x20]
	int (*DoUnk40)(char *, int *, int); // titleId[0x20]
	int (*DoUnk41)(char *, char *, int); // titleId[0x20], char [4]
	int (*DoUnk42)(char *, int, char *, int); //titleid, flags
	int (*DoUnk43)();
	int (*DoUnk44)();
	int (*initGameData)(int,int); // memContainer, NoCalcFlag
	int (*EndGameData)();
	int (*getGameDataStat)(char *, char *, void *); // [0x1450]
	int (*updateGameData)(char *, char *, void *, void *);//callback, sysparam[0x1450]
	int (*DoUnk49)(int,int,int,void *,char *);
	int (*DoUnk50)();
	int (*DoUnk51)();
	int (*cacheInit)(void *, void *); // callback, SysCacheParam[0x444]
	int (*cacheClear)();
	int (*GetBootInfo)(void *);// [0x20]
	int (*GetTitleId)(void *);
	int (*kbGetSize)(int *, int);
	int (*SetSysVersion)(char *);
	int (*GetDiscInfo)(void *); //[0x20]
	int (*DoUnk59)(int, int, void *, int);
	int (*SetEjectMode)(int); //int mode
	int (*gameExec)(char *, char *, int, int, int, int, int);
	int (*getList)(int *, int *, int *, int *, int);
	int (*DoUnk63_GetBootInfo)(int *, char *, int *); //[0x20]
	int (*SetExecDataParam)(int *);
	int (*GetExitInfo)(int *, int *, char *, int *, int *);
	int (*HomePath)(char *);
	int (*DeleteGame)(char *, int);
	int (*OptionPath)(char *, char *);
	int (*ExportPath)(char *);
	int (*ImportPath)(char *);
	int (*Open)(int,char *, int, int *);
	int (*BootCheck)(int *, int *, int, int *, char *);
	int (*PatchCheck)(int, int *);
	int (*Create)(void *, char *, char *, int);
	int (*getInt)(int, int*, int);
	int (*getStr)(int, char *, int, int);
	int (*setInt)(int, int, int);
	int (*setStr)(int, char *, int);
	int (*Close)(char *, char *);
	int (*DoUnk80)(int, int, char *);
	int (*getSizeKB)(int *);
	int (*tInstall)(char *, char *, int, int);
	int (*mtInstall)(int);
	int (*mtWrite)(int, void *);
	int (*mtClose)(int, int);
	int (*getUpPath)(char *);
	int (*getWConPath)(char *);
	int (*delGameData)(char *);
	int (*getDevIdList)(int *, void *);
	int (*getDevInfo)(unsigned long, void *);
	int (*getUsbDevInfo)(unsigned long, void *);
	int (*storageMode)();
	int (*notifyCtrl)(int);
	int (*allreadyDisp)();
	int (*pspLoad)(void *, int);
	int (*pspSave)(void *, int);
	int (*vmcAssign)(int, char *, void *, int);
	int (*ps1End)(int);
	int (*SetPadRumble)(int);
	int (*DoUnk100)(void *, int);
	int (*DoUnk101)();
	int (*DoUnk102)(char *);
	int (*DoUnk103_DeleteGame)(char *);
	int (*DoUnk104)();
}; game_plugin_interface * game_interface;