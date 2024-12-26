#ifndef _REBUGTOOLBOX_H
#define _REBUGTOOLBOX_H

#include <stdio.h>
#include "functions.h"
#include "cfw_settings.h"
#include "log.h"

#define LV1_PP_OFFSET		0x8000000000309E4CULL
#define LV1_LV2_OFFSET		0x80000000002B4434ULL
#define	LV1_HTAB_OFFSET		0x80000000002DD70CULL
#define LV1_INDI_OFFSET		0x80000000000AC594ULL
#define LV1_UM_OFFSET		0x80000000000FEBD4ULL
#define LV1_DM_OFFSET1		0x800000000016FA64ULL
#define LV1_DM_OFFSET2		0x800000000016FA88ULL
#define LV1_DM_OFFSET3		0x800000000016FB00ULL
#define LV1_DM_OFFSET4		0x800000000016FB08ULL
#define LV1_ENC_OFFSET		0x8000000000274FECULL
#define LV1_PKG_OFFSET		0x80000000000FBE24ULL
#define LV1_LPAR_OFFSET1	0x80000000002E4E28ULL
#define LV1_LPAR_OFFSET2	0x80000000002E50ACULL
#define LV1_LPAR_OFFSET3	0x80000000002E5550ULL
#define LV1_SPE_OFFSET		0x80000000002F9EB8ULL
#define LV1_DABR_OFFSET		0x80000000002EB550ULL
#define LV1_GART_OFFSET		0x8000000000214F1CULL
#define LV1_KEYS_OFFSET		0x8000000000714D50ULL
#define LV1_ACL_OFFSET1		0x800000000025C504ULL
#define LV1_ACL_OFFSET2 	0x800000000025C50CULL

typedef struct
{
	uint64_t offset;
	uint64_t patch;
	uint64_t ori;
} patches_64_st;

typedef struct
{
	uint64_t offset;
	uint32_t patch;
	uint32_t ori;
} patches_32_st;

static patches_64_st lv1_lpar_data[11] =
{
	// Part 1
	{ LV1_LPAR_OFFSET1 + 0,  0xE81E0020E95E0028ULL, 0xE81E0018E95E0020ULL },
	{ LV1_LPAR_OFFSET1 + 8,  0xE91E0030E8FE0038ULL, 0xE91E0028E8FE0030ULL },
	{ LV1_LPAR_OFFSET1 + 12, 0xE8FE0038EBFE0018ULL, 0xE8FE0030EBEB0050ULL },

	// Part 2
	{ LV1_LPAR_OFFSET2 + 0,  0xE81E0020E93E0028ULL, 0xE81E0018E93E0020ULL},
	{ LV1_LPAR_OFFSET2 + 8,  0xE95E0030E91E0038ULL, 0xE95E0028E91E0030ULL},
	{ LV1_LPAR_OFFSET2 + 16, 0xE8FE0040E8DE0048ULL, 0xE8FE0038E8DE0040ULL},
	{ LV1_LPAR_OFFSET2 + 20, 0xE8DE0048EBFE0018ULL, 0xE8DE0040EBEB0050ULL},

	// Part 3
	{ LV1_LPAR_OFFSET3 + 0,  0xE81E0020E93E0028ULL, 0xE81E0018E93E0020ULL},
	{ LV1_LPAR_OFFSET3 + 8,  0xE95E0030E91E0038ULL, 0xE95E0028E91E0030ULL},
	{ LV1_LPAR_OFFSET3 + 16, 0xE8FE0040E8DE0048ULL, 0xE8FE0038E8DE0040ULL},
	{ LV1_LPAR_OFFSET3 + 20, 0xE8DE0048EBFE0018ULL, 0xE8DE0040EBEB0050ULL},
};

static patches_64_st lv1_pp_data[4] =
{	
	{ LV1_PP_OFFSET + 0,  0xE8830018E8840000ULL, 0x6400FFFF6000FFECULL },
	{ LV1_PP_OFFSET + 8,  0xF88300C84E800020ULL, 0xF80300C04E800020ULL },
	{ LV1_PP_OFFSET + 16, 0x38000000E8A30020ULL, 0x380000006400FFFFULL },
	{ LV1_PP_OFFSET + 24, 0xE8830018F8A40000ULL, 0x6000FFECF80300C0ULL },
};

static patches_32_st lv1_data[10] =
{	
	{ LV1_LV2_OFFSET,  0x60000000, 0x419E0118 },
	{ LV1_HTAB_OFFSET, 0x60000000, 0x41DA0054 },
	{ LV1_INDI_OFFSET, 0x38600000, 0x7C630038 },
	{ LV1_UM_OFFSET,   0x38000000, 0xE8180008 },
	{ LV1_ENC_OFFSET,  0x392001DF, 0x392001CF },
	{ LV1_PKG_OFFSET,  0x60000000, 0x419D00A8 },
	{ LV1_SPE_OFFSET,  0x3920FFFF, 0x39200009 },
	{ LV1_DABR_OFFSET, 0x3800000F, 0x3800000B },
	{ LV1_GART_OFFSET, 0x38001000, 0x3C000001 },
	{ LV1_KEYS_OFFSET, 0x60000000, 0x419D004C },
};

static patches_32_st dm_data[4] =
{	
	{ LV1_DM_OFFSET1, 0x60000000, 0xF8010098 },
	{ LV1_DM_OFFSET2, 0x38600001, 0x4BFFF0E5 },
	{ LV1_DM_OFFSET3, 0x3BE00001, 0x38A10070 },
	{ LV1_DM_OFFSET4, 0x38600000, 0x48006065 },
};

static patches_64_st acl_data[2] =
{	
	{ LV1_ACL_OFFSET1, 0x386000012F830000ULL, 0x5463063E2F830000ULL },
	{ LV1_ACL_OFFSET2, 0x419E001438000001ULL, 0x419E0014E8010070ULL },
};

static void rtb_option(uint64_t offset)
{
	uint32_t current_value;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}
	
	current_value = lv1_peek32(offset);

	for(int i = 0; i < 10; i++)
	{
		if(offset == lv1_data[i].offset)
		{
			lv1_poke32(lv1_data[i].offset, (current_value == lv1_data[i].ori ? lv1_data[i].patch : lv1_data[i].ori));
			showMessage(current_value == lv1_data[i].ori ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			return;
		}
	}
	
	showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
}

void rtb_pp()
{
	uint64_t current_value;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek_cobra(lv1_pp_data[0].offset);

	if(current_value != lv1_pp_data[0].patch)
	{
		for(int i = 0; i < 4; i++)
			lv1_poke(lv1_pp_data[i].offset, lv1_pp_data[i].patch);
	}
	else
	{
		for(int i = 0; i < 4; i++)
			lv1_poke(lv1_pp_data[i].offset, lv1_pp_data[i].ori);
	}
	
	current_value = lv1_peek(lv1_pp_data[0].offset);
	showMessage(current_value == lv1_pp_data[0].patch ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_dm()
{
	uint32_t current_value;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek32(dm_data[0].offset);
	
	for(int i = 0; i < 4; i++)
		lv1_poke32(dm_data[i].offset, (current_value == dm_data[0].ori ? dm_data[i].patch : dm_data[i].ori));

	current_value = lv1_peek32(dm_data[0].offset);
	showMessage(current_value == dm_data[0].ori ? "msg_disabled" : "msg_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_smgo()
{
	int isNor, targetID;
	int current_value;
	uint64_t offset;
	uint8_t	idps0[IDPS_SIZE];

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	isNor = check_flash_type();
	targetID = getTargetID(1);

	if(targetID != 0x82 && isNor)
		offset = 0x80000000001194CCULL;
	else if(targetID == 0x82 && isNor)
		offset = 0x80000000001504CCULL;
	else if(targetID != 0x82 && !isNor)
		offset = 0x80000000007814CCULL;
	else if(targetID == 0x82 && !isNor)
		offset = 0x80000000003784CCULL;

	if(!offset)
	{
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek32(offset) == 0x640003FB;
	lv1_poke32(offset, (current_value ? 0x6400FFFF : 0x640003FB));
	lv1_poke32(offset + 8, (current_value ? 0x6000FFFE : 0x6000F7EE));
	showMessage(current_value ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_go()
{
	int isNor, targetID;
	int current_value;
	uint64_t offset;
	uint8_t	idps0[IDPS_SIZE];

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	isNor = check_flash_type();
	targetID = getTargetID(1);

	if(targetID != 0x82 && isNor)
		offset = 0x8000000000168090ULL;
	else if(targetID != 0x82 && !isNor)
		offset = 0x800000000011C090ULL;
	else if(targetID == 0x82)
		offset = 0x800000000011B090ULL;	

	if(!offset)
	{
		showMessage("msg_sort_games_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek32(offset) == 0x38600000;
	lv1_poke32(offset, (current_value ? 0x38600001 : 0x38600000));
	lv1_poke32(offset + 8, (current_value ? 0x38600001 : 0x38600000));
	showMessage(current_value ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_lpar()
{
	uint64_t current_value;	

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}	

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek(lv1_lpar_data[0].offset);

	for(int i = 0; i < 11; i++)
		lv1_poke(lv1_lpar_data[i].offset, (current_value == lv1_lpar_data[0].ori ? lv1_lpar_data[i].patch : lv1_lpar_data[i].ori));

	current_value = lv1_peek(lv1_lpar_data[0].offset);
	showMessage(current_value == lv1_lpar_data[0].ori ? "msg_disabled" : "msg_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_acl()
{
	uint64_t current_value;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	current_value = lv1_peek(acl_data[0].offset);

	for(int i = 0; i < 2; i++)
		lv1_poke(acl_data[i].offset, (current_value == acl_data[0].ori ? acl_data[i].patch : acl_data[i].ori));

	current_value = lv1_peek(acl_data[0].offset);
	showMessage(current_value == acl_data[0].ori ? "msg_disabled" : "msg_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

#endif /* _REBUGTOOLBOX_H */