#ifndef _REBUGTOOLBOX_H
#define _REBUGTOOLBOX_H

/*
 *	This file contains data for different versions of FW
 *	It is possible that support for some more may need to be added
 */

#include <stdio.h>
#include "functions.h"
#include "cfw_settings.h"
#include "log.h"

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
	{ 0, 0xE81E0020E95E0028ULL, 0xE81E0018E95E0020ULL },
	{ 0, 0xE91E0030E8FE0038ULL, 0xE91E0028E8FE0030ULL },
	{ 0, 0xE8FE0038EBFE0018ULL, 0xE8FE0030EBEB0050ULL },

	{ 0, 0xE81E0020E93E0028ULL, 0xE81E0018E93E0020ULL},
	{ 0, 0xE95E0030E91E0038ULL, 0xE95E0028E91E0030ULL},
	{ 0, 0xE8FE0040E8DE0048ULL, 0xE8FE0038E8DE0040ULL},
	{ 0, 0xE8DE0048EBFE0018ULL, 0xE8DE0040EBEB0050ULL},

	{ 0, 0xE81E0020E93E0028ULL, 0xE81E0018E93E0020ULL},
	{ 0, 0xE95E0030E91E0038ULL, 0xE95E0028E91E0030ULL},
	{ 0, 0xE8FE0040E8DE0048ULL, 0xE8FE0038E8DE0040ULL},
	{ 0, 0xE8DE0048EBFE0018ULL, 0xE8DE0040EBEB0050ULL},
};

static patches_64_st lv1_pp_data[4] =
{	
	{ 0, 0xE8830018E8840000ULL, 0x6400FFFF6000FFECULL },
	{ 0, 0xF88300C84E800020ULL, 0xF80300C04E800020ULL },
	{ 0, 0x38000000E8A30020ULL, 0x380000006400FFFFULL },
	{ 0, 0xE8830018F8A40000ULL, 0x6000FFECF80300C0ULL },
};	

static patches_32_st dm_data[4] =
{	
	{ 0, 0x60000000, 0xF8010098 },
	{ 0, 0x38600001, 0x4BFFF0E5 },
	{ 0, 0x3BE00001, 0x38A10070 },
	{ 0, 0x38600000, 0x48006065 },
};

static patches_32_st acl_data[2] =
{	
	{ 0, 0x38600001, 0x5463063E },
	{ 0, 0x38000001, 0xE8010070 },
};

void offsetNotfound()
{
	showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
}

int rbt_custom_lv1_patch(uint64_t pattern, uint64_t min_offset, uint64_t max_offset, uint32_t original, uint32_t patch, int suffix)
{
	char patch_state[120];
	uint64_t current_value, offset, first_value;

	if(checkSyscalls(LV1))
	{
		showMessage("msg_cfw_syscalls_disabled", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	// HEN
	if(!is_hen())
	{
		showMessage("msg_hen_notsupported_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 1;
	}

	offset = findValueinLV1(min_offset, max_offset, pattern);

	if(!offset)
		return 2;

	offset = offset + suffix;

	first_value = lv1_peek32(offset) == original;

	current_value = lv1_peek32(offset);
	sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n",
		offset, current_value, (first_value ? patch : original));
	log(patch_state);

	lv1_poke32(offset, (first_value ? patch : original));

	current_value = lv1_peek32(offset) == patch;
	showMessage(current_value ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);

	return 0;
}

void rtb_pp()
{
	char patch_state[120];
	uint64_t current_value, lv1_pp_offset, first_value;

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

	lv1_pp_offset = findValueinLV1(0x300000, 0x350000, 0x4BEFC43438000000ULL);

	if(!lv1_pp_offset)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	lv1_pp_data[0].offset = lv1_pp_offset + 8;
	lv1_pp_data[1].offset = lv1_pp_offset + 16;
	lv1_pp_data[2].offset = lv1_pp_offset + 24;
	lv1_pp_data[3].offset = lv1_pp_offset + 32;

	first_value = lv1_pp_data[0].offset == lv1_pp_data[0].ori;

	for(int i = 0; i <= 3; i++)
	{
		sprintf_(patch_state, "Patching LV1: Offset 0x%X\n", lv1_pp_data[i].offset);
		log(patch_state);
		lv1_poke(lv1_pp_data[i].offset, (first_value ? lv1_pp_data[i].patch : lv1_pp_data[i].ori));
	}
	
	current_value = lv1_peek(lv1_pp_data[0].offset);
	showMessage(current_value == lv1_pp_data[0].patch ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_dm()
{
	char patch_state[120];
	uint32_t current_value, first_value;
	uint64_t lv1_dm_offset;

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

	lv1_dm_offset = findValueinLV1(0x150000, 0x180000, 0x48004EC5E8170008ULL);
	if(!lv1_dm_offset)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	dm_data[0].offset = lv1_dm_offset + 0x10;
	dm_data[1].offset = lv1_dm_offset + 0x34;
	dm_data[2].offset = lv1_dm_offset + 0xAC;
	dm_data[3].offset = lv1_dm_offset + 0xB4;

	first_value = lv1_peek32(dm_data[0].offset) == dm_data[0].ori;

	for(int i = 0; i <= 3; i++)
	{
		current_value = lv1_peek32(dm_data[i].offset);
		sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n", 
			dm_data[i].offset, current_value, (first_value ? dm_data[i].patch : dm_data[i].ori));
		log(patch_state);
		lv1_poke32(dm_data[i].offset, (first_value ? dm_data[i].patch : dm_data[i].ori));
	}

	current_value = lv1_peek32(dm_data[0].offset);
	showMessage(current_value == dm_data[0].patch ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_smgo()
{
	char patch_state[120];
	uint32_t current_value, current_value2, first_value;
	uint64_t offset;

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

	offset = findValueinLV1(0x115000, 0x120000, 0x39200003F91F0068ULL);
	if(!offset)
		offset = findValueinLV1(0x150000, 0x160000, 0x39200003F91F0068ULL);
	if(!offset)
		offset = findValueinLV1(0x240000, 0x24000, 0x39200003F91F0068ULL);
	if(!offset)
		offset = findValueinLV1(0x375000, 0x380000, 0x39200003F91F0068ULL);
	if(!offset)
		offset = findValueinLV1(0x780000, 0x782000, 0x39200003F91F0068ULL);

	if(!offset)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	offset = offset + 8;

	first_value = lv1_peek32(offset) == 0x640003FB;

	current_value = lv1_peek32(offset);
	sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n",
		offset, current_value, (first_value ? 0x6400FFFF : 0x640003FB));
	log(patch_state);

	current_value2 = lv1_peek32(offset + 8);
	sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n",
		offset + 8, current_value2, (first_value ? 0x6000FFFE : 0x6000F7EE));
	log(patch_state);

	lv1_poke32(offset, (current_value == 0x6400FFFF ? 0x640003FB : 0x6400FFFF));
	lv1_poke32(offset + 8, (current_value == 0x6400FFFF ? 0x6000F7EE : 0x6000FFFE));

	current_value = lv1_peek32(offset) == 0x6400FFFF;
	showMessage(current_value ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_go()
{
	char patch_state[120];
	uint32_t current_value, first_value;
	uint64_t offset;

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

	offset = findValueinLV1(0x110000, 0x120000, 0x386000FF4800DCF1ULL);
	if(!offset)
		offset = findValueinLV1(0x160000, 0x170000, 0x386000FF4800DCF1ULL);
	if(!offset)
		offset = findValueinLV1(0x1B0000, 0x1C0000, 0x386000FF4800DCF1ULL);

	if(!offset)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	offset = offset + 8;

	first_value = lv1_peek32(offset) == 0x38600000;

	current_value = lv1_peek32(offset);
	sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n",
		offset, current_value, (first_value ? 0x38600001 : 0x38600000));
	log(patch_state);

	lv1_poke32(offset, (first_value ? 0x38600001 : 0x38600000));

	current_value = lv1_peek32(offset) == 0x38600001;
	showMessage(current_value ? "msg_enabled" : "msg_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_lpar()
{
	char patch_state[120];
	uint64_t current_value, first_value;	
	uint64_t lv1_par_offset1, lv1_par_offset2, lv1_par_offset3;	

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

	lv1_par_offset1 = findValueinLV1(0x2E0000, 0x300000, 0xE87D0000FBE100C8ULL);
	lv1_par_offset2 = findValueinLV1(0x2E0000, 0x300000, 0x4BFFFF683D2D0000ULL);
	lv1_par_offset3 = findValueinLV1(0x2E0000, 0x300000, 0x6063FFFAEBE100E8ULL);

	if(!lv1_par_offset1 || !lv1_par_offset2 || !lv1_par_offset3)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	lv1_lpar_data[0].offset = lv1_par_offset1 + 8;
	lv1_lpar_data[1].offset = lv1_par_offset1 + 0x10;
	lv1_lpar_data[2].offset = lv1_par_offset1 + 0x14;

	lv1_lpar_data[3].offset = lv1_par_offset2 + 0x38;
	lv1_lpar_data[4].offset = lv1_par_offset2 + 0x40;
	lv1_lpar_data[5].offset = lv1_par_offset2 + 0x48;
	lv1_lpar_data[6].offset = lv1_par_offset2 + 0x4C;

	lv1_lpar_data[7].offset = lv1_par_offset3 + 0x70;
	lv1_lpar_data[8].offset = lv1_par_offset3 + 0x78;
	lv1_lpar_data[9].offset = lv1_par_offset3 + 0x80;
	lv1_lpar_data[10].offset = lv1_par_offset3 + 0x84;

	first_value = lv1_peek(lv1_lpar_data[0].offset) == lv1_lpar_data[0].ori;

	for(int i = 0; i <= 10; i++)
	{		
		sprintf_(patch_state, "Patching LV1: Offset 0x%X\n", lv1_lpar_data[i].offset);
		log(patch_state);
		lv1_poke(lv1_lpar_data[i].offset, (first_value ? lv1_lpar_data[i].patch : lv1_lpar_data[i].ori));
	}

	current_value = lv1_peek(lv1_lpar_data[0].offset);
	showMessage(current_value == lv1_lpar_data[0].ori ? "msg_disabled" : "msg_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

void rtb_acl()
{
	char patch_state[120];
	uint32_t current_value, first_value;
	uint64_t acl_data_offset;	

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

	acl_data_offset = findValueinLV1(0x250000, 0x280000, 0x38A100704805E7B5ULL);

	if(!acl_data_offset)
	{
		showMessage("msg_rap2bin_error", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return;
	}

	acl_data[0].offset = acl_data_offset + 8;
	acl_data[1].offset = acl_data_offset + 0x14;

	first_value = lv1_peek32(acl_data[0].offset) == acl_data[0].ori;

	for(int i = 0; i <= 1; i++)
	{
		current_value = lv1_peek32(acl_data[i].offset);
		sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n", 
			acl_data[i].offset, current_value, (first_value ? acl_data[i].patch : acl_data[i].ori));
		log(patch_state);
		lv1_poke32(acl_data[i].offset, (first_value ? acl_data[i].patch : acl_data[i].ori));
	}
	
	current_value = lv1_peek32(acl_data[0].offset);
	showMessage(current_value == acl_data[0].ori ? "msg_disabled" : "msg_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
}

#endif /* _REBUGTOOLBOX_H */