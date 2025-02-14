#ifndef _EEPROM_H_
#define _EEPROM_H_

#include <stdio.h>

typedef struct
{
	uint32_t offset;
	uint32_t patch;
	uint32_t ori;
} patches_eeprom;

uint64_t findValueinLV1(uint64_t min_offset, uint64_t max_offset, uint64_t value);
int dump_eeprom();

#endif