#ifndef _COMMON_H_
#define _COMMON_H_

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "functions.h"

#define KERNEL_BASE					0x8000000000000000ULL
#define KERNEL_ADDRESS(x)			(KERNEL_BASE | (uint32_t)(x))
#define SYSCALL_OPD_PTR_OFFSET(n)	(SYSCALL_TABLE_OFFSET + (n) * sizeof(uint64_t))
#define SYSCALL_OPD_OFFSET(n)		peekq(SYSCALL_OPD_PTR_OFFSET(n))
#define SYSCALL_CODE_OFFSET(n)		peekq(SYSCALL_OPD_OFFSET(n))

#define EID_ROOT_KEY_SIZE			0x30

/* Firmware specific defines */
#define TOC_OFFSET					KERNEL_ADDRESS(0x34FBB0)
#define SYSCALL_TABLE_OFFSET		KERNEL_ADDRESS(0x363BE0)
#define PAYLOAD_OFFSET				KERNEL_ADDRESS(0x7F0000)
#define PAYLOAD_OPD_OFFSET			KERNEL_ADDRESS(0x1630)

#define HTAB_BASE					KERNEL_ADDRESS(0xF000000)
#define HTAB_SIZE					0x40000ULL
#define HTAB_ENTRY_SIZE				0x10

//#define SYSCALL_LV2_POKE			7
//#define SYSCALL_LV1_PEEK			8
//#define SYSCALL_LV1_POKE			9
#define SYSCALL_RUN_PAYLOAD			32
//#define SYSCALL_SM_SHUTDOWN			379
//#define SYSCALL_RING_BUZZER			392
//#define SYSCALL_CONSOLE_WRITE		398
#define SYSCALL_HVC_REDIRECTOR		811
//#define SYSCALL_POKE_WITH_CACHE		813

#endif
