
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#include "hvcall.h"
#include "util.h"
#include "functions.h"

#define SYSCALL_HVC_REDIRECTOR_OFFSET SYSCALL_CODE_OFFSET(SYSCALL_HVC_REDIRECTOR)

#define INSTALL_HVSC_REDIRECT(n) \
	uint64_t tmp1 = peekq(SYSCALL_HVC_REDIRECTOR_OFFSET); \
	uint64_t tmp2 = peekq(SYSCALL_HVC_REDIRECTOR_OFFSET + 8); \
	uint64_t tmp3 = peekq(SYSCALL_HVC_REDIRECTOR_OFFSET + 16); \
	uint64_t tmp4 = peekq(SYSCALL_HVC_REDIRECTOR_OFFSET + 24); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET +  0, 0x7C0802A6F8010010ULL); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET +  8, 0x3960000044000022ULL | ((uint64_t)(n) << 32)); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET + 16, 0xE80100107C0803A6ULL); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET + 24, 0x4E80002060000000ULL);
	
#define REMOVE_HVSC_REDIRECT() \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET, tmp1); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET + 8, tmp2); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET + 16, tmp3); \
	pokeq(SYSCALL_HVC_REDIRECTOR_OFFSET + 24, tmp4);

#define SYSCALL_HELPER(x) #x
#define SYSCALL(n) "li %%r11, " SYSCALL_HELPER(n) "; sc;"

int lv1_insert_htab_entry(uint64_t htab_id, uint64_t hpte_group, uint64_t hpte_v, uint64_t hpte_r, uint64_t bolted_flag, uint64_t flags, uint64_t* hpte_index, uint64_t* hpte_evicted_v, uint64_t* hpte_evicted_r) 
{
	int result;

	uint64_t index = 0;
	uint64_t evicted_v = 0;
	uint64_t evicted_r = 0;

	INSTALL_HVSC_REDIRECT(0x9E);

	__asm__ __volatile__(
		"mr %%r3, %4;"
		"mr %%r4, %5;"
		"mr %%r5, %6;"
		"mr %%r6, %7;"
		"mr %%r7, %8;"
		"mr %%r8, %9;"
		SYSCALL(SYSCALL_HVC_REDIRECTOR)
		"mr %0, %%r3;"
		"mr %1, %%r4;"
		"mr %2, %%r5;"
		"mr %3, %%r6;"
		: "=r"(result), "=r"(index), "=r"(evicted_v), "=r"(evicted_r)
		: "r"(htab_id), "r"(hpte_group), "r"(hpte_v), "r"(hpte_r), "r"(bolted_flag), "r"(flags)
		: "r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory"
	);
		
	REMOVE_HVSC_REDIRECT();

	if (hpte_index)
		*hpte_index = index;
	if (hpte_evicted_v)
		*hpte_evicted_v = evicted_v;
	if (hpte_evicted_r)
		*hpte_evicted_r = evicted_r;

	return result;
}

int lv1_write_htab_entry(uint64_t vas_id, uint64_t hpte_index, uint64_t hpte_v, uint64_t hpte_r) 
{
	int result;

	INSTALL_HVSC_REDIRECT(1);

	__asm__ __volatile__ (
		"mr %%r3, %1;"
		"mr %%r4, %2;"
		"mr %%r5, %3;"
		"mr %%r6, %4;"
		SYSCALL(SYSCALL_HVC_REDIRECTOR)
		"mr %0, %%r3;"
		: "=r"(result)
		: "r"(vas_id), "r"(hpte_index), "r"(hpte_v), "r"(hpte_r)
		: "r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory"
	);
		
	REMOVE_HVSC_REDIRECT();

	return result;
}