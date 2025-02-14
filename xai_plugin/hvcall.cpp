
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#include "hvcall.h"
#include "functions.h"

uint64_t OFFSET_HVSC_REDIRECT = 0;
uint64_t tmp1 = 0;
uint64_t tmp2 = 0;
uint64_t tmp3 = 0;
uint64_t tmp4 = 0;

static void INSTALL_HVSC_REDIRECT(uint64_t offset)
{
	tmp1 = lv2_peek(offset);							 		 
	tmp2 = lv2_peek(offset + 8);								 
	tmp3 = lv2_peek(offset + 16);								 
	tmp4 = lv2_peek(offset + 24);								 
	lv2_poke(offset +  0, 0x7C0802A6F8010010ULL);						 
	lv2_poke(offset +  8, 0x3960000044000022ULL | ((uint64_t)(1) << 32)); 
	lv2_poke(offset + 16, 0xE80100107C0803A6ULL);					     
	lv2_poke(offset + 24, 0x4E80002060000000ULL);
}

static void REMOVE_HVSC_REDIRECT(uint64_t offset)
{
	lv2_poke(offset, tmp1);	    
	lv2_poke(offset + 8, tmp2);  
	lv2_poke(offset + 16, tmp3); 
	lv2_poke(offset + 24, tmp4);
}

int lv1_insert_htab_entry(uint64_t htab_id, uint64_t hpte_group, uint64_t hpte_v, uint64_t hpte_r, uint64_t bolted_flag, uint64_t flags, uint64_t * hpte_index, uint64_t * hpte_evicted_v, uint64_t * hpte_evicted_r)
{
	uint64_t ret = 0, ret_hpte_index = 0, ret_hpte_evicted_v =
		0, ret_hpte_evicted_r = 0;
	__asm__ __volatile__("mr %%r3, %4;" "mr %%r4, %5;" "mr %%r5, %6;"
					"mr %%r6, %7;" "mr %%r7, %8;" "mr %%r8, %9;"
					"li %%r10, 0x9e;" "li %%r11, 10;" "sc;" "mr %0, %%r3;" "mr %1, %%r4;"
					"mr %2, %%r5;" "mr %3, %%r6;":"=r"(ret),
					"=r"(ret_hpte_index), "=r"(ret_hpte_evicted_v),
					"=r"(ret_hpte_evicted_r)
					:"r"(htab_id), "r"(hpte_group), "r"(hpte_v),
					"r"(hpte_r), "r"(bolted_flag), "r"(flags)
					:"r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
					"r9", "r10", "r11", "r12", "lr", "ctr", "xer",
					"cr0", "cr1", "cr5", "cr6", "cr7", "memory");

	*hpte_index = ret_hpte_index;
	*hpte_evicted_v = ret_hpte_evicted_v;
	*hpte_evicted_r = ret_hpte_evicted_r;
	return (int)ret;
}

int lv1_write_htab_entry(uint64_t vas_id, uint64_t hpte_index, uint64_t hpte_v, uint64_t hpte_r) 
{
	int result;
	uint64_t tmp1, tmp2, tmp3, tmp4;

	INSTALL_HVSC_REDIRECT(OFFSET_HVSC_REDIRECT);

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
		
	REMOVE_HVSC_REDIRECT(OFFSET_HVSC_REDIRECT);

	return result;
}

int lv1_allocate_memory(uint64_t size, uint64_t page_size_exp, uint64_t flags, uint64_t * addr, uint64_t * muid)
{
	uint64_t ret = 0, ret_addr = 0, ret_muid = 0;
	__asm__ __volatile__(
		"mr %%r3, %3;"
			"mr %%r4, %4;"
			"li %%r5, 0;"
			"mr %%r6, %5;"
			"li %%r10, 0;"
			"li %%r11, 10;"
			"sc;"
			"mr %0, %%r3;"
			"mr %1, %%r4;"
			"mr %2, %%r5;":"=r"(ret), "=r"(ret_addr),
			"=r"(ret_muid)
			:"r"(size), "r"(page_size_exp), "r"(flags)
			:"r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
			"r9", "r10", "r11", "r12", "lr", "ctr", "xer",
			"cr0", "cr1", "cr5", "cr6", "cr7", "memory");

	*addr = ret_addr;
	*muid = ret_muid;
	return (int)ret;
}

int lv1_write_virtual_uart( uint64_t port_number, uint64_t buffer, uint64_t bytes, uint64_t *bytes_written )
{
	uint64_t ret = 0, ret_bytes = 0;

	__asm__ __volatile__(
				"mr %%r3, %2;"
				"mr %%r4, %3;"
				"mr %%r5, %4;"
				"li %%r10, 163;"
				"li %%r11, 10;"
				"sc;"
				"mr %0, %%r3;"
				"mr %1, %%r4;"
					:"=r"(ret), "=r"(ret_bytes)
					:"r"(port_number), "r"(buffer), "r"(bytes)
					:"r0", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory");

	*bytes_written = ret_bytes;
	return (int)ret;
}
