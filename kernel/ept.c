#include "ept.h"

static inline void INVEPT(int type, u64 eptp){
	struct INVEPT_DESC {
		u64 eptp, reserved;
	} desc = {eptp, 0};
	int err;

	__asm__ __volatile__(
		"invept %[desc], %[type]; setna %[err];"
		: [err]"=rm"(err)
		: [desc]"m"(desc), [type]"r"(type)
		: "cc", "memory"
	);
	BUG_ON(err);
}

static void inline INVEPT_SINGLE_CTX(EPTP eptp){
	// SINGLE_CTX_TYPE = 1
	INVEPT(1, eptp.value);
}

static void inline INVEPT_ALL_CTX(void){
	// SINGLE_CTX_TYPE = 2
	INVEPT(2, 0);
}

EPTP alloc_ept(int initial_pages_count){
	int i;
	EPTP eptp;
	EPT_PML4E *ept_pml4;
	EPT_PDPTE *ept_pdpt;
	EPT_PDE *ept_pd;
	EPT_PTE *ept_pt;
	eptp.value = 0;

	ept_pml4 = kzalloc(4096, GFP_KERNEL | GFP_NOWAIT);
	if(!ept_pml4)
		goto pml4err;
	ept_pdpt = kzalloc(4096, GFP_KERNEL | GFP_NOWAIT);
	if(!ept_pdpt)
		goto pdpterr;
	ept_pd = kzalloc(4096, GFP_KERNEL | GFP_NOWAIT);
	if(!ept_pd)
		goto pderr;
	ept_pt = kzalloc(4096, GFP_KERNEL | GFP_NOWAIT);
	if(!ept_pt)
		goto pterr;	
	
	for(i = 0; i < initial_pages_count; i++){
		ept_pt[i].fields.read_access = 1;
		ept_pt[i].fields.write_access = 1;
		ept_pt[i].fields.execute_access = 1;
		ept_pt[i].fields.ept_memtype = 6;
		ept_pt[i].fields.phys_addr = virt_to_phys(kzalloc(4096, GFP_KERNEL | GFP_NOWAIT));
	}

	ept_pd->fields.read_access = 1;
	ept_pd->fields.write_access = 1;
	ept_pd->fields.execute_access = 1;
	ept_pd->fields.phys_addr = virt_to_phys(ept_pt);	

	ept_pdpt->fields.read_access = 1;
	ept_pdpt->fields.write_access = 1;
	ept_pdpt->fields.execute_access = 1;
	ept_pdpt->fields.phys_addr = virt_to_phys(ept_pd);

	ept_pml4->fields.read_access = 1;
	ept_pml4->fields.write_access = 1;
	ept_pml4->fields.execute_access = 1;
	ept_pml4->fields.phys_addr = virt_to_phys(ept_pdpt);

	eptp.fields.memtype = 6;
	eptp.fields.page_walk = 3;
	eptp.fields.accessed_and_dirty_flags_enabled = 1;
	eptp.fields.pml4_phys_addr = virt_to_phys(ept_pml4);

	return eptp;
	
	pterr:
	kfree(ept_pd);
	pderr:
	kfree(ept_pdpt);
	pdpterr:
	kfree(ept_pml4);
	pml4err:
	return eptp;
}

