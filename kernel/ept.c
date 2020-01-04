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
	int i, j, k, l;
	EPTP eptp;
	EPT_PML4E *ept_pml4;
	EPT_PDPTE *ept_pdpt;
	EPT_PDE *ept_pd;
	EPT_PTE *ept_pt;	
	unsigned long cr3;
	struct _PML4E *pml4;
	struct _PDPTE *pdpt;
	struct _PDE *pd;
	struct _PTE *pt;

	eptp.value = 0;
	// Read CR0.bit30(CD) to determine cache disable and check if memtype=6 is supported:
	eptp.fields.memtype = 0;
	eptp.fields.page_walk = 3;
	// TODO: Read IA32_VMX_EPT_VPID_CAP - bit 21 if this is supported:
	eptp.fields.accessed_and_dirty_flags_enabled = 0;

	cr3 = read_cr3_pa();
	pml4 = (struct _PML4E*)phys_to_virt(cr3);
	ept_pml4 = kzalloc(4096, GFP_KERNEL);
	eptp.fields.pml4_phys_addr = virt_to_phys(ept_pml4) >> 12;
	for(i = 0; i < 512; i++){
		if(!pml4[i].Present || pml4[i].Reserved)
			continue;
		printk(KERN_INFO "PML4 index %d present!\n", i);
		ept_pml4[i].fields.read_access = 1;
		ept_pml4[i].fields.write_access = 1;
		ept_pml4[i].fields.execute_access = 1;

		pdpt = (struct _PDPTE*)phys_to_virt(pml4[i].PageFrameNumber << 12);
		ept_pdpt = kzalloc(4096, GFP_KERNEL);
		ept_pml4[i].fields.phys_addr = virt_to_phys(ept_pdpt) >> 12;
		for(j = 0; j < 512; j++){
			if(!pdpt[j].Present || pdpt[j].Reserved)
				continue;
			printk(KERN_INFO "PDPT index %d present!\n", j);
	
			ept_pdpt[j].fields.read_access = 1;
			ept_pdpt[j].fields.write_access = 1;
			ept_pdpt[j].fields.execute_access = 1;
			if(pdpt[j].PageSize){
				//printk(KERN_INFO "PDPT PageSize=1, PageFrameNumber: %lx\n", (unsigned long)pdpt[j].PageFrameNumber);
				ept_pdpt[j].fields.phys_addr = pdpt[j].PageFrameNumber;
				ept_pdpt[j].fields.page_mapped_flag = 1;
			} else {
				pd = (struct _PDE*)phys_to_virt(pdpt[j].PageFrameNumber << 12);
				ept_pd = kzalloc(4096, GFP_KERNEL);
				ept_pdpt[j].fields.phys_addr = virt_to_phys(ept_pd) >> 12;
				for(k = 0; k < 512; k++){
					if(!pd[k].Present || pd[k].Reserved)
						continue;
	
					ept_pd[k].fields.read_access = 1;
					ept_pd[k].fields.write_access = 1;
					ept_pd[k].fields.execute_access = 1;
					if(pd[k].PageSize){
						ept_pd[k].fields.phys_addr = pd[k].PageFrameNumber;
						ept_pd[k].fields.page_mapped_flag = 1;
						//printk(KERN_INFO "PD PageIndex %x, PageFrameNumber: %lx\n", k*j*512,(unsigned long)pd[k].PageFrameNumber);
					} else {
						pt = (struct _PTE*)phys_to_virt(pd[k].PageFrameNumber << 12);
						ept_pt = kzalloc(4096, GFP_KERNEL);
						ept_pd[k].fields.phys_addr = virt_to_phys(ept_pt) >> 12;
						for(l = 0; l < 512; l++){
							if(!pt[l].Present || pt[l].Reserved)
								continue;

							ept_pt[l].fields.read_access = 1;
							ept_pt[l].fields.write_access = 1;
							ept_pt[l].fields.execute_access = 1;
							ept_pt[l].fields.phys_addr = pt[l].PageFrameNumber;
							//printk(KERN_INFO "PT PageIndex %x, PageFrameNumber: %lx\n", k*j*512+l,(unsigned long)pt[l].PageFrameNumber);
						}
					}
				}
			}
		}
	}

	printk(KERN_INFO "EPT construction done!");
	return eptp;
}

