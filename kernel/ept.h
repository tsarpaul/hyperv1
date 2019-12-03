#include <linux/types.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/io.h>

typedef union EPTP {
	u64 value;
	struct {
		u64 memtype : 3;
		u64 page_walk : 3;
		u64 accessed_and_dirty_flags_enabled : 1;
		u64 shadow_stack_access_rights_enforced : 1;
		u64 reserved1 : 4;
		u64 pml4_phys_addr : 36;
		u64 reserved2 : 16;
	} fields;
} EPTP;

typedef union EPT_PML4E {
	u64 value;
	struct {
		u64 read_access: 1;
		u64 write_access: 1;
		u64 execute_access: 1;
		u64 reserved1 : 5;
		u64 accessed_flag : 1;
		u64 ignored1 : 1;
		u64 user_execute_access : 1;
		u64 ignored2 : 1;
		u64 phys_addr : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} EPT_PML4E;

typedef union EPT_PDPTE {
	u64 value;
	struct {
		u64 read_access;
		u64 write_access: 1;
		u64 execute_access: 1;
		u64 reserved1 : 4;
		u64 page_mapped_flag : 1;
		u64 accessed_flag : 1;
		u64 ignored1 : 1;
		u64 user_execute_access : 1;
		u64 ignored2 : 1;
		u64 phys_addr : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} EPT_PDPTE;

typedef union EPT_PDE {
	u64 value;
	struct {
		u64 read_access;
		u64 write_access: 1;
		u64 execute_access: 1;
		u64 reserved1 : 4;
		u64 page_mapped_flag : 1;
		u64 accessed_flag : 1;
		u64 ignored1 : 1;
		u64 user_execute_access : 1;
		u64 ignored2 : 1;
		u64 phys_addr : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} EPT_PDE;

typedef union EPT_PTE {
	u64 value;
	struct {
		u64 read_access: 1;
		u64 write_access: 1;
		u64 execute_access: 1;
		u64 ept_memtype : 3;
		u64 ignore_pat_memtype : 1;
		u64 ignored1 : 1;
		u64 accessed_flag : 1;
		u64 dirty_flag : 1;
		u64 user_execute_access : 1;
		u64 ignored2 : 1;
		u64 phys_addr : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 11;
		u64 supress_ve : 1;
	} fields;
} EPT_PTE;

EPTP alloc_ept(int initial_pages_count);
