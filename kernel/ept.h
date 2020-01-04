#include <linux/types.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/io.h>

typedef struct _PML4E
{
    union
    {
        struct
        {
            u64 Present : 1;              // Must be 1, region invalid if 0.
            u64 ReadWrite : 1;            // If 0, writes not allowed.
            u64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            u64 PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
            u64 PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
            u64 Accessed : 1;             // If 0, this entry has not been used for translation.
            u64 Ignored1 : 1;
            u64 PageSize : 1;             // Must be 0 for PML4E.
            u64 Ignored2 : 4;
            u64 PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
            u64 Reserved : 4;
            u64 Ignored3 : 11;
            u64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        u64 Value;
    };
} PML4E;

typedef struct _PDPTE
{
    union
    {
        struct
        {
            u64 Present : 1;              // Must be 1, region invalid if 0.
            u64 ReadWrite : 1;            // If 0, writes not allowed.
            u64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            u64 PageWriteThrough : 1;     // Determines the memory type used to access PD.
            u64 PageCacheDisable : 1;     // Determines the memory type used to access PD.
            u64 Accessed : 1;             // If 0, this entry has not been used for translation.
            u64 Ignored1 : 1;
            u64 PageSize : 1;             // If 1, this entry maps a 1GB page.
            u64 Ignored2 : 4;
            u64 PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
            u64 Reserved : 4;
            u64 Ignored3 : 11;
            u64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        u64 Value;
    };
} PDPTE;

typedef struct _PDE
{
    union
    {
        struct
        {
            u64 Present : 1;              // Must be 1, region invalid if 0.
            u64 ReadWrite : 1;            // If 0, writes not allowed.
            u64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            u64 PageWriteThrough : 1;     // Determines the memory type used to access PT.
            u64 PageCacheDisable : 1;     // Determines the memory type used to access PT.
            u64 Accessed : 1;             // If 0, this entry has not been used for translation.
            u64 Ignored1 : 1;
            u64 PageSize : 1;             // If 1, this entry maps a 2MB page.
            u64 Ignored2 : 4;
            u64 PageFrameNumber : 36;     // The page frame number of the PT of this PDE.
            u64 Reserved : 4;
            u64 Ignored3 : 11;
            u64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        u64 Value;
    };
} PDE;


typedef struct _PTE
{
    union
    {
        struct
        {
            u64 Present : 1;              // Must be 1, region invalid if 0.
            u64 ReadWrite : 1;            // If 0, writes not allowed.
            u64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
            u64 PageWriteThrough : 1;     // Determines the memory type used to access the memory.
            u64 PageCacheDisable : 1;     // Determines the memory type used to access the memory.
            u64 Accessed : 1;             // If 0, this entry has not been used for translation.
            u64 Dirty : 1;                // If 0, the memory backing this page has not been written to.
            u64 PageAccessType : 1;       // Determines the memory type used to access the memory.
            u64 Global: 1;                // If 1 and the PGE bit of CR4 is set, translations are global.
            u64 Ignored2 : 3;
            u64 PageFrameNumber : 36;     // The page frame number of the backing physical page.
            u64 Reserved : 4;
            u64 Ignored3 : 7;
            u64 ProtectionKey: 4;         // If the PKE bit of CR4 is set, determines the protection key.
            u64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
        };
        u64 Value;
    };
} PTE;

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
		u64 read_access: 1;
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
		u64 read_access: 1;
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
