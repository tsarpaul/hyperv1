#include <linux/io.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/gfp.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>
#include <asm/perf_event.h>
#include <asm/vmx.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>

#include "ept.h"

// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT				 0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING						 0x00000004
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI						 0x00000010
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER				 0x00000020 
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS        0x00000040


#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT						0x2
#define CPU_BASED_CTL2_RDTSCP							0x8
#define CPU_BASED_CTL2_ENABLE_VPID						0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST				0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY		0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID					0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC					0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS				0x100000


// VM-exit Control Bits 
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_GUEST_PAT          0x00040000
#define VM_EXIT_LOAD_HOST_PAT           0x00080000




// VM-entry Control Bits 
#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT         0x00004000

int vmx_setup(void);
void vmx_teardown(void);
int vmx_launch(void);


