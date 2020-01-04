#include "vmx.h"

typedef struct vmstate {
	bool vmx_enabled;
	void *vmxon_region;
	u64 vmxon_physical;
	void *vmcs_region;
	u64 vmcs_physical;
	EPTP eptp;
	int vpid;
	void *vmm_handle_stack;
	unsigned int vmm_handle_stack_size;
	unsigned long initial_rsp;
	unsigned long initial_rip;
} vmstate;

static DECLARE_BITMAP(vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vpid_lock);
static DEFINE_PER_CPU(vmstate*, cpu_vms);

static int adjust_msr_control(int msr, int flags){
	// Ex: https://xem.github.io/minix86/manual/intel-x86-and-64-manual-vol3/o_fe12b1e2a880e0ce-1945.html
	int must_one; // bit == 1 -> flags[bit] must equal 1
	int must_zero;    // bit == 0 -> flags[bit-32] must equal 0
	rdmsr_safe(msr, &must_one, &must_zero);
	
	return (must_one | flags) & must_zero;
}

static bool is_ldttss(struct desc_struct *desc){
	/* s = 0 -> system, 1 -> user
	 type = 2 -> LDT , 9 -> available tss, 11 -> busy tss */
	if(desc->s == 0 && (desc->type == 2 || desc->type == 9 || desc->type == 11)){
		return true;
	}
	return false;
}

static int segment_base(int selector){
	struct desc_ptr gdtptr;
	struct desc_struct *desc;
	int gdt_index = selector >> 3;
	unsigned long base;

	native_store_gdt(&gdtptr);
	desc = (struct desc_struct *)gdtptr.address + sizeof(struct desc_struct)*gdt_index;
	base = get_desc_base(desc);

	/* On x64, LDT and TSS segment descriptors occupy 64 extra bits */
	if(is_ldttss(desc))
		base |= ((unsigned long)((struct ldttss_desc *)desc)->base3) << 32;

	return base;
}

static int read_tr_base(void){
	uint16_t tss_selector;
	__asm__ __volatile__("str %[tss_selector]" 
		: [tss_selector]"=rm"(tss_selector) 
		: : "cc", "memory"
	);
	return segment_base(tss_selector);
}

static inline int VMXON(u64 phys){
	// TODO: Signal VMX to PT, to avoid PT crashes (Processor Trace)
	uint8_t ret;
	__asm__ __volatile__ (
		"vmxon %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(phys)
		: "cc", "memory"
	);
	return ret;
}

static inline void VMXOFF(void){
	__asm__ __volatile__("vmxoff" : : : "cc");
}

static inline void VMPTRLD(phys_addr_t phys){
	uint8_t err;
	__asm__ __volatile__(
		"vmptrld %[pa]; setna %[err]"
		: [err]"=rm"(err)
		: [pa]"m"(phys) 
		: "cc", "memory"
	);
	BUG_ON(err);
}

static inline void VMCLEAR(phys_addr_t phys){
	uint8_t err;
	__asm__ __volatile__(
		"vmclear %[pa]; setna %[err]"
		: [err]"=rm"(err) 
		: [pa]"m"(phys) 
		: "cc", "memory"
	);
	BUG_ON(err);
}

static inline void enable_vmx_operation_cr(void){
	// Enable 14th bit in CR4
	__write_cr4(__read_cr4() | 0x2000);
}
  
static inline void disable_vmx_operation_cr(void){
	__write_cr4(__read_cr4() & ~(0x2000));
}

static unsigned long vmcs_read(unsigned long field){
	unsigned long value = 0;
	uint8_t err;
	__asm__ __volatile__(
		"vmread %[field],%[value]; setna %[err]" 
		: [err]"=rm"(err), [value]"=r"(value)
		: [field]"rm"(field)
		: "cc", "memory"
	);
	if(err)
		printk(KERN_INFO "vmread err: reg %lx value %lx\n", field, value);
	return value;
}

static unsigned long long vmcs_read64(unsigned long field){
	// TODO: add 32bit support
	return vmcs_read(field);
}

static unsigned int vmcs_read32(unsigned long field){
	return vmcs_read(field) & 0xffffffff;
}

static noinline void vmwrite_error(unsigned long field, unsigned long value){
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, (int)(vmcs_read(VM_INSTRUCTION_ERROR)));
	dump_stack();
	BUG_ON(1);
}

static void vmcs_write(unsigned long field, unsigned long value){
	uint8_t err;
	__asm__ __volatile__(
		"vmwrite %[value],%[field]; setna %[err]" 
		: [err]"=rm"(err)
		: [field]"r"(field), [value]"r"(value)
		: "cc", "memory"
	);
	if(err)
		vmwrite_error(field, value);
	else
		printk(KERN_INFO "vmwrite log: reg %lx value %lx\n", field, value);
}

static void vmcs_write64(unsigned long field, u64 value){
	// TODO: Add 32bit support
	vmcs_write(field, value);
}

static void vmx_dump_sel(char *name, uint32_t sel)
{
	pr_err("%s sel=0x%04lx, attr=0x%05x, limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read(sel),
	       vmcs_read32(sel + GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR),
	       vmcs_read32(sel + GUEST_ES_LIMIT - GUEST_ES_SELECTOR),
	       vmcs_read(sel + GUEST_ES_BASE - GUEST_ES_SELECTOR));
}

static void vmx_dump_dtsel(char *name, uint32_t limit)
{
	pr_err("%s                           limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read32(limit),
	       vmcs_read(limit + GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
}

void dump_vmcs(void)
{
	u32 vmentry_ctl, vmexit_ctl;
	u32 cpu_based_exec_ctrl, pin_based_exec_ctrl, secondary_exec_control;
	unsigned long cr4, status;
	u64 efer;

	vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	vmexit_ctl = vmcs_read32(VM_EXIT_CONTROLS);
	cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	cr4 = vmcs_read(GUEST_CR4);
	efer = vmcs_read64(GUEST_IA32_EFER);
	secondary_exec_control = 0;
	secondary_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);

	pr_err("*** Guest State ***\n");
	pr_err("CR0: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       vmcs_read(GUEST_CR0), vmcs_read(CR0_READ_SHADOW),
	       vmcs_read(CR0_GUEST_HOST_MASK));
	pr_err("CR4: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       cr4, vmcs_read(CR4_READ_SHADOW), vmcs_read(CR4_GUEST_HOST_MASK));
	pr_err("CR3 = 0x%016lx\n", vmcs_read(GUEST_CR3));
	pr_err("PDPTR0 = 0x%016llx  PDPTR1 = 0x%016llx\n",
		vmcs_read64(GUEST_PDPTR0), vmcs_read64(GUEST_PDPTR1));
	pr_err("PDPTR2 = 0x%016llx  PDPTR3 = 0x%016llx\n",
		vmcs_read64(GUEST_PDPTR2), vmcs_read64(GUEST_PDPTR3));
	pr_err("RSP = 0x%016lx  RIP = 0x%016lx\n",
	       vmcs_read(GUEST_RSP), vmcs_read(GUEST_RIP));
	pr_err("RFLAGS=0x%08lx         DR7 = 0x%016lx\n",
	       vmcs_read(GUEST_RFLAGS), vmcs_read(GUEST_DR7));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       vmcs_read(GUEST_SYSENTER_ESP),
	       vmcs_read32(GUEST_SYSENTER_CS), vmcs_read(GUEST_SYSENTER_EIP));
	vmx_dump_sel("CS:  ", GUEST_CS_SELECTOR);
	vmx_dump_sel("DS:  ", GUEST_DS_SELECTOR);
	vmx_dump_sel("SS:  ", GUEST_SS_SELECTOR);
	vmx_dump_sel("ES:  ", GUEST_ES_SELECTOR);
	vmx_dump_sel("FS:  ", GUEST_FS_SELECTOR);
	vmx_dump_sel("GS:  ", GUEST_GS_SELECTOR);
	vmx_dump_dtsel("GDTR:", GUEST_GDTR_LIMIT);
	vmx_dump_sel("LDTR:", GUEST_LDTR_SELECTOR);
	vmx_dump_dtsel("IDTR:", GUEST_IDTR_LIMIT);
	vmx_dump_sel("TR:  ", GUEST_TR_SELECTOR);
	pr_err("EFER =     0x%016llx  PAT = 0x%016llx\n",
		efer, vmcs_read64(GUEST_IA32_PAT));
	pr_err("DebugCtl = 0x%016llx  DebugExceptions = 0x%016lx\n",
	       vmcs_read64(GUEST_IA32_DEBUGCTL),
	       vmcs_read(GUEST_PENDING_DBG_EXCEPTIONS));
	pr_err("PerfGlobCtl = 0x%016llx\n",
		       vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL));
	pr_err("BndCfgS = 0x%016llx\n", vmcs_read64(GUEST_BNDCFGS));
	pr_err("Interruptibility = %08x  ActivityState = %08x\n",
	       vmcs_read32(GUEST_INTERRUPTIBILITY_INFO),
	       vmcs_read32(GUEST_ACTIVITY_STATE));
	pr_err("InterruptStatus = %04lx\n",
		vmcs_read(GUEST_INTR_STATUS));

	pr_err("*** Host State ***\n");
	pr_err("RIP = 0x%016lx  RSP = 0x%016lx\n",
	       vmcs_read(HOST_RIP), vmcs_read(HOST_RSP));
	pr_err("CS=%04lx SS=%04lx DS=%04lx ES=%04lx FS=%04lx GS=%04lx TR=%04lx\n",
	       vmcs_read(HOST_CS_SELECTOR), vmcs_read(HOST_SS_SELECTOR),
	       vmcs_read(HOST_DS_SELECTOR), vmcs_read(HOST_ES_SELECTOR),
	       vmcs_read(HOST_FS_SELECTOR), vmcs_read(HOST_GS_SELECTOR),
	       vmcs_read(HOST_TR_SELECTOR));
	pr_err("FSBase=%016lx GSBase=%016lx TRBase=%016lx\n",
	       vmcs_read(HOST_FS_BASE), vmcs_read(HOST_GS_BASE),
	       vmcs_read(HOST_TR_BASE));
	pr_err("GDTBase=%016lx IDTBase=%016lx\n",
	       vmcs_read(HOST_GDTR_BASE), vmcs_read(HOST_IDTR_BASE));
	pr_err("CR0=%016lx CR3=%016lx CR4=%016lx\n",
	       vmcs_read(HOST_CR0), vmcs_read(HOST_CR3),
	       vmcs_read(HOST_CR4));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       vmcs_read(HOST_IA32_SYSENTER_ESP),
	       vmcs_read32(HOST_IA32_SYSENTER_CS),
	       vmcs_read(HOST_IA32_SYSENTER_EIP));
	pr_err("EFER = 0x%016llx  PAT = 0x%016llx\n",
		vmcs_read64(HOST_IA32_EFER),
		vmcs_read64(HOST_IA32_PAT));
	pr_err("PerfGlobCtl = 0x%016llx\n",
		vmcs_read64(HOST_IA32_PERF_GLOBAL_CTRL));

	pr_err("*** Control State ***\n");
	pr_err("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
	       pin_based_exec_ctrl, cpu_based_exec_ctrl, secondary_exec_control);
	pr_err("EntryControls=%08x ExitControls=%08x\n", vmentry_ctl, vmexit_ctl);
	pr_err("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
	       vmcs_read32(EXCEPTION_BITMAP),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MASK),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MATCH));
	pr_err("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
	       vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE),
	       vmcs_read32(VM_ENTRY_INSTRUCTION_LEN));
	pr_err("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_EXIT_INTR_INFO),
	       vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
	       vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
	pr_err("        reason=%08x qualification=%016lx\n",
	       vmcs_read32(VM_EXIT_REASON), vmcs_read(EXIT_QUALIFICATION));
	pr_err("GUEST_LINEAR_ADDRESS=%016lx GUEST_PHYSICAL_ADDRESS=%016lx\n", vmcs_read(GUEST_LINEAR_ADDRESS), vmcs_read(GUEST_PHYSICAL_ADDRESS));
	printk("GUEST_PHYS_TO_HOST_LINEAR_ADDR=%016lx", (unsigned long)phys_to_virt(GUEST_PHYSICAL_ADDRESS));
	pr_err("IDTVectoring: info=%08x errcode=%08x\n",
	       vmcs_read32(IDT_VECTORING_INFO_FIELD),
	       vmcs_read32(IDT_VECTORING_ERROR_CODE));
	pr_err("TSC Offset = 0x%016llx\n", vmcs_read64(TSC_OFFSET));
	//pr_err("TSC Multiplier = 0x%016llx\n",
	//	vmcs_read64(TSC_MULTIPLIER));
	status = vmcs_read(GUEST_INTR_STATUS);
	pr_err("SVI|RVI = %02lx|%02lx ", status >> 8, status & 0xff);
	pr_cont("TPR Threshold = 0x%02x\n", vmcs_read32(TPR_THRESHOLD));
	pr_err("APIC-access addr = 0x%016llx ", vmcs_read64(APIC_ACCESS_ADDR));
	pr_cont("virt-APIC addr = 0x%016llx\n", vmcs_read64(VIRTUAL_APIC_PAGE_ADDR));
	pr_err("PostedIntrVec = 0x%02lx\n", vmcs_read(POSTED_INTR_NV));
	pr_err("EPT pointer = 0x%016llx\n", vmcs_read64(EPT_POINTER));
	//n = vmcs_read32(CR3_TARGET_COUNT);
	//for (i = 0; i + 1 < n; i += 4)
	//	pr_err("CR3 target%u=%016lx target%u=%016lx\n",
	//	       i, vmcs_read(CR3_TARGET_VALUE0 + i * 2),
	//	       i + 1, vmcs_read(CR3_TARGET_VALUE0 + i * 2 + 2));
	//if (i < n)
	//	pr_err("CR3 target%u=%016lx\n",
	//	       i, vmcs_read(CR3_TARGET_VALUE0 + i * 2));
	//pr_err("PLE Gap=%08x Window=%08x\n",
	//	vmcs_read32(PLE_GAP), vmcs_read32(PLE_WINDOW));
	pr_err("Virtual processor ID = 0x%04lx\n",
		vmcs_read(VIRTUAL_PROCESSOR_ID));
}

static inline void VMLAUNCH(void){
	uint8_t err;
	__asm__ __volatile__(
		"vmlaunch; setna %[err]"
		: [err]"=rm"(err) 
		: : "cc", "memory"
	);
	dump_vmcs();
	printk(KERN_ERR "VMLAUNCH failure (err %lx)", vmcs_read(VM_INSTRUCTION_ERROR));
	BUG_ON(err);
}

static inline void VMRESUME(void){
	uint8_t err;
	__asm__ __volatile__(
		"vmresume; setna %[err]"
		: [err]"=rm"(err) 
		: : "cc", "memory"
	);
	printk(KERN_ERR "VMRESUME failure (err %lx)", vmcs_read(VM_INSTRUCTION_ERROR));
	dump_stack();
	BUG_ON(err);
}

static int get_free_vpid(void){
	int vpid;
	spin_lock(&vpid_lock);
	vpid = find_first_zero_bit(vpid_bitmap, VMX_NR_VPIDS);
	__set_bit(vpid, vpid_bitmap);
	spin_unlock(&vpid_lock);
	return vpid;
}

static vmstate* create_vmstate(void){
	vmstate *vms = kzalloc(sizeof(vmstate), GFP_KERNEL);
	vms->vmx_enabled = false;
	return vms;
}

static void teardown_vmstate(vmstate *vms){
	if(vms->vmxon_region)
		kfree(vms->vmxon_region);
	if(vms->vmcs_region){
		kfree(vms->vmcs_region);
	}
	kfree(vms);
}

static void vmx_enable(void){
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());
	printk("Enabling VMX!");
	enable_vmx_operation_cr();
	printk("VMXONX!");
	if(VMXON(vms->vmxon_physical)){
		vms->vmx_enabled = false;
		printk("VMXON FAILED!!");
	}
	else
		vms->vmx_enabled = true;
}

static void vmx_disable(void){
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());
	if(vms->vmx_enabled == true) {
		VMXOFF();
		vms->vmx_enabled = false;
	}
	disable_vmx_operation_cr();
}

static void setup_vm_code(vmstate *vms){
	vms->initial_rsp = (unsigned long)kmalloc(4096, GFP_KERNEL | GFP_NOWAIT) + 4095;
}

static void prepare_vmx_cpu(void){
	uint32_t vmcs_revid = 0;
	uint32_t hi = 0;
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());

	// Populate VMCS revision id in vmxon region
	rdmsr_safe(MSR_IA32_VMX_BASIC, &vmcs_revid, &hi);
	memcpy(vms->vmxon_region, &vmcs_revid, 4);
	memcpy(vms->vmcs_region, &vmcs_revid, 4);

	setup_vm_code(vms);
	vms->eptp = alloc_ept(10);

	vmx_enable();	
}

//static void handle_vmexit(void) __attribute__((used));
static void handle_vmexit(void){
	int exit_reason = vmcs_read32(VM_EXIT_REASON);
	int basic_exit_code = exit_reason & 0xffff;
	int exit_qualification = vmcs_read32(EXIT_QUALIFICATION);
	int vm_entry_failure = exit_reason & 0x80000000;
	dump_vmcs();
	panic("VMEXIT WITH CODE %d, VM ENTRY FAILURE: %s, QUAL: %d", basic_exit_code, vm_entry_failure ? "true" : "false", exit_qualification);
	VMRESUME();
	//TODO: switch error reasons
}

static void vmx_setup_vm_controls(void){
	// VM Execution Controls
	vmcs_write(PIN_BASED_VM_EXEC_CONTROL, adjust_msr_control(MSR_IA32_VMX_PINBASED_CTLS, 0));
	vmcs_write(CPU_BASED_VM_EXEC_CONTROL, adjust_msr_control(
		MSR_IA32_VMX_PROCBASED_CTLS, CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));
	vmcs_write(SECONDARY_VM_EXEC_CONTROL, adjust_msr_control(
		MSR_IA32_VMX_PROCBASED_CTLS2, CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID/* | CPU_BASED_CTL2_ENABLE_VPID */ | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | CPU_BASED_CTL2_ENABLE_EPT
	));

	//vmcs_write64(TSC_OFFSET, 0);	

	vmcs_write(CR0_READ_SHADOW, read_cr0());
	vmcs_write(CR4_READ_SHADOW, __read_cr4());
	vmcs_write(CR0_GUEST_HOST_MASK, ~0ul);
	vmcs_write(CR4_GUEST_HOST_MASK, ~0ul);

	// How many CR3_TARGET_VALUEs are considered without VM exit when MOV CR3, VAL
	vmcs_write(CR3_TARGET_COUNT, 0);

	// VM Entry & Exit Controls
	vmcs_write(VM_EXIT_CONTROLS, adjust_msr_control(MSR_IA32_VMX_EXIT_CTLS, VM_EXIT_IA32E_MODE | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_HOST_ADDR_SPACE_SIZE));
	vmcs_write(VM_ENTRY_CONTROLS, adjust_msr_control(MSR_IA32_VMX_ENTRY_CTLS, VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER));
}

static void vmx_setup_initial_host_state(vmstate *vms){
	struct desc_ptr gdtptr, idt;

	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, __read_cr3());
	vmcs_write(HOST_CR4, __read_cr4());
	vmcs_write(HOST_RSP, (unsigned long)vms->vmm_handle_stack + vms->vmm_handle_stack_size - 1);
	vmcs_write(HOST_RIP, (unsigned long)handle_vmexit);
	
	/* An explanation of segment selectors: https://medium.com/hungys-blog/linux-kernel-memory-addressing-a0d304283af3 */
	// Segment Selectors
	vmcs_write(HOST_CS_SELECTOR, __KERNEL_CS);
	vmcs_write(HOST_DS_SELECTOR, __KERNEL_DS);
	vmcs_write(HOST_ES_SELECTOR, __KERNEL_DS);
	vmcs_write(HOST_SS_SELECTOR, __KERNEL_DS);
	vmcs_write(HOST_FS_SELECTOR, 0);
	vmcs_write(HOST_GS_SELECTOR, 0);
	vmcs_write(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);

	// Segment Base Adresses
	vmcs_write(HOST_FS_BASE, native_read_msr(MSR_FS_BASE));
	vmcs_write(HOST_GS_BASE, native_read_msr(MSR_GS_BASE));
	vmcs_write(HOST_TR_BASE, read_tr_base());
	native_store_gdt(&gdtptr);
	vmcs_write(HOST_GDTR_BASE, gdtptr.address);
	store_idt(&idt);
	vmcs_write(HOST_IDTR_BASE, idt.address);

	// MSRs
	vmcs_write(HOST_IA32_SYSENTER_CS, native_read_msr(MSR_IA32_SYSENTER_CS));
	vmcs_write(HOST_IA32_SYSENTER_ESP, native_read_msr(MSR_IA32_SYSENTER_ESP));
	vmcs_write(HOST_IA32_SYSENTER_EIP, native_read_msr(MSR_IA32_SYSENTER_EIP));
	vmcs_write64(HOST_IA32_EFER, native_read_msr(MSR_EFER));
}

static void RIPTEST(void) __attribute__((used));
static void RIPTEST(void){
	__asm__ __volatile__("hlt; hlt; hlt; hlt; hlt; hlt");
}

static void vmx_setup_initial_guest_state(vmstate *vms){
	vmcs_write(GUEST_CR0, read_cr0());
	vmcs_write(GUEST_CR3, __read_cr3());
	vmcs_write(GUEST_CR4, __read_cr4());
	vmcs_write(GUEST_DR7, 0);

	//vmcs_write(GUEST_RIP, vms->initial_rip);
	vmcs_write(GUEST_RIP, (unsigned long)RIPTEST);
	printk(KERN_INFO "RIPTEST PHYSICAL ADDRESS: %lx", (unsigned long)virt_to_phys(RIPTEST));
	vmcs_write(GUEST_RSP, vms->initial_rsp);
	vmcs_write(GUEST_RFLAGS, 0x2); // Reserved flag

	// Setup selectors
	vmcs_write(GUEST_CS_SELECTOR, 0);
	vmcs_write(GUEST_SS_SELECTOR, 0);
	vmcs_write(GUEST_DS_SELECTOR, 0);
	vmcs_write(GUEST_ES_SELECTOR, 0);
	vmcs_write(GUEST_FS_SELECTOR, 0);
	vmcs_write(GUEST_GS_SELECTOR, 0);
	vmcs_write(GUEST_LDTR_SELECTOR, 0);
	vmcs_write(GUEST_TR_SELECTOR, 0);

	// Setup base addresses
	vmcs_write(GUEST_CS_BASE, 0);
	vmcs_write(GUEST_SS_BASE, 0);
	vmcs_write(GUEST_DS_BASE, 0);
	vmcs_write(GUEST_ES_BASE, 0);
	vmcs_write(GUEST_FS_BASE, native_read_msr(MSR_FS_BASE));
	vmcs_write(GUEST_GS_BASE, native_read_msr(MSR_GS_BASE));
	vmcs_write(GUEST_LDTR_BASE, 0);
	vmcs_write(GUEST_TR_BASE, 0);

	// Setup guest segment limits	
	vmcs_write(GUEST_CS_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_SS_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_DS_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_ES_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_FS_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_GS_LIMIT, 0xFFFFFFFF);
	vmcs_write(GUEST_LDTR_LIMIT, 0);
	vmcs_write(GUEST_TR_LIMIT, 0xFF);

	// Setup guest segment access rights
	// https://www.amd.com/system/files/TechDocs/24593.pdf#G10.910849
	vmcs_write(GUEST_CS_AR_BYTES, 0xA09B);
	vmcs_write(GUEST_SS_AR_BYTES, 0xA093);
	vmcs_write(GUEST_DS_AR_BYTES, 0xA093);
	vmcs_write(GUEST_ES_AR_BYTES, 0xA093);
	vmcs_write(GUEST_FS_AR_BYTES, 0xA093);
	vmcs_write(GUEST_GS_AR_BYTES, 0xA093);
	vmcs_write(GUEST_LDTR_AR_BYTES, 0x0082);
	vmcs_write(GUEST_TR_AR_BYTES, 0x008B);

	// Setup GDTR & IDTR
	vmcs_write(GUEST_GDTR_BASE, 0);
	vmcs_write(GUEST_IDTR_BASE, 0);
	vmcs_write(GUEST_GDTR_LIMIT, 0);
	vmcs_write(GUEST_IDTR_LIMIT, 0);

	vmcs_write(GUEST_IA32_EFER, native_read_msr(MSR_EFER));
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	// Setup sysenter primitives
	vmcs_write(GUEST_SYSENTER_CS, 0);
	vmcs_write(GUEST_SYSENTER_ESP, 0);
	vmcs_write(GUEST_SYSENTER_EIP, 0);
}

static void init_vmcs(vmstate *vms){
	VMPTRLD(vms->vmcs_physical);
	vmx_setup_vm_controls();
	vmx_setup_initial_guest_state(vms);
	vmx_setup_initial_host_state(vms);

	vmcs_write64(VMCS_LINK_POINTER, -1ull);
	
	//vmcs_write(EXCEPTION_BITMAP, 8192);

	vmcs_write64(EPT_POINTER, vms->eptp.value);
	//vmcs_write(VIRTUAL_PROCESSOR_ID, vms->vpid);
}

int vmx_launch(void){
	int cpu = smp_processor_id();
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());

	printk(KERN_INFO "Launching VM on CPU %d\n", cpu);
	init_vmcs(vms);
	VMLAUNCH();

	put_cpu();
	return 0;
}

int vmx_setup(void){
	int i = smp_processor_id();
	vmstate* vms;
	printk(KERN_INFO "NUM CPUS: %d\n", num_online_cpus());

	vms = create_vmstate();
	vms->vmxon_region = kzalloc(4096, GFP_KERNEL);
	vms->vmxon_physical = virt_to_phys(vms->vmxon_region);
	vms->vmcs_region = kzalloc(4096, GFP_KERNEL);
	vms->vmcs_physical = virt_to_phys(vms->vmcs_region);
	vms->vmm_handle_stack_size = 4096;
	vms->vmm_handle_stack = kmalloc(vms->vmm_handle_stack_size, GFP_KERNEL);
	//vms->vpid = get_free_vpid();
	per_cpu(cpu_vms, i) = vms;
	
	printk(KERN_INFO "Preparing CPUs!");
	prepare_vmx_cpu();
	printk(KERN_INFO "CPUs prepared!");

	if(vms->vmx_enabled == false) {
		printk(KERN_ALERT "Tearing down after VMXON failed!");
		vmx_teardown();
		return -1;
	}
	printk(KERN_INFO "VMX turned on!");
	return 0;
}

void vmx_teardown(void){
	int i = smp_processor_id();
	vmstate* vms;
	vmx_disable();
	vms = per_cpu_ptr(cpu_vms, i);
	teardown_vmstate(vms);
}

