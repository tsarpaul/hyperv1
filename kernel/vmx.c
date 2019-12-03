#include "vmx.h"

typedef struct vmstate {
	bool vmx_enabled;
	void *vmxon_region;
	phys_addr_t vmxon_physical;
	void *vmcs_region;
	phys_addr_t vmcs_physical;
	EPTP eptp;
	int vpid;
	void *vmm_handle_stack;
	unsigned int vmm_handle_stack_size;
	unsigned long initial_rsp;
	unsigned long initial_rip;
} vmstate;

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

static inline int VMXON(phys_addr_t phys){
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

static void enable_vmx_operation_cr(void){
	// Enable 14th bit in CR4
	__write_cr4(__read_cr4() | 0x2000);
}
  
static void disable_vmx_operation_cr(void){
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
	BUG_ON(err);
	return value;
}

static unsigned long vmcs_read64(unsigned long field){
	// TODO: add 32bit support
	return vmcs_read(field);
}

static inline void VMLAUNCH(void){
	uint8_t err;
	__asm__ __volatile__(
		"vmlaunch; setna %[err]"
		: [err]"=rm"(err) 
		: : "cc", "memory"
	);
	printk(KERN_ERR "VMLAUNCH failure (err %lx)", vmcs_read(VM_INSTRUCTION_ERROR));
	dump_stack();
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

static vmstate *create_vmstate(void){
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
	enable_vmx_operation_cr();
	if(VMXON(vms->vmxon_physical)){
		vms->vmx_enabled = false;
		printk("VMXON FAILED!!");
	}
	else
		vms->vmx_enabled = true;
}

static void vmx_disable(void *info){
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());
	if(vms->vmx_enabled == true) {
		VMXOFF();
		vms->vmx_enabled = false;
	}
	disable_vmx_operation_cr();
}

static void setup_vm_code(vmstate *vms){
	int i;
        EPT_PML4E *pml = phys_to_virt(vms->eptp.fields.pml4_phys_addr);
        EPT_PDPTE *pdpt = phys_to_virt(pml->fields.phys_addr);
        EPT_PDE *pd = phys_to_virt(pdpt->fields.phys_addr);
        EPT_PTE *pt = phys_to_virt(pd->fields.phys_addr);

	vms->initial_rip = (unsigned long)phys_to_virt(pt[0].fields.phys_addr);
	for(i = 0; i < 4096; i++){	
		// hlt
		*(char*)(vms->initial_rip+i) = 0xf4;
	}
	// Stack grows down
	vms->initial_rsp = (unsigned long)phys_to_virt(pt[10].fields.phys_addr) + 4095;
}

static void prepare_vmx_cpu(void *info){
	uint32_t vmcs_revid = 0;
	uint32_t hi = 0;
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());

	// Populate VMCS revision id in vmxon region
	rdmsr_safe(MSR_IA32_VMX_BASIC, &vmcs_revid, &hi);
	memcpy(vms->vmxon_region, &vmcs_revid, 4);
	memcpy(vms->vmcs_region, &vmcs_revid, 4);

	vms->eptp = alloc_ept(10);
	setup_vm_code(vms);

	vmx_enable();	
}

//static void handle_vmexit(void) __attribute__((used));
static void handle_vmexit(void){
	int exit_code = vmcs_read(VM_EXIT_REASON);
	printk(KERN_INFO "VMEXIT WITH CODE %d!", exit_code);
	VMRESUME();
	//TODO: Panic
}

//__asm__(".handle_vmexit: \n\t"
//	"call handle_vmexit"
//);

static void vmx_setup_vm_controls(void){
	// VM Execution Controls
	vmcs_write(PIN_BASED_VM_EXEC_CONTROL, adjust_msr_control(MSR_IA32_VMX_PINBASED_CTLS, 0));
	vmcs_write(CPU_BASED_VM_EXEC_CONTROL, adjust_msr_control(
		MSR_IA32_VMX_PROCBASED_CTLS, CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));
	vmcs_write(SECONDARY_VM_EXEC_CONTROL, adjust_msr_control(
		MSR_IA32_VMX_PROCBASED_CTLS2, CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS | CPU_BASED_CTL2_ENABLE_VPID | CPU_BASED_CTL2_ENABLE_EPT */
	));

	//vmcs_write64(TSC_OFFSET, 0);	

	//vmcs_write(CR0_READ_SHADOW, read_cr0());
	//vmcs_write(CR4_READ_SHADOW, __read_cr4());
	//vmcs_write(CR0_GUEST_HOST_MASK, ~0ul);
	//vmcs_write(CR4_GUEST_HOST_MASK, ~0ul);

	// How many CR3_TARGET_VALUEs are considered without VM exit when MOV CR3, VAL
	vmcs_write(CR3_TARGET_COUNT, 0);

	// VM Entry & Exit Controls
	vmcs_write(VM_EXIT_CONTROLS, adjust_msr_control(MSR_IA32_VMX_EXIT_CTLS, VM_EXIT_IA32E_MODE));
	vmcs_write(VM_ENTRY_CONTROLS, adjust_msr_control(MSR_IA32_VMX_ENTRY_CTLS, VM_ENTRY_IA32E_MODE));
}

static void vmx_setup_initial_host_state(vmstate *vms){
	struct desc_ptr gdtptr, idt;
	//unsigned long tmp;

	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, __read_cr3());
	vmcs_write(HOST_CR4, __read_cr4());
	vmcs_write(HOST_RSP, (unsigned long)vms->vmm_handle_stack + vms->vmm_handle_stack_size - 1);
	//asm("mov $.handle_vmexit, %0" : "=r"(tmp));
	//vmcs_write(HOST_RIP, (unsigned long)tmp);
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

static void vmx_setup_initial_guest_state(vmstate *vms){
	vmcs_write(GUEST_CR0, read_cr0());
	vmcs_write(GUEST_CR3, __read_cr3());
	vmcs_write(GUEST_CR4, __read_cr4());
	vmcs_write(GUEST_DR7, 0);

	vmcs_write(GUEST_RIP, vms->initial_rip);
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

	// Setup sysenter primitives
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	vmcs_write(GUEST_SYSENTER_CS, 0);
	vmcs_write(GUEST_SYSENTER_ESP, 0);
	vmcs_write(GUEST_SYSENTER_EIP, 0);
}

static void init_vmcs(vmstate *vms){
	VMPTRLD(vms->vmcs_physical);
	vmx_setup_vm_controls();
	vmx_setup_initial_guest_state(vms);
	vmx_setup_initial_host_state(vms);

	/*
	vmcs_write(EPT_POINTER, vms->eptp.value);
	vmcs_write(VIRTUAL_PROCESSOR_ID, vms->vpid);
	*/
}

int vmx_launch(void){
	int cpu = smp_processor_id();
	vmstate *vms = per_cpu(cpu_vms, smp_processor_id());

	printk(KERN_INFO "Launching VM on CPU %d", cpu);
	init_vmcs(vms);
	VMLAUNCH();

	put_cpu();
	return 0;
}

int vmx_setup(void){
	int i;
	vmstate* vms;
	printk(KERN_INFO "NUM CPUS: %d", num_possible_cpus());

	for_each_possible_cpu(i){
		vms = create_vmstate();
		vms->vmxon_region = kmalloc(4096, GFP_KERNEL);
		vms->vmxon_physical = virt_to_phys(vms->vmxon_region);
		vms->vmcs_region = kzalloc(4096, GFP_KERNEL);
		vms->vmcs_physical = virt_to_phys(vms->vmcs_region);
		per_cpu(cpu_vms, i) = vms;
	}
	
	on_each_cpu(prepare_vmx_cpu, NULL, 1);
	printk(KERN_INFO "CPUS prepared!");

	for_each_possible_cpu(i){
		vms = per_cpu(cpu_vms, i);
		if(vms->vmx_enabled == false) {
			printk(KERN_ALERT "Tearing down after VMXON failed!");
			vmx_teardown();
			return -1;
		}
	}
	printk(KERN_INFO "VMX turned on for all CPUs!");
	return 0;
}

void vmx_teardown(void){
	int i;
	vmstate* vms;
	on_each_cpu(vmx_disable, NULL, 1);
	for_each_possible_cpu(i){
		vms = per_cpu(cpu_vms, i);
		teardown_vmstate(vms);
	}
}

