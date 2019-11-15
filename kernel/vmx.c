#include "vmx.h"

typedef struct vmstate {
	bool vmx_enabled;
	void *vmxon_region;
	phys_addr_t vmxon_physical;
	void *vmcs_region;
	phys_addr_t vmcs_physical;
} vmstate;

static DEFINE_PER_CPU(vmstate*, cpu_vms);

static inline int VMXON(phys_addr_t phys){
	uint8_t ret;
	// TODO: Signal VMX to PT, to avoid PT crashes (Processor Trace)
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

static void enable_vmx_operation_cr(void){
	// Enable 14th bit in CR4
	__write_cr4(__read_cr4() | 0x2000);
}
  
static void disable_vmx_operation_cr(void){
	__write_cr4(__read_cr4() & ~(0x2000));
}

static vmstate *create_vmstate(void){
	vmstate *vms = kzalloc(sizeof(vmstate), GFP_KERNEL);
	vms->vmx_enabled = false;
	return vms;
}

static void teardown_vmstate(vmstate *vms){
	if(vms->vmxon_region)
		kfree(vms->vmxon_region);
	kfree(vms);
}

static void vmx_disable(void *info){
	vmstate *vms = get_cpu_var(cpu_vms);
	if(vms->vmx_enabled == true) {
		VMXOFF();
		vms->vmx_enabled = false;
	}
	disable_vmx_operation_cr();
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

static void vmx_enable(void *info){
	uint32_t vmcs_revid = 0;
	uint32_t hi = 0;
	vmstate *vms = get_cpu_var(cpu_vms);

	// Populate VMCS revision id in vmxon region
	rdmsr_safe(MSR_IA32_VMX_BASIC, &vmcs_revid, &hi);
	memcpy(vms->vmxon_region, &vmcs_revid, 4);

	enable_vmx_operation_cr();
	if(VMXON(vms->vmxon_physical))
		vms->vmx_enabled = false;
	else
		vms->vmx_enabled = true;
}

int vmx_setup(void){
	int i;
	vmstate* vms;
	printk(KERN_INFO "NUM CPUS: %d", num_possible_cpus());

	for_each_possible_cpu(i){
		vms = create_vmstate();
		vms->vmxon_region = kmalloc(4096, GFP_KERNEL);
		vms->vmxon_physical = virt_to_phys(vms->vmxon_region);
		per_cpu(cpu_vms, i) = vms;
	}
	
	on_each_cpu(vmx_enable, NULL, 1);

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

