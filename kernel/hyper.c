#include "hyper.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hyper1 kernel module");

static dev_t devt = 0; // Our only device number
static struct cdev *cdev;
static struct class *cls;
static struct device *dev;
bool cdev_added = false;

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = hyper_dev_open,
	.release = hyper_dev_release,
	.read = NULL,
	.write = NULL
};

static void device_cleanup(void){
	if(dev != NULL)
		device_destroy(cls, devt);
	if(cls != NULL)
		class_destroy(cls);
	if(cdev_added)
		cdev_del(cdev);
	if(devt != 0)
		unregister_chrdev_region(devt, DEVICE_COUNT); 
}

static int check_vmx_support(void){
	int ecx = cpuid_ecx(1);
	int lo = 0;
	int hi = 0;
	if ((ecx&(1<<5)) == 0) {
		printk(KERN_ALERT "CPU does not support VMX operations");
		return -1;
	}
	rdmsr_safe(MSR_IA32_FEATURE_CONTROL, &lo, &hi);
	if((lo & 0b100) == 0) {
		printk(KERN_ALERT "Please turn on virtualization support in BIOS");
		return -1;
	}
	return 0;
}

static int setup_chrdev(void){
	int err;
	// Obtain available device number (devt)
	if((err = alloc_chrdev_region(&devt, 0 , DEVICE_COUNT, DEVICE_NAME))){
		printk(KERN_ALERT "alloc_chrdev_region() failed");
		return err;
	}

	// Create chrdev and register with the system
        if((cdev = cdev_alloc()) == NULL){
                printk(KERN_ALERT "cdev_alloc() failed");
                return -1;
        } 
        cdev->ops = &fops;
        if(cdev_add(cdev, devt, 1) == -1){
                printk(KERN_ALERT "cdev_add() failed");
                return -1;
        }
        cdev_added = true;	
	
	// Register chrdev with sysfs for udevd to create our device file
	if((cls = class_create(THIS_MODULE, DEVICE_NAME)) == NULL){
		printk(KERN_ALERT "class_create() failed");
		return -1;	
	} 
	if((dev = device_create(cls, NULL, devt, NULL, DEVICE_NAME)) == NULL){
		printk(KERN_ALERT "device_create() failed");
		return -1;
	}

	return 0;
}

static int __init hyper_init(void) {
	int err;

	printk(KERN_INFO "Hyper1 Init!\n");
	if(check_vmx_support()){
		device_cleanup();
		return -1;
	}
	if((err = setup_chrdev())){
		device_cleanup();
		return err;
	}
	if((err = vmx_setup())){
		device_cleanup();
		return err;
	}
	
	printk(KERN_INFO "Assigned major number %d\n", MAJOR(devt));
	return 0;
}

static void __exit hyper_exit(void) {
	vmx_teardown();
	device_cleanup();
	printk(KERN_INFO "Hyper1 Exit!\n");
} 

static int hyper_dev_open(struct inode* inode, struct file *filep){
	printk(KERN_INFO "Hyper device opened!\n");
	vmx_launch();
	return 0;
}

static int hyper_dev_release(struct inode* inode, struct file *filep){
	printk(KERN_INFO "Hyper device released!\n");
	return 0;
}

module_init(hyper_init);
module_exit(hyper_exit);
