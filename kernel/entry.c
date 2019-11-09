#include "entry.h"
#include "linux/device.h"
#include "linux/fs.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hyper1 kernel module");

static dev_t devt; // Our only device number
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

static void cleanup(void){
	if(dev != NULL)
		device_destroy(cls, devt);
	if(cls != NULL)
		class_destroy(cls);
	if(cdev_added)
		cdev_del(cdev);
	unregister_chrdev_region(devt, DEVICE_COUNT); 
}

static void enable_vmx_operation(void){
	__write_cr4(__read_cr4() | 0x2000);
}

static void disable_vmx_operation(void){
	__write_cr4(__read_cr4() & ~(0x2000));
}

static void smp_enable_vmx_operation(void *info) {
	enable_vmx_operation();
}

static void smp_disable_vmx_operation(void *info) {
	disable_vmx_operation();
}

static int __init hyper_init(void) {
	int err;

	printk(KERN_INFO "Hyper1 Init!\n");
	
	// Obtain available device number (devt)
	if((err = alloc_chrdev_region(&devt, 0 , DEVICE_COUNT, DEVICE_NAME))){
		printk(KERN_ALERT "alloc_chrdev_region() failed");
		return err;
	}

	// Create chrdev and register with the system
        if((cdev = cdev_alloc()) == NULL){
                cleanup();
                printk(KERN_ALERT "cdev_alloc() failed");
                return -1;
        } 
        cdev->ops = &fops;
        if(cdev_add(cdev, devt, 1) == -1){
                cleanup();
                printk(KERN_ALERT "cdev_add() failed");
                return -1;
        }
        cdev_added = true;	
	
	// Register chrdev with sysfs for udevd to create our device file
	if((cls = class_create(THIS_MODULE, DEVICE_NAME)) == NULL){
		cleanup();
		printk(KERN_ALERT "class_create() failed");
		return -1;	
	} 
	if((dev = device_create(cls, NULL, devt, NULL, DEVICE_NAME)) == NULL){
		cleanup();
		printk(KERN_ALERT "device_create() failed");
		return -1;
	}
	
	printk(KERN_INFO "Assigned major number %d\n", MAJOR(devt));
	return 0;
}

static void __exit hyper_exit(void) {
	cleanup();
	printk(KERN_INFO "Hyper1 Exit!\n");
} 

static int hyper_dev_open(struct inode* inode, struct file *filep){
	printk(KERN_INFO "Enabling VMX operation!\n");
	on_each_cpu(smp_enable_vmx_operation, NULL, 1);
	return 0;
}

static int hyper_dev_release(struct inode* inode, struct file *filep){
	printk(KERN_INFO "Disabling VMX operation!\n");
	on_each_cpu(smp_disable_vmx_operation, NULL, 1);
	return 0;
}


module_init(hyper_init);
module_exit(hyper_exit);
