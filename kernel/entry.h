#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "linux/fs.h"
#include "linux/cdev.h"
#include "linux/device.h"
#include "asm/special_insns.h"

#define DEVICE_NAME "hyper1"
#define DEVICE_COUNT 1

static int hyper_init(void);
static void hyper_exit(void);

static int hyper_dev_open(struct inode *, struct file *);
static int hyper_dev_release(struct inode *, struct file *);
//static ssize_t device_read(struct file *, char *, size_t, loff_t *);
//static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

