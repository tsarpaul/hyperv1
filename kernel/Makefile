obj-m := hyperko.o 
hyperko-objs := vmx.o hyper.o ept.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	EXTRA_CFLAGS="-fno-inline"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
