#General Purpose Makefile for Linux Kernel module by guoqingbo

#KERN_DIR = /usr/src/linux-headers-3.19.0-32-generic
#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build
test-objs := lwfw.o 
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   

clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order

obj-m += test.o
