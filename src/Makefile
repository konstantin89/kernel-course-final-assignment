obj-m += net_filt.o  

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS = -g

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) M=$(PWD) modules

i:
	sudo insmod net_filt.ko cache_ttl_ns=1000

r:
	sudo rmmod net_filt

clean:
	$(RM) .*.cmd *.o *.ko -r *.mod *.mod.c Module.symvers modules.order