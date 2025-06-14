# --- Makefile for KVM exploit/probe setup ---

obj-m := kvm_probe_drv.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: kvm_probe_drv.ko kvm_prober

kvm_probe_drv.ko: kvm_probe_drv.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules

kvm_prober: kvm_prober.c
	gcc -Wall -O2 -o kvm_prober kvm_prober.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kvm_prober

.PHONY: all clean
