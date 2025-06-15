TARGET_MODULE := kvm_probe_drv
USER_PROBER := kvm_prober

obj-m += $(TARGET_MODULE).o

KVERS := $(shell uname -r)
KDIR := /lib/modules/$(KVERS)/build
PWD_M := $(shell pwd)

EXTRA_CFLAGS_MODULE := -Wno-declaration-after-statement -D_GNU_SOURCE -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-unused-variable

all: $(TARGET_MODULE).ko $(USER_PROBER)

$(TARGET_MODULE).ko: kvm_probe_drv.c
	@echo "Building Kernel Module $(TARGET_MODULE).ko for kernel $(KVERS)"
	$(MAKE) -C $(KDIR) M=$(PWD_M) EXTRA_CFLAGS="$(EXTRA_CFLAGS_MODULE)" modules

$(USER_PROBER): kvm_prober.c
	@echo "Building User Prober $(USER_PROBER)"
	$(CC) -Wall -O2 -o $(USER_PROBER) kvm_prober.c

clean:
	@echo "Cleaning build files..."
	$(MAKE) -C $(KDIR) M=$(PWD_M) clean > /dev/null 2>&1 || true
	rm -f $(USER_PROBER) *.o .*.o.cmd .*.ko.cmd *.mod.c *.order *.symvers \\
	Module.markers modules.builtin modules.builtin.modinfo .tmp_versions/* \\
	.$(TARGET_MODULE).ko.cmd .$(TARGET_MODULE).mod.o.cmd .$(TARGET_MODULE).o.cmd \\
	$(TARGET_MODULE).mod $(TARGET_MODULE).mod.o

.PHONY: all clean modules
