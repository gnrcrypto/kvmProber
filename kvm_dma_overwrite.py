# -*- coding: utf-8 -*-
import os
import subprocess
import shutil
import tempfile
import sys
import fcntl
import importlib.util
import stat

# Path to vmlinux file containing kernel symbols
VMLINUX_PATH = "/root/vmlinux"
# --- Configuration ---
MODULE_NAME = "kvm_probe_drv"
USER_PROBER_NAME = "kvm_prober"
# --- Configuration ---
MODULE_NAME = "kvm_probe_drv"
USER_PROBER_NAME = "kvm_prober"
DEVICE_NAME = "kvm_probe"  # Device node will be /dev/kvm_probe

TEMP_BUILD_DIR_PREFIX = "kvm_probe_build_"

# IOCTL Definitions
IOCTL_READ_PORT_DEF = "_IOWR('k', 0x10, struct port_io_data)"
IOCTL_WRITE_PORT_DEF = "_IOW('k', 0x11, struct port_io_data)"
IOCTL_READ_MMIO_DEF = "_IOWR('k', 0x20, struct mmio_data)"
IOCTL_WRITE_MMIO_DEF = "_IOW('k', 0x21, struct mmio_data)"
IOCTL_ALLOC_VQ_PAGE_DEF = "_IOR('k', 0x30, unsigned long)"  # Returns PFN
IOCTL_FREE_VQ_PAGE_DEF = "_IO('k', 0x31)"
IOCTL_WRITE_VQ_DESC_DEF = "_IOW('k', 0x32, struct vq_desc_user_data)"
IOCTL_TRIGGER_HYPERCALL_DEF = "_IOR('k', 0x40, long)"  # Fixed to return hypercall result

# Get Kernel Symbols

def get_kernel_symbol(symbol):
    # try vmlinux first
    if os.path.isfile(VMLINUX_PATH):
        process = run_command(["bash", "-c", f"nm -n {VMLINUX_PATH} | grep ' {symbol}$'"], capture_output=True, check=False)
        out = process.stdout.strip() if process and process.stdout else ""
        if out:
            addr = out.split()[0]
            print(f"[+] Kernel symbol '{symbol}' from vmlinux at address: {addr}")
            return int(addr, 16)
        else:
            print(f"[!] Symbol '{symbol}' not in vmlinux, falling back to /proc/kallsyms")
    # fallback
    process = run_command(["bash", "-c", f"grep ' {symbol}$' /proc/kallsyms"], capture_output=True, check=False)
    kallsyms = process.stdout.strip() if process and process.stdout else ""
    if kallsyms:
        addr = kallsyms.split()[0]
        print(f"[+] Kernel symbol '{symbol}' from /proc/kallsyms at address: {addr}")
        return int(addr, 16)
    print(f"[!] Kernel symbol '{symbol}' not found anywhere.")
    return None

# --- Helper Functions ---
def check_command_exists(command):
    return shutil.which(command) is not None

def run_command(cmd_list, cwd=None, capture_output=True, check=True, ignore_errors=False):
    print(f"🔩 Executing: {' '.join(cmd_list)} {'in ' + cwd if cwd else ''}")
    try:
        process = subprocess.run(cmd_list, cwd=cwd, check=check, text=True, capture_output=capture_output)
        if capture_output:
            if process.stdout and process.stdout.strip(): print(f"Stdout:\n{process.stdout.strip()}")
            if process.stderr and process.stderr.strip(): print(f"Stderr:\n{process.stderr.strip()}")
        return process
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {' '.join(cmd_list)}")
        if e.stdout and e.stdout.strip(): print(f"Stdout (on error):\n{e.stdout.strip()}")
        if e.stderr and e.stderr.strip(): print(f"Stderr (on error):\n{e.stderr.strip()}")
        if not ignore_errors: raise
        return e
    except FileNotFoundError:
        print(f"❌ Command not found: {cmd_list[0]}.")
        if not ignore_errors: raise
        return None

# --- Main Lab Setup Logic ---
def setup_kvm_probe_lab():
    workdir = None
    module_loaded_successfully = False

    print("--- [KVM Probe Lab Setup - Enhanced for Host Interaction] ---")

    if os.geteuid() != 0:
        print("🚨 This script needs to run as root.")
        return

    print("✅ Running as root. Proceeding with setup.")

    if not check_command_exists("make") or not check_command_exists("gcc"):
        print("❌ 'make' or 'gcc' not found. Attempting to install...")
        run_command(["sudo", "apt", "update", "-qq"], ignore_errors=True)
        run_command(["sudo", "apt", "install", "-y", "-qq", "build-essential"], ignore_errors=True)
        if not check_command_exists("make") or not check_command_exists("gcc"):
            print("❌ Failed to install 'make'/'gcc'. Aborting.")
            return

    try:
        workdir = tempfile.mkdtemp(prefix=TEMP_BUILD_DIR_PREFIX)
        print(f"📂 Temp build directory: {workdir}")
    except Exception as e:
        print(f"❌ Failed to create temp dir: {e}. Aborting."); return

    kernel_module_c_path = os.path.join(workdir, f'{MODULE_NAME}.c')
    user_prober_c_path   = os.path.join(workdir, f'{USER_PROBER_NAME}.c')
    makefile_path        = os.path.join(workdir, 'Makefile')
    kernel_module_ko_path = os.path.join(workdir, f"{MODULE_NAME}.ko")
    user_prober_exe_path  = os.path.join(workdir, USER_PROBER_NAME)

    kernel_module_code = f"""
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#define DRIVER_NAME "{{MODULE_NAME}}"
#define DEVICE_FILE_NAME "{{DEVICE_NAME}}"

#define VQ_PAGE_ORDER 0
#define VQ_PAGE_SIZE (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))

// Increase virtqueue page size for better exploitability
#define MAX_VQ_DESCS 256

static void *g_vq_virt_addr = NULL;
static dma_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;

struct port_io_data {{
    unsigned short port;
    unsigned int size;
    unsigned int value;
}};

struct mmio_data {{
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
}};

struct vring_desc_kernel {{
    __le64 addr;
    __le32 len;
    __le16 flags;
    __le16 next;
}};
struct vq_desc_user_data {{
    u16 index;
    u64 phys_addr;
    u32 len;
    u16 flags;
    u16 next_idx;
}};

#define IOCTL_READ_PORT {IOCTL_READ_PORT_DEF}
#define IOCTL_WRITE_PORT {IOCTL_WRITE_PORT_DEF}
#define IOCTL_READ_MMIO {IOCTL_READ_MMIO_DEF}
#define IOCTL_WRITE_MMIO {IOCTL_WRITE_MMIO_DEF}
#define IOCTL_ALLOC_VQ_PAGE {IOCTL_ALLOC_VQ_PAGE_DEF}
#define IOCTL_FREE_VQ_PAGE  {IOCTL_FREE_VQ_PAGE_DEF}
#define IOCTL_WRITE_VQ_DESC {IOCTL_WRITE_VQ_DESC_DEF}
#define IOCTL_TRIGGER_HYPERCALL {IOCTL_TRIGGER_HYPERCALL_DEF}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Enhanced kernel module for KVM exploitation");

static int major_num;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

// Hypercall helper with timing info
static long force_hypercall(void) {{
    long ret;
    u64 start = ktime_get_ns();
    ret = kvm_hypercall0(KVM_HC_VAPIC_POLL_IRQ);
    u64 end = ktime_get_ns();
    printk(KERN_INFO "%s: HYPERCALL executed | latency=%llu ns | ret=%ld\\n",
           DRIVER_NAME, end - start, ret);
    return ret;
}}

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {{
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;

    printk(KERN_CRIT "%s: IOCTL ENTRY! cmd=0x%x, arg=0x%lx. ktime=%llu\\n",
           DRIVER_NAME, cmd, arg, ktime_get_ns());

    switch (cmd) {{
        case IOCTL_READ_PORT:
        {{
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {{
                printk(KERN_ERR "%s: READ_PORT: copy_from_user failed. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
                return -EFAULT;
            }}
            printk(KERN_INFO "%s: IOCTL_READ_PORT: port=0x%hx, req_size=%u. ktime=%llu\\n",
                   DRIVER_NAME, p_io_data_kernel.port, p_io_data_kernel.size, ktime_get_ns());

            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {{
                printk(KERN_WARNING "%s: READ_PORT: Invalid size: %u. ktime=%llu\\n", DRIVER_NAME, p_io_data_kernel.size, ktime_get_ns());
                return -EINVAL;
            }}

            switch (p_io_data_kernel.size) {{
                case 1: p_io_data_kernel.value = inb(p_io_data_kernel.port); break;
                case 2: p_io_data_kernel.value = inw(p_io_data_kernel.port); break;
                case 4: p_io_data_kernel.value = inl(p_io_data_kernel.port); break;
            }}
            printk(KERN_INFO "%s: IOCTL_READ_PORT: value_read=0x%x from port 0x%hx. ktime=%llu\\n",
                   DRIVER_NAME, p_io_data_kernel.value, p_io_data_kernel.port, ktime_get_ns());

            if (copy_to_user((struct port_io_data __user *)arg, &p_io_data_kernel, sizeof(p_io_data_kernel))) {{
                printk(KERN_ERR "%s: READ_PORT: copy_to_user failed. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
                return -EFAULT;
            }}

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_WRITE_PORT:
        {{
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {{
                printk(KERN_ERR "%s: WRITE_PORT: copy_from_user failed. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
                return -EFAULT;
            }}
            printk(KERN_INFO "%s: IOCTL_WRITE_PORT: port=0x%hx, value_to_write=0x%x, req_size=%u. ktime=%llu\\n",
                   DRIVER_NAME, p_io_data_kernel.port, p_io_data_kernel.value, p_io_data_kernel.size, ktime_get_ns());

            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {{
                printk(KERN_WARNING "%s: WRITE_PORT: Invalid size: %u. ktime=%llu\\n", DRIVER_NAME, p_io_data_kernel.size, ktime_get_ns());
                return -EINVAL;
            }}

            switch (p_io_data_kernel.size) {{
                case 1: outb((u8)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 2: outw((u16)p_io_data_kernel.value, p_io_data_kernel.port); break;
                case 4: outl((u32)p_io_data_kernel.value, p_io_data_kernel.port); break;
            }}
            printk(KERN_INFO "%s: IOCTL_WRITE_PORT: Write to port 0x%hx completed. ktime=%llu\\n",
                   DRIVER_NAME, p_io_data_kernel.port, ktime_get_ns());

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_READ_MMIO:
        {{
            struct mmio_data data;
            if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
                return -EFAULT;
            void __iomem *mmio = ioremap(data.phys_addr, data.size);
            if (!mmio)
                return -EFAULT;
            void *kbuf = kmalloc(data.size, GFP_KERNEL);
            if (!kbuf) {{
                iounmap(mmio);
                return -ENOMEM;
            }}
            memcpy_fromio(kbuf, mmio, data.size);
            if (copy_to_user(data.user_buffer, kbuf, data.size)) {{
                kfree(kbuf);
                iounmap(mmio);
                return -EFAULT;
            }}
            kfree(kbuf);
            iounmap(mmio);
            return 0;
        }}
        case IOCTL_WRITE_MMIO:
        {{
            if (copy_from_user(&m_io_data_kernel, (struct mmio_data __user *)arg, sizeof(m_io_data_kernel))) {{ return -EFAULT; }}
            unsigned long map_size = m_io_data_kernel.size > 0 ? m_io_data_kernel.size : m_io_data_kernel.value_size;
            if (map_size == 0) {{
                printk(KERN_ERR "%s: WRITE_MMIO: Map size is zero.\\n", DRIVER_NAME);
                return -EINVAL;
            }}
            printk(KERN_INFO "%s: WRITE_MMIO: Requesting ioremap for phys_addr=0x%lx, map_size=%lu\\n",
                   DRIVER_NAME, m_io_data_kernel.phys_addr, map_size);
            mapped_addr = ioremap(m_io_data_kernel.phys_addr, map_size);
            if (!mapped_addr) {{
                printk(KERN_ERR "%s: WRITE_MMIO: ioremap for 0x%lx returned NULL!\\n",
                       DRIVER_NAME, m_io_data_kernel.phys_addr);
                return -ENOMEM;
            }}
            printk(KERN_INFO "%s: WRITE_MMIO: ioremap(0x%lx, %lu) successful, mapped_addr=%p\\n",
                   DRIVER_NAME, m_io_data_kernel.phys_addr, map_size, mapped_addr);
            if (m_io_data_kernel.size > 0) {{
                if (!m_io_data_kernel.user_buffer) {{
                    printk(KERN_ERR "%s: WRITE_MMIO: User buffer NULL.\\n", DRIVER_NAME);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }}
                k_mmio_buffer = kmalloc(m_io_data_kernel.size, GFP_KERNEL);
                if (!k_mmio_buffer) {{
                    iounmap(mapped_addr);
                    return -ENOMEM;
                }}
                if (copy_from_user(k_mmio_buffer, m_io_data_kernel.user_buffer, m_io_data_kernel.size)) {{
                    kfree(k_mmio_buffer);
                    iounmap(mapped_addr);
                    return -EFAULT;
                }}
                for (len_to_copy = 0; len_to_copy < m_io_data_kernel.size; ++len_to_copy) {{
                    writeb(k_mmio_buffer[len_to_copy], mapped_addr + len_to_copy);
                }}
                kfree(k_mmio_buffer);
            }} else {{
                switch(m_io_data_kernel.value_size) {{
                    case 1:
                        writeb((u8)m_io_data_kernel.single_value, mapped_addr);
                        break;
                    case 2:
                        writew((u16)m_io_data_kernel.single_value, mapped_addr);
                        break;
                    case 4:
                        writel((u32)m_io_data_kernel.single_value, mapped_addr);
                        break;
                    case 8:
                        writeq(m_io_data_kernel.single_value, mapped_addr);
                        break;
                    default:
                        printk(KERN_ERR "%s: WRITE_MMIO: Invalid value_size %u\\n",
                               DRIVER_NAME, m_io_data_kernel.value_size);
                        iounmap(mapped_addr);
                        return -EINVAL;
                }}
            }}
            iounmap(mapped_addr);

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_ALLOC_VQ_PAGE:
        {{
            struct page *vq_page_ptr;
            unsigned long pfn_to_user;

            if (g_vq_virt_addr) {{
                printk(KERN_INFO "%s: ALLOC_VQ_PAGE: Freeing previous VQ page (virt: %p, phys: 0x%llx). ktime=%llu\\n",
                       DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, ktime_get_ns());
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }}
            vq_page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM, VQ_PAGE_ORDER);
            if (!vq_page_ptr) {{
                printk(KERN_ERR "%s: ALLOC_VQ_PAGE: Failed to allocate VQ page. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
                return -ENOMEM;
            }}
            g_vq_virt_addr = page_address(vq_page_ptr);
            g_vq_phys_addr = page_to_phys(vq_page_ptr);
            g_vq_pfn = PFN_DOWN(g_vq_phys_addr);
            pfn_to_user = g_vq_pfn;

            printk(KERN_INFO "%s: ALLOC_VQ_PAGE: Allocated VQ page: virt=%p, phys=0x%llx, pfn=0x%lx, size=%lu. ktime=%llu\\n",
                   DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, g_vq_pfn, VQ_PAGE_SIZE, ktime_get_ns());

            if (copy_to_user((unsigned long __user *)arg, &pfn_to_user, sizeof(pfn_to_user))) {{
                printk(KERN_ERR "%s: ALLOC_VQ_PAGE: copy_to_user failed for PFN. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
                return -EFAULT;
            }}

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_FREE_VQ_PAGE:
        {{
            printk(KERN_INFO "%s: IOCTL_FREE_VQ_PAGE. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
            if (g_vq_virt_addr) {{
                printk(KERN_INFO "%s: FREE_VQ_PAGE: Freeing VQ page (virt: %p, phys: 0x%llx). ktime=%llu\\n",
                       DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, ktime_get_ns());
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
            }} else {{
                printk(KERN_INFO "%s: FREE_VQ_PAGE: No VQ page currently allocated. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
            }}

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_WRITE_VQ_DESC:
        {{
            struct vq_desc_user_data user_desc_data_kernel;
            struct vring_desc_kernel *kernel_desc_ptr_local;
            unsigned int max_descs_in_page_local;

            printk(KERN_INFO "%s: IOCTL_WRITE_VQ_DESC received. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
            if (!g_vq_virt_addr) {{
                printk(KERN_ERR "%s: WRITE_VQ_DESC: VQ page not allocated. Call ALLOC_VQ_PAGE first.\\n", DRIVER_NAME);
                return -ENXIO;
            }}
            if (copy_from_user(&user_desc_data_kernel, (struct vq_desc_user_data __user *)arg, sizeof(user_desc_data_kernel))) {{
                return -EFAULT;
            }}

            max_descs_in_page_local = VQ_PAGE_SIZE / sizeof(struct vring_desc_kernel);
            if (user_desc_data_kernel.index >= max_descs_in_page_local) {{
                printk(KERN_ERR "%s: WRITE_VQ_DESC: Descriptor index %u out of bounds (max %u)\\n",
                    DRIVER_NAME, user_desc_data_kernel.index, max_descs_in_page_local - 1);
                return -EINVAL;
            }}

            kernel_desc_ptr_local = (struct vring_desc_kernel *)g_vq_virt_addr + user_desc_data_kernel.index;

            kernel_desc_ptr_local->addr = cpu_to_le64(user_desc_data_kernel.phys_addr);
            kernel_desc_ptr_local->len = cpu_to_le32(user_desc_data_kernel.len);
            kernel_desc_ptr_local->flags = cpu_to_le16(user_desc_data_kernel.flags);
            kernel_desc_ptr_local->next = cpu_to_le16(user_desc_data_kernel.next_idx);

            printk(KERN_INFO "%s: Wrote VQ desc at index %u: GPA=0x%llx, len=%u, flags=0x%hx, next=%hu. ktime=%llu\\n",
                   DRIVER_NAME, user_desc_data_kernel.index, user_desc_data_kernel.phys_addr,
                   user_desc_data_kernel.len, user_desc_data_kernel.flags, user_desc_data_kernel.next_idx, ktime_get_ns());

            // Force hypercall after operation
            force_hypercall();
            break;
        }}
        case IOCTL_TRIGGER_HYPERCALL:
        {{
            printk(KERN_INFO "%s: DIRECT HYPERCALL TRIGGER. ktime=%llu\\n", DRIVER_NAME, ktime_get_ns());
            long ret = force_hypercall();
            if (copy_to_user((long __user *)arg, &ret, sizeof(ret))) {{
                printk(KERN_ERR "%s: TRIGGER_HYPERCALL: copy_to_user failed\\n", DRIVER_NAME);
                return -EFAULT;
            }}
            break;
        }}
        default:
            printk(KERN_ERR "%s: Unknown IOCTL command: 0x%x\\n", DRIVER_NAME, cmd);
            return -EINVAL;
    }}
    return 0;
}}

static struct file_operations fops = {{
    .unlocked_ioctl = driver_ioctl,
}};

static int __init mod_init(void) {{
    printk(KERN_INFO "%s: Initializing Enhanced KVM Probe Module.\\n", DRIVER_NAME);
    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {{
        printk(KERN_ERR "%s: register_chrdev failed: %d\\n", DRIVER_NAME, major_num);
        return major_num;
    }}

    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(driver_class)) {{
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: class_create failed\\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }}

    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {{
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: device_create failed\\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }}
    g_vq_virt_addr = NULL;
    g_vq_phys_addr = 0;
    g_vq_pfn = 0;
    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d.\\n", DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    return 0;
}}

static void __exit mod_exit(void) {{
    printk(KERN_INFO "%s: Unloading KVM Probe Module.\\n", DRIVER_NAME);
    if (g_vq_virt_addr) {{
        printk(KERN_INFO "%s: mod_exit: Freeing VQ page (virt: %p, phys: 0x%llx).\\n",
               DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr);
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
        g_vq_virt_addr = NULL;
        g_vq_phys_addr = 0;
        g_vq_pfn = 0;
    }}
    if (driver_device) {{
        device_destroy(driver_class, MKDEV(major_num, 0));
    }}
    if (driver_class) {{
        class_unregister(driver_class);
        class_destroy(driver_class);
    }}
    if (major_num >= 0) {{
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
    }}
    printk(KERN_INFO "%s: Module unloaded.\\n", DRIVER_NAME);
}}

module_init(mod_init);
module_exit(mod_exit);
"""

    # --- USER-SPACE PROBER C CODE (kvm_prober.c) ---
    user_prober_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>  // For nanosleep

#define DEVICE_PATH "/dev/{{DEVICE_NAME}}"

// Data structures (must match kernel module)
struct port_io_data {{
    unsigned short port;
    unsigned int size;
    unsigned int value;
}};

struct mmio_data {{
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
}};

struct vq_desc_user_data {{
    unsigned short index;
    unsigned long long phys_addr;
    unsigned int len;
    unsigned short flags;
    unsigned short next_idx;
}};

// IOCTL definitions
#define IOCTL_READ_PORT {IOCTL_READ_PORT_DEF}
#define IOCTL_WRITE_PORT {IOCTL_WRITE_PORT_DEF}
#define IOCTL_READ_MMIO {IOCTL_READ_MMIO_DEF}
#define IOCTL_WRITE_MMIO {IOCTL_WRITE_MMIO_DEF}
#define IOCTL_ALLOC_VQ_PAGE {IOCTL_ALLOC_VQ_PAGE_DEF}
#define IOCTL_FREE_VQ_PAGE  {IOCTL_FREE_VQ_PAGE_DEF}
#define IOCTL_WRITE_VQ_DESC {IOCTL_WRITE_VQ_DESC_DEF}
#define IOCTL_TRIGGER_HYPERCALL {IOCTL_TRIGGER_HYPERCALL_DEF}

// Exploit helper functions
void exploit_delay(int nanoseconds) {{
    struct timespec req = {{0}};
    req.tv_nsec = nanoseconds;
    nanosleep(&req, NULL);
}}

void print_usage(char *prog_name) {{
    fprintf(stderr, "Usage: %s <command> [args...]\\n", prog_name);
    fprintf(stderr, "Commands:\\n");
    fprintf(stderr, "  readport <port_hex> <size_bytes (1,2,4)>\\n");
    fprintf(stderr, "  writeport <port_hex> <value_hex> <size_bytes (1,2,4)>\\n");
    fprintf(stderr, "  readmmio_val <phys_addr_hex> <size_bytes (1,2,4,8)> \\n");
    fprintf(stderr, "  writemmio_val <phys_addr_hex> <value_hex> <size_bytes (1,2,4,8)> \\n");
    fprintf(stderr, "  readmmio_buf <phys_addr_hex> <num_bytes_to_read> \\n");
    fprintf(stderr, "  writemmio_buf <phys_addr_hex> <hex_string_to_write> \\n");
    fprintf(stderr, "  allocvqpage                       (Allocate a page for VQ, prints PFN)\\n");
    fprintf(stderr, "  freevqpage                        (Free the allocated VQ page)\\n");
    fprintf(stderr, "  writevqdesc <idx> <buf_gpa_hex> <buf_len_str> <flags_hex> <next_idx_dec>\\n");
    fprintf(stderr, "  trigger_hypercall                 (Directly trigger hypercall)\\n");
    fprintf(stderr, "  exploit_delay <nanoseconds>       (Inject delay for race conditions)\\n");
    fprintf(stderr, "  scanmmio <start_addr_hex> <end_addr_hex> <step_bytes>\\n");
}}

unsigned char *hex_string_to_bytes(const char *hex_str, unsigned long *num_bytes) {{
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {{
        fprintf(stderr, "Hex string must have an even number of characters.\\n");
        return NULL;
    }}
    *num_bytes = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(*num_bytes);
    if (!bytes) {{
        perror("malloc for hex_string_to_bytes");
        return NULL;
    }}
    for (size_t i = 0; i < *num_bytes; ++i) {{
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {{
            fprintf(stderr, "Invalid hex char in string.\\n");
            free(bytes);
            return NULL;
        }}
    }}
    return bytes;
}}

int main(int argc, char *argv[]) {{
    if (argc < 2) {{
        print_usage(argv[0]);
        return 1;
    }}
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {{
        perror("Failed to open " DEVICE_PATH ". Is the kernel module loaded?");
        return 1;
    }}
    char *cmd = argv[1];

    if (strcmp(cmd, "readport") == 0) {{
        if (argc != 4) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.size = (unsigned int)strtoul(argv[3], NULL, 10);
        if (ioctl(fd, IOCTL_READ_PORT, &data) < 0) perror("ioctl READ_PORT failed");
        else printf("Port 0x%X (size %u) Value: 0x%X (%u)\\n", data.port, data.size, data.value, data.value);
    }} else if (strcmp(cmd, "writeport") == 0) {{
        if (argc != 5) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.value = (unsigned int)strtoul(argv[3], NULL, 16);
        data.size = (unsigned int)strtoul(argv[4], NULL, 10);
        if (ioctl(fd, IOCTL_WRITE_PORT, &data) < 0) perror("ioctl WRITE_PORT failed");
        else printf("Wrote 0x%X to port 0x%X (size %u)\\n", data.value, data.port, data.size);
    }} else if (strcmp(cmd, "readmmio_val") == 0) {{
        if (argc != 4) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct mmio_data data = {{0}};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[3], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) perror("ioctl READ_MMIO (value) failed");
        else printf("MMIO 0x%lX (size %u) Value: 0x%lX (%lu)\\n", data.phys_addr, data.value_size, data.single_value, data.single_value);
    }} else if (strcmp(cmd, "writemmio_val") == 0) {{
        if (argc != 5) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct mmio_data data = {{0}};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.single_value = strtoul(argv[3], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0) perror("ioctl WRITE_MMIO (value) failed");
        else printf("Wrote 0x%lX to MMIO 0x%lX (size %u)\\n", data.single_value, data.phys_addr, data.value_size);
    }} else if (strcmp(cmd, "readmmio_buf") == 0) {{
        if (argc != 4) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct mmio_data data = {{0}};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 4096) {{
            fprintf(stderr, "Invalid read size for buffer.\\n");
            close(fd);
            return 1;
        }}
        data.user_buffer = (unsigned char*)malloc(data.size);
        if (!data.user_buffer) {{
            perror("malloc for read buffer");
            close(fd);
            return 1;
        }}
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) perror("ioctl READ_MMIO (buffer) failed");
        else {{
            printf("Read %lu bytes from MMIO 0x%lX:\\n", data.size, data.phys_addr);
            for (unsigned long i = 0; i < data.size; ++i) {{
                printf("%02X ", data.user_buffer[i]);
                if ((i + 1) % 16 == 0) printf("\\n");
            }}
            if (data.size % 16 != 0) printf("\\n");
        }}
        free(data.user_buffer);
    }} else if (strcmp(cmd, "writemmio_buf") == 0) {{
        if (argc != 4) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct mmio_data data = {{0}};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        unsigned char *bytes_to_write = hex_string_to_bytes(argv[3], &num_bytes);
        if (!bytes_to_write || num_bytes == 0) {{
            fprintf(stderr, "Failed to parse hex string or zero length.\\n");
            if(bytes_to_write) free(bytes_to_write);
            close(fd);
            return 1;
        }}
        data.user_buffer = bytes_to_write;
        data.size = num_bytes;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0) perror("ioctl WRITE_MMIO (buffer) failed");
        else printf("Wrote %lu bytes to MMIO 0x%lX from hex string.\\n", data.size, data.phys_addr);
        free(bytes_to_write);
    }} else if (strcmp(cmd, "allocvqpage") == 0) {{
        if (argc != 2) {{ print_usage(argv[0]); close(fd); return 1; }}
        unsigned long pfn_returned = 0;
        if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn_returned) < 0) {{
            perror("ioctl ALLOC_VQ_PAGE failed");
        }} else {{
            printf("Allocated VQ page. PFN: 0x%lX\\n", pfn_returned);
            printf("Guest Physical Address (approx, if PAGE_SIZE=4096): 0x%lX\\n", pfn_returned * 0x1000);
        }}
    }} else if (strcmp(cmd, "freevqpage") == 0) {{
        if (argc != 2) {{ print_usage(argv[0]); close(fd); return 1; }}
        if (ioctl(fd, IOCTL_FREE_VQ_PAGE) < 0) {{
            perror("ioctl FREE_VQ_PAGE failed");
        }} else {{
            printf("Sent FREE_VQ_PAGE command.\\n");
        }}
    }} else if (strcmp(cmd, "writevqdesc") == 0) {{
        if (argc != 7) {{ print_usage(argv[0]); close(fd); return 1; }}
        struct vq_desc_user_data d_data;
        d_data.index = (unsigned short)strtoul(argv[2], NULL, 10);
        d_data.phys_addr = strtoull(argv[3], NULL, 16);
        d_data.len = (unsigned int)strtoul(argv[4], NULL, 0);
        d_data.flags = (unsigned short)strtoul(argv[5], NULL, 16);
        d_data.next_idx = (unsigned short)strtoul(argv[6], NULL, 10);

        fprintf(stderr, "[Prober: Sending WRITE_VQ_DESC for index %hu: GPA=0x%llx, len=%u, flags=0x%hx, next=%hu]\\n",
                d_data.index, d_data.phys_addr, d_data.len, d_data.flags, d_data.next_idx);

        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &d_data) < 0) {{
            perror("ioctl IOCTL_WRITE_VQ_DESC failed");
        }} else {{
            printf("Sent IOCTL_WRITE_VQ_DESC command.\\n");
        }}
    }} else if (strcmp(cmd, "trigger_hypercall") == 0) {{
        if (argc != 2) {{ print_usage(argv[0]); close(fd); return 1; }}
        long hypercall_ret = 0;
        if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &hypercall_ret) < 0) {{
            perror("ioctl IOCTL_TRIGGER_HYPERCALL failed");
        }} else {{
            printf("Hypercall triggered, return value: %ld\\n", hypercall_ret);
        }}
    }} else if (strcmp(cmd, "exploit_delay") == 0) {{
        if (argc != 3) {{ print_usage(argv[0]); close(fd); return 1; }}
        int delay_ns = atoi(argv[2]);
        exploit_delay(delay_ns);
        printf("Delayed for %d nanoseconds.\\n", delay_ns);
    }} else if (strcmp(cmd, "scanmmio") == 0) {{
        if (argc != 5) {{
            print_usage(argv[0]);
            close(fd);
            return 1;
        }}
        unsigned long start = strtoul(argv[2], NULL, 16);
        unsigned long end = strtoul(argv[3], NULL, 16);
        unsigned long step = strtoul(argv[4], NULL, 10);
        struct mmio_data data = {{0}};
        unsigned char *buf = malloc(step);
        if (!buf) {{
            perror("malloc for scanmmio buffer");
            close(fd);
            return 1;
        }}
        for (unsigned long addr = start; addr < end; addr += step) {{
            memset(buf, 0, step);
            data.phys_addr = addr;
            data.size = step;
            data.user_buffer = buf;
            if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) {{
                printf("MMIO 0x%lX: <read error>\\n", addr);
            }} else {{
                printf("MMIO 0x%lX: ", addr);
                for (unsigned long i = 0; i < step; ++i)
                    printf("%02X", buf[i]);
                printf("\\n");
            }}
        }}
        free(buf);
    }} else if (strcmp(cmd, "scanmmio") == 0) {{
        if (argc != 5) {{
            print_usage(argv[0]);
            close(fd);
            return 1;
        }}
        unsigned long start = strtoul(argv[2], NULL, 16);
        unsigned long end = strtoul(argv[3], NULL, 16);
        unsigned long step = strtoul(argv[4], NULL, 10);
        struct mmio_data data = {{0}};
        unsigned char *buf = malloc(step);
        if (!buf) {{
            perror("malloc for scanmmio buffer");
            close(fd);
            return 1;
        }}
        for (unsigned long addr = start; addr < end; addr += step) {{
            memset(buf, 0, step);
            data.phys_addr = addr;
            data.size = step;
            data.user_buffer = buf;
            if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) {{
                printf("MMIO 0x%lX: <read error>\\n", addr);
            }} else {{
                printf("MMIO 0x%lX: ", addr);
                for (unsigned long i = 0; i < step; ++i)
                    printf("%02X", buf[i]);
                printf("\\n");
            }}
        }}
        free(buf);
    }} else {{
        fprintf(stderr, "Unknown command: %s\\n", cmd);
        print_usage(argv[0]);
    }}

    close(fd);
    return 0;
}}
"""

    makefile_code = f"""
TARGET_MODULE := {{MODULE_NAME}}
USER_PROBER := {{USER_PROBER_NAME}}

obj-m += $(TARGET_MODULE).o

KVERS := $(shell uname -r)
KDIR := /lib/modules/$(KVERS)/build
PWD_M := $(shell pwd)

EXTRA_CFLAGS_MODULE := -Wno-declaration-after-statement -D_GNU_SOURCE -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -Wno-unused-variable

all: $(TARGET_MODULE).ko $(USER_PROBER)

$(TARGET_MODULE).ko: {{MODULE_NAME}}.c
\t@echo "Building Kernel Module $(TARGET_MODULE).ko for kernel $(KVERS)"
\t$(MAKE) -C $(KDIR) M=$(PWD_M) EXTRA_CFLAGS="$(EXTRA_CFLAGS_MODULE)" modules

$(USER_PROBER): {USER_PROBER_NAME}.c
\t@echo "Building User Prober $(USER_PROBER)"
\tgcc -Wall -O2 -o $(USER_PROBER) {{USER_PROBER_NAME}}.c

clean:
\t@echo "Cleaning build files..."
\t$(MAKE) -C $(KDIR) M=$(PWD_M) clean > /dev/null 2>&1 || true
\trm -f $(USER_PROBER) *.o .*.o.cmd .*.ko.cmd *.mod.c *.order *.symvers \\
\t Module.markers modules.builtin modules.builtin.modinfo .tmp_versions/* \\
\t .$(TARGET_MODULE).ko.cmd .$(TARGET_MODULE).mod.o.cmd .$(TARGET_MODULE).o.cmd \\
\t $(TARGET_MODULE).mod $(TARGET_MODULE).mod.o
"""

    try:
        print("🔧 Ensuring kernel headers are installed...")
        kernel_release = os.uname().release
        if not os.path.isdir(f"/lib/modules/{kernel_release}/build"):
            run_command(["sudo", "apt", "update", "-qq"])
            run_command(["sudo", "apt", "install", "-y", "-qq", f"linux-headers-{kernel_release}"])
        else:
            print(f"ℹ️ Kernel headers for {kernel_release} seem to be present.")

        print(f"📝 Writing source files to {workdir}...")
        with open(kernel_module_c_path, 'w') as f: f.write(kernel_module_code)
        with open(user_prober_c_path, 'w') as f: f.write(user_prober_code)
        with open(makefile_path, 'w') as f: f.write(makefile_code)
        print("✅ Source files generated.")

        print(f"🛠️ Building kernel module '{MODULE_NAME}.ko' and prober '{USER_PROBER_NAME}'...")
        run_command(["make", "clean"], cwd=workdir, ignore_errors=True, check=False)
        run_command(["make"], cwd=workdir) # Check output for warnings/errors
        if not os.path.exists(kernel_module_ko_path):
            raise FileNotFoundError(f"{kernel_module_ko_path} not built.")
        if not os.path.exists(user_prober_exe_path):
            raise FileNotFoundError(f"{user_prober_exe_path} not built.")
        print("✅ Build successful.")

        print(f"🚀 Loading kernel module '{MODULE_NAME}.ko'...")
        run_command(["sudo", "rmmod", MODULE_NAME], ignore_errors=True, check=False, cwd=workdir)
        run_command(["sudo", "insmod", kernel_module_ko_path], cwd=workdir)
        module_loaded_successfully = True
        print(f"✅ Kernel module loaded. Device /dev/{DEVICE_NAME} should be available.")
        print(f"🛠️ User prober tool is at: {user_prober_exe_path}")
        print(f"--- Test new commands: ---")
        print(f"  # Trigger hypercall directly")
        print(f"  sudo {user_prober_exe_path} trigger_hypercall")
        print(f"  # Introduce timing delays for race conditions")
        print(f"  sudo {user_prober_exe_path} exploit_delay 1000000  # 1ms delay")
        print(f"---")
        print(f"To cleanup when done:")
        print("---")

    except Exception as e_lab:
        print(f"❌ Error during KVM Probe Lab setup: {e_lab}")
        import traceback
        traceback.print_exc()
    finally:
        if workdir and not module_loaded_successfully:
            print(f"⚠️ You suck again")

def probe_device(dev_path):
    print(f"Probing {dev_path}")
    try:
        with open(dev_path, 'rb+', buffering=0) as f:
            # Try common IOCTLs
            for code in range(0x40000000, 0x40000000 + 0x1000, 4):
                try:
                    fcntl.ioctl(f, code, b'\x00'*32)
                except Exception as e:
                    pass  # Log or analyze errors for clues
    except Exception as e:
        print(f"Failed to open {dev_path}: {e}")

PLUGIN_DIR = "./plugins"

PLUGIN_TEMPLATE = '''from dynamic_kvm_prober import generic_probe

def probe(dev_path):
    print(f"[PLUGIN:{{plugin_name}}] Probing {{dev_path}} (auto-generated, dynamic).")
    generic_probe(dev_path)
'''
def ensure_plugin(name):
    plugin_path = f"{PLUGIN_DIR}/{name}.py"
    if not os.path.exists(plugin_path):
        with open(plugin_path, "w") as f:
            f.write(PLUGIN_TEMPLATE.replace("{plugin_name}", name))
        print(f"[+] Auto-generated dynamic plugin: {plugin_path}")

def load_plugin(name):
    plugin_path = f"{PLUGIN_DIR}/{name}.py"
    if not os.path.exists(plugin_path):
        ensure_plugin(name)
    try:
        spec = importlib.util.spec_from_file_location(name, plugin_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            print(f"[+] Loaded plugin: {name}")
            return module
    except Exception as e:
        print(f"[-] Could not load plugin {name}: {e}")
    return None

def generic_probe(dev_path):
    print(f"[!] No plugin for {dev_path}, using generic probe.")
    try:
        with open(dev_path, 'rb+', buffering=0) as f:
            for code in range(0x40000000, 0x40000000 + 0x1000, 4):
                try:
                    fcntl.ioctl(f, code, b'\x00'*32)
                except Exception:
                    pass
    except Exception as e:
        print(f"[-] Failed to open dev_path}}: {e}")

def get_kvm_related_modules():
    """
    Returns a list of loaded kernel modules related to KVM.
    """
    modules = []
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                mod_name = line.split()[0]
                if "kvm" in mod_name.lower():
                    modules.append(mod_name)
    except Exception as e:
        print(f"[-] Could not read /proc/modules: {e}")
    return modules

def enumerate_char_devices():
    """
    Enumerate character devices in /dev that are likely to be KVM-related or interesting.
    Returns a list of device paths.
    """
    char_devs = []
    dev_dir = "/dev"
    try:
        for entry in os.listdir(dev_dir):
            path = os.path.join(dev_dir, entry)
            try:
                st = os.stat(path)
                if os.path.exists(path) and stat.S_ISCHR(st.st_mode):
                    # Optionally filter for kvm-related names
                    if "kvm" in entry.lower() or "vhost" in entry.lower() or "virt" in entry.lower():
                        char_devs.append(path)
            except Exception:
                continue
    except Exception as e:
        print(f"[-] Could not enumerate char devices: {e}")
    return char_devs

def main():
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    modules = get_kvm_related_modules()
    char_devices = enumerate_char_devices()

    for dev_path in char_devices:
        dev_name = os.path.basename(dev_path)
        plugin = None
        # Try to load plugin by device name
        plugin = load_plugin(dev_name)
        # If not found, try by module name
        if not plugin:
            for mod in modules:
                if mod in dev_name:
                    plugin = load_plugin(mod)
                    if plugin:
                        break
        # Use plugin if found, else generic probe
        if plugin and hasattr(plugin, 'probe'):
            print(f"[+] Using plugin for {dev_name}")
            plugin.probe(dev_path)
        else:
            generic_probe(dev_path)

if __name__ == "__main__":
    main()

if __name__ == '__main__':
    setup_kvm_probe_lab()
