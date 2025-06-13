# kvmProber
its a prober, its a scanner, its a midnight pwner 

# KVM Guest-to-Host Memory Probing Toolkit

## Overview

This toolkit is designed for security research and CTF challenges involving KVM guest-to-host memory probing and exploitation. It provides scripts and kernel modules to probe, fuzz, and interact with KVM-related devices and MMIO regions from within a Linux guest VM. The toolkit can help identify vulnerabilities that allow a guest to read or write host memory, potentially leading to privilege escalation or VM escape.

---

## Components

### 1. `kvm_dma_overwrite.py`
- **Purpose:** Generates and builds a kernel module (`kvm_probe_drv.ko`) and a userland tool (`kvm_prober`) for probing and manipulating MMIO and I/O ports.
- **Features:**
  - Read/write MMIO and I/O ports.
  - Bulk MMIO scanning (`scanmmio` command).
  - Support for fuzzing and exploitation primitives.
- **Usage:**
  Run the script to generate, build, and install the kernel module and userland tool.

### 2. `kvm_prober`
- **Purpose:** Userland tool for interacting with the kernel module.
- **Key Commands:**
  - `readmmio_val <addr> <size>`: Read value from MMIO.
  - `writemmio_val <addr> <value> <size>`: Write value to MMIO.
  - `readmmio_buf <addr> <size>`: Read buffer from MMIO.
  - `writemmio_buf <addr> <hex_string>`: Write buffer to MMIO.
  - `scanmmio <start> <end> <step>`: Bulk scan MMIO regions.
- **Example:**
  ```bash
  kvm_prober scanmmio 0x6000000 0x7000000 64 > mmio_scan.txt
  ```

### 3. `dynamic_kvm_prober.py`
- **Purpose:** Dynamically loads plugins to probe various KVM and vhost devices.
- **Features:**
  - Enumerates and probes `/dev/kvm`, `/dev/vhost-*`, `/dev/vfio`, etc.
  - Supports plugin-based device-specific fuzzing.
  - Useful for discovering new attack surfaces.

### 4. Plugins Directory
- **Purpose:** Contains Python plugins for device-specific probing logic.
- **How to Extend:**
  Add new plugins for additional devices or fuzzing strategies.

### 5. `setup.sh`
- **Purpose:** Ensures the environment is ready and runs the dynamic prober.

---

## Typical Workflow

1. **Build and Load the Kernel Module**
   ```bash
   python3 kvm_dma_overwrite.py
   cd /tmp/evil_src
   make
   sudo insmod evil.ko
   ```

2. **Probe MMIO Regions**
   ```bash
   kvm_prober scanmmio 0x6000000 0x7000000 64 > mmio_scan.txt
   kvm_prober readmmio_buf 0xdeadbeef | xxd -r -p
   kvm_prober scanmmio 0xdeadbeat 0xdeadbeef 64 | xxd -r -p | strings | grep foo
   ```

3. **Analyze Output**
   - Extract ASCII strings:
     ```bash
     strings mmio_scan.txt | grep -Eo 'flag\{[^}]{0,64}\}|kvmCTF\{[^}]{0,64}\}'
     ```
   - Convert to binary for deeper analysis:
     ```bash
     awk '{for(i=3;i<=NF;i++) printf $i; print ""}' mmio_scan.txt | xxd -r -p > mmio_scan.bin
     strings mmio_scan.bin | grep -i flag
     ```

4. **Dynamic Device Probing**
   ```bash
   python3 dynamic_kvm_prober.py
   ```

---

## Security Notes

- **In a secure KVM setup, you should NOT be able to read or write outside your guest's assigned RAM.**
- If you can scan or modify host memory, this is a critical vulnerability or intentional CTF challenge.
- Use these tools only in controlled, legal environments (CTFs, research labs, etc.).

---

## Troubleshooting

- **Kernel module build errors:** Ensure you have the correct kernel headers installed.
- **Permission errors:** Run as root or with `sudo`.
- **Unknown command in `kvm_prober`:** Rebuild after updating `kvm_dma_overwrite.py`.

---

## Requirements

- Python 3
- GCC, make, and Linux kernel headers
- binutils (`nm`, etc.) for symbol extraction
- Root privileges for kernel module operations

---

## References

- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)
- [KVM Documentation](https://www.linux-kvm.org/page/Main_Page)
- [CTF Writeups](https://ctftime.org/writeups)

---

## Disclaimer

This toolkit is for educational and research purposes only.
**Do not use on systems you do not own or have explicit permission to test.**
