#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// Add any extra interesting HCALL numbers here:
#define HCALLS_LEN 6
int hcalls[HCALLS_LEN] = {
    0,      // KVM_HC_VAPIC_POLL_IRQ (sometimes default)
    1,      // KVM_HC_MMU_OP
    9,      // KVM_HC_CLOCK_PAIRING
    100,    // Custom/CTF
    101,    // KVM_HC_CHECK_OOB_WRITE_FLAG
    102     // KVM_HC_TRIGGER_HOST_ROPE
};

#ifndef __NR_kvm_hypercall
#define __NR_kvm_hypercall 0x4000
#endif

int main(int argc, char **argv) {
    unsigned long a1 = 0x1337, a2 = 0x42, a3 = 0xdeadbeef, a4 = 0xabadcafe;
    int failures = 0;
    printf("[*] Starting BEAST hypercall sweep...\n");
    for (int i = 0; i < HCALLS_LEN; ++i) {
        unsigned long res = syscall(__NR_kvm_hypercall, hcalls[i], a1, a2, a3, a4);
        printf("[+] Hypercall %d (nr %d): return = 0x%lx (errno: %d: %s)\n", i, hcalls[i], res, errno, strerror(errno));
        if (res == (unsigned long)-1) ++failures;
    }
    // Do one “wild” call with random params
    unsigned long wild = syscall(__NR_kvm_hypercall, rand() % 256, rand(), rand(), rand(), rand());
    printf("[*] Wildcard hypercall: return = 0x%lx (errno: %d: %s)\n", wild, errno, strerror(errno));
    // Exit 0 if any worked, 1 if all failed
    if (failures == HCALLS_LEN + 1)
        return 1;
    return 0;
}
