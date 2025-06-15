#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vq_desc_user_data {
    unsigned short index;
    unsigned long long phys_addr;
    unsigned int len;
    unsigned short flags;
    unsigned short next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};
struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buf;
};

// ---- PATCH: VA SCAN/WRITE ----
#define IOCTL_SCAN_VA   0x1010
#define IOCTL_WRITE_VA  0x1011
struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char *user_buffer;
};
struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char *user_buffer;
};
// ---- END PATCH ----

#define IOCTL_READ_PORT         0x1001
#define IOCTL_WRITE_PORT        0x1002
#define IOCTL_READ_MMIO         0x1003
#define IOCTL_WRITE_MMIO        0x1004
#define IOCTL_ALLOC_VQ_PAGE     0x1005
#define IOCTL_FREE_VQ_PAGE      0x1006
#define IOCTL_WRITE_VQ_DESC     0x1007
#define IOCTL_TRIGGER_HYPERCALL 0x1008
#define IOCTL_READ_KERNEL_MEM   0x1009
#define IOCTL_WRITE_KERNEL_MEM  0x100A

void print_usage(char *prog_name) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", prog_name);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  readport <port_hex> <size_bytes (1,2,4)>\n");
    fprintf(stderr, "  writeport <port_hex> <value_hex> <size_bytes (1,2,4)>\n");
    fprintf(stderr, "  readmmio_val <phys_addr_hex> <size_bytes (1,2,4,8)>\n");
    fprintf(stderr, "  writemmio_val <phys_addr_hex> <value_hex> <size_bytes (1,2,4,8)>\n");
    fprintf(stderr, "  readmmio_buf <phys_addr_hex> <num_bytes_to_read>\n");
    fprintf(stderr, "  writemmio_buf <phys_addr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  readkvmem <kaddr_hex> <num_bytes>\n");
    fprintf(stderr, "  writekvmem <kaddr_hex> <hex_string_to_write>\n");
    fprintf(stderr, "  allocvqpage\n");
    fprintf(stderr, "  freevqpage\n");
    fprintf(stderr, "  writevqdesc <idx> <buf_gpa_hex> <buf_len> <flags_hex> <next_idx>\n");
    fprintf(stderr, "  trigger_hypercall\n");
    fprintf(stderr, "  exploit_delay <nanoseconds>\n");
    fprintf(stderr, "  scanmmio <start_addr_hex> <end_addr_hex> <step_bytes>\n");
    fprintf(stderr, "  scanva <va_hex> <num_bytes>\n");
    fprintf(stderr, "  writeva <va_hex> <hex_string_to_write>\n");
}

unsigned char *hex_string_to_bytes(const char *hex_str, unsigned long *num_bytes) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string must have even number of characters.\n");
        return NULL;
    }
    *num_bytes = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(*num_bytes);
    if (!bytes) {
        perror("malloc for hex_string_to_bytes");
        return NULL;
    }
    for (size_t i = 0; i < *num_bytes; ++i) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
            fprintf(stderr, "Invalid hex char in string.\n");
            free(bytes);
            return NULL;
        }
    }
    return bytes;
}

void exploit_delay(int nanoseconds) {
    struct timespec req = {0};
    req.tv_nsec = nanoseconds;
    nanosleep(&req, NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open " DEVICE_PATH ". Is the kernel module loaded?");
        return 1;
    }
    char *cmd = argv[1];

    if (strcmp(cmd, "readport") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.size = (unsigned int)strtoul(argv[3], NULL, 10);
        if (ioctl(fd, IOCTL_READ_PORT, &data) < 0)
            perror("ioctl READ_PORT failed");
        else
            printf("Port 0x%X (size %u) Value: 0x%X (%u)\n", data.port, data.size, data.value, data.value);

    } else if (strcmp(cmd, "writeport") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct port_io_data data;
        data.port = (unsigned short)strtoul(argv[2], NULL, 16);
        data.value = (unsigned int)strtoul(argv[3], NULL, 16);
        data.size = (unsigned int)strtoul(argv[4], NULL, 10);
        if (ioctl(fd, IOCTL_WRITE_PORT, &data) < 0)
            perror("ioctl WRITE_PORT failed");
        else
            printf("Wrote 0x%X to port 0x%X (size %u)\n", data.value, data.port, data.size);

    } else if (strcmp(cmd, "readmmio_val") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[3], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0)
            perror("ioctl READ_MMIO (value) failed");
        else
            printf("MMIO 0x%lX (size %u) Value: 0x%lX (%lu)\n", data.phys_addr, data.value_size, data.single_value, data.single_value);

    } else if (strcmp(cmd, "writemmio_val") == 0) {
        if (argc != 5) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.single_value = strtoul(argv[3], NULL, 16);
        data.value_size = (unsigned int)strtoul(argv[4], NULL, 10);
        data.size = 0;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO (value) failed");
        else
            printf("Wrote 0x%lX to MMIO 0x%lX (size %u)\n", data.single_value, data.phys_addr, data.value_size);

    } else if (strcmp(cmd, "readmmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        data.size = strtoul(argv[3], NULL, 10);
        if (data.size == 0 || data.size > 65536) {
            fprintf(stderr, "Invalid read size for buffer (max 64K).\n");
            close(fd);
            return 1;
        }
        data.user_buffer = (unsigned char*)malloc(data.size);
        if (!data.user_buffer) {
            perror("malloc for read buffer");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0)
            perror("ioctl READ_MMIO (buffer) failed");
        else {
            printf("Read %lu bytes from MMIO 0x%lX:\n", data.size, data.phys_addr);
            for (unsigned long i = 0; i < data.size; ++i) {
                printf("%02X", data.user_buffer[i]);
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n\n[ASCII]:\n");
            for (unsigned long i = 0; i < data.size; ++i) {
                unsigned char c = data.user_buffer[i];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n");
        }
        free(data.user_buffer);

    } else if (strcmp(cmd, "writemmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct mmio_data data = {0};
        data.phys_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        unsigned char *bytes_to_write = hex_string_to_bytes(argv[3], &num_bytes);
        if (!bytes_to_write || num_bytes == 0) {
            fprintf(stderr, "Failed to parse hex string or zero length.\n");
            if (bytes_to_write) free(bytes_to_write);
            close(fd);
            return 1;
        }
        data.user_buffer = bytes_to_write;
        data.size = num_bytes;
        if (ioctl(fd, IOCTL_WRITE_MMIO, &data) < 0)
            perror("ioctl WRITE_MMIO (buffer) failed");
        else
            printf("Wrote %lu bytes to MMIO 0x%lX from hex string.\n", data.size, data.phys_addr);
        free(bytes_to_write);

    } else if (strcmp(cmd, "readkvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct kvm_kernel_mem_read req;
        req.kernel_addr = strtoul(argv[2], NULL, 16);
        req.length = strtoul(argv[3], NULL, 10);
        if (req.length == 0 || req.length > 4096) {
            fprintf(stderr, "Invalid read length (1-4096 supported)\n");
            close(fd); return 1;
        }
        req.user_buf = malloc(req.length);
        if (!req.user_buf) {
            perror("malloc for kernel mem read");
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
            perror("ioctl IOCTL_READ_KERNEL_MEM failed");
        } else {
            printf("Kernel memory @ 0x%lx:\n", req.kernel_addr);
            for (unsigned long i = 0; i < req.length; ++i) {
                printf("%02X", req.user_buf[i]);
                if ((i + 1) % 16 == 0) printf(" ");
                if ((i + 1) % 64 == 0) printf("\n");
            }
            printf("\n[ASCII]:\n");
            for (unsigned long i = 0; i < req.length; ++i)
                printf("%c", (req.user_buf[i] >= 0x20 && req.user_buf[i] < 0x7F) ? req.user_buf[i] : '.');
            printf("\n");
        }
        free(req.user_buf);

    } else if (strcmp(cmd, "writekvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct kvm_kernel_mem_write req;
        req.kernel_addr = strtoul(argv[2], NULL, 16);
        unsigned long num_bytes = 0;
        req.user_buf = hex_string_to_bytes(argv[3], &num_bytes);
        req.length = num_bytes;
        if (!req.user_buf || req.length == 0) {
            fprintf(stderr, "Failed to parse hex string.\n");
            if (req.user_buf) free(req.user_buf);
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0)
            perror("ioctl IOCTL_WRITE_KERNEL_MEM failed");
        else
            printf("Wrote %lu bytes to kernel memory 0x%lX.\n", req.length, req.kernel_addr);
        free(req.user_buf);

    } else if (strcmp(cmd, "allocvqpage") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        unsigned long pfn_returned = 0;
        if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn_returned) < 0) {
            perror("ioctl ALLOC_VQ_PAGE failed");
        } else {
            printf("Allocated VQ page. PFN: 0x%lX\n", pfn_returned);
            printf("Guest Physical Address (approx, if PAGE_SIZE=4096): 0x%lX\n", pfn_returned * 0x1000);
        }

    } else if (strcmp(cmd, "freevqpage") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        if (ioctl(fd, IOCTL_FREE_VQ_PAGE) < 0) {
            perror("ioctl FREE_VQ_PAGE failed");
        } else {
            printf("Sent FREE_VQ_PAGE command.\n");
        }

    } else if (strcmp(cmd, "writevqdesc") == 0) {
        if (argc != 7) { print_usage(argv[0]); close(fd); return 1; }
        struct vq_desc_user_data d_data;
        d_data.index = (unsigned short)strtoul(argv[2], NULL, 10);
        d_data.phys_addr = strtoull(argv[3], NULL, 16);
        d_data.len = (unsigned int)strtoul(argv[4], NULL, 0);
        d_data.flags = (unsigned short)strtoul(argv[5], NULL, 16);
        d_data.next_idx = (unsigned short)strtoul(argv[6], NULL, 10);

        fprintf(stderr, "[Prober: Sending WRITE_VQ_DESC for index %hu: GPA=0x%llx, len=%u, flags=0x%hx, next=%hu]\n",
                d_data.index, d_data.phys_addr, d_data.len, d_data.flags, d_data.next_idx);

        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &d_data) < 0) {
            perror("ioctl IOCTL_WRITE_VQ_DESC failed");
        } else {
            printf("Sent IOCTL_WRITE_VQ_DESC command.\n");
        }

    } else if (strcmp(cmd, "trigger_hypercall") == 0) {
        if (argc != 2) { print_usage(argv[0]); close(fd); return 1; }
        long hypercall_ret = 0;
        if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &hypercall_ret) < 0) {
            perror("ioctl IOCTL_TRIGGER_HYPERCALL failed");
        } else {
            printf("Hypercall triggered, return value: %ld\n", hypercall_ret);
        }

    } else if (strcmp(cmd, "exploit_delay") == 0) {
        if (argc != 3) { print_usage(argv[0]); close(fd); return 1; }
        int delay_ns = atoi(argv[2]);
        exploit_delay(delay_ns);
        printf("Delayed for %d nanoseconds.\n", delay_ns);

    } else if (strcmp(cmd, "scanmmio") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            close(fd);
            return 1;
        }
        unsigned long start = strtoul(argv[2], NULL, 16);
        unsigned long end = strtoul(argv[3], NULL, 16);
        unsigned long step = strtoul(argv[4], NULL, 10);
        struct mmio_data data = {0};
        unsigned char *buf = malloc(step);
        if (!buf) {
            perror("malloc for scanmmio buffer");
            close(fd);
            return 1;
        }
        for (unsigned long addr = start; addr < end; addr += step) {
            memset(buf, 0, step);
            data.phys_addr = addr;
            data.size = step;
            data.user_buffer = buf;
            if (ioctl(fd, IOCTL_READ_MMIO, &data) < 0) {
                printf("MMIO 0x%lX: <read error>\n", addr);
            } else {
                printf("MMIO 0x%lX: ", addr);
                for (unsigned long i = 0; i < step; ++i)
                    printf("%02X", buf[i]);
                printf("\n");
            }
        }
        free(buf);

    // ---- PATCH: VA SCAN/WRITE ----
    } else if (strcmp(cmd, "scanva") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct va_scan_data req = {0};
        req.va = strtoul(argv[2], NULL, 16);
        req.size = strtoul(argv[3], NULL, 10);
        if (req.size == 0) {
            fprintf(stderr, "Invalid size for scanva (must be >0).\n");
            close(fd);
            return 1;
        }
        req.user_buffer = malloc(req.size);
        if (!req.user_buffer) {
            perror("malloc for scanva buffer");
            close(fd);
            return 1;
        }
        if (ioctl(fd, IOCTL_SCAN_VA, &req) < 0) {
            perror("ioctl IOCTL_SCAN_VA failed");
        } else {
            printf("Kernel VA @ 0x%lX:\n", req.va);
            for (unsigned long i = 0; i < req.size; ++i) {
                printf("%02X", req.user_buffer[i]);
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n[ASCII]:\n");
            for (unsigned long i = 0; i < req.size; ++i) {
                unsigned char c = req.user_buffer[i];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
                if ((i+1) % 16 == 0) printf(" ");
            }
            printf("\n");
        }
        free(req.user_buffer);

    } else if (strcmp(cmd, "writeva") == 0) {
        if (argc != 4) { print_usage(argv[0]); close(fd); return 1; }
        struct va_write_data req = {0};
        req.va = strtoul(argv[2], NULL, 16);
        unsigned long nbytes;
        req.user_buffer = hex_string_to_bytes(argv[3], &nbytes);
        req.size = nbytes;
        if (!req.user_buffer || req.size == 0) {
            fprintf(stderr, "Failed to parse hex string for writeva\n");
            if (req.user_buffer) free(req.user_buffer);
            close(fd); return 1;
        }
        if (ioctl(fd, IOCTL_WRITE_VA, &req) < 0)
            perror("ioctl IOCTL_WRITE_VA failed");
        else
            printf("Wrote %lu bytes to VA 0x%lx.\n", req.size, req.va);
        free(req.user_buffer);

    // ---- END PATCH ----

    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
    }
    close(fd);
    return 0;
}