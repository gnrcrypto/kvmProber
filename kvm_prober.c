    # --- USER-SPACE PROBER C CODE (kvm_prober.c) ---
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
