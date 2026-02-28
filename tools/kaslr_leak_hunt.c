/*
 * kaslr_leak_hunt.c — Hunt for kernel address leaks to defeat KASLR
 *
 * Checks every accessible /proc, /sys, dmesg source for kernel pointers.
 * Kernel pointers on ARM64 typically start with 0xffffffc0 or 0xffffff80.
 * On 32-bit ARM kernel, they start with 0xc0.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_LINE 4096

static int leaks_found = 0;

/* Check if a hex value looks like a kernel pointer */
static int is_kernel_ptr(unsigned long long val) {
    /* ARM64 kernel addresses: 0xffffffc000000000 - 0xffffffffffffffff */
    if (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL)
        return 1;
    /* ARM32 kernel addresses: 0xc0000000 - 0xffffffff */
    if (val >= 0xc0000000ULL && val <= 0xffffffffULL && val < 0x100000000ULL)
        return 1;
    return 0;
}

/* Scan a string for hex values that look like kernel pointers */
static void scan_line(const char *source, const char *line) {
    const char *p = line;
    while (*p) {
        /* Look for 0x prefix or standalone hex-looking sequences */
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            char *end;
            unsigned long long val = strtoull(p, &end, 16);
            if (end != p + 2 && is_kernel_ptr(val)) {
                printf("*** LEAK *** %s: %s\n", source, line);
                leaks_found++;
                return; /* One per line is enough */
            }
            p = end;
        } else {
            p++;
        }
    }
}

/* Read and scan a file */
static void scan_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        scan_line(path, line);
    }
    fclose(f);
}

/* Recursively scan a directory */
static void scan_dir(const char *dirpath, int depth) {
    if (depth > 3) return; /* Don't go too deep */

    DIR *d = opendir(dirpath);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);

        struct stat st;
        if (lstat(path, &st) != 0) continue;

        if (S_ISREG(st.st_mode) && (st.st_mode & S_IROTH)) {
            /* Only scan small files to avoid hanging */
            if (st.st_size > 0 && st.st_size < 1048576) {
                scan_file(path);
            }
        } else if (S_ISDIR(st.st_mode) && (st.st_mode & S_IXOTH)) {
            scan_dir(path, depth + 1);
        }
    }
    closedir(d);
}

int main(void) {
    printf("=== KASLR LEAK HUNTER ===\n");
    printf("Scanning for kernel pointers in accessible files...\n\n");

    /* 1. Check specific high-value targets */
    printf("--- High-value targets ---\n");

    /* kallsyms — usually zeroed but worth checking */
    scan_file("/proc/kallsyms");

    /* Various proc files that sometimes leak */
    scan_file("/proc/modules");
    scan_file("/proc/iomem");
    scan_file("/proc/ioports");
    scan_file("/proc/slabinfo");
    scan_file("/proc/vmallocinfo");
    scan_file("/proc/pagetypeinfo");
    scan_file("/proc/timer_list");
    scan_file("/proc/timer_stats");
    scan_file("/proc/sched_debug");
    scan_file("/proc/softirqs");
    scan_file("/proc/interrupts");
    scan_file("/proc/buddyinfo");
    scan_file("/proc/vmstat");
    scan_file("/proc/zoneinfo");
    scan_file("/proc/meminfo");
    scan_file("/proc/net/tcp");
    scan_file("/proc/net/tcp6");
    scan_file("/proc/net/udp");
    scan_file("/proc/net/udp6");
    scan_file("/proc/net/unix");
    scan_file("/proc/net/netlink");
    scan_file("/proc/net/raw");

    /* Process-specific leaks */
    scan_file("/proc/self/maps");
    scan_file("/proc/self/smaps");
    scan_file("/proc/self/status");
    scan_file("/proc/self/wchan");
    scan_file("/proc/self/stack");
    scan_file("/proc/self/syscall");
    scan_file("/proc/self/stat");

    /* dmesg — often has kernel pointers */
    printf("\n--- dmesg scan ---\n");
    {
        FILE *p = popen("dmesg 2>/dev/null", "r");
        if (p) {
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), p)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                scan_line("dmesg", line);
            }
            pclose(p);
        } else {
            printf("dmesg: not accessible\n");
        }
    }

    /* 2. Scan /proc/net/ for socket addresses */
    printf("\n--- /proc/net/ scan ---\n");
    scan_dir("/proc/net", 0);

    /* 3. Scan /sys/kernel/ */
    printf("\n--- /sys/ scan ---\n");
    scan_dir("/sys/kernel", 0);
    scan_dir("/sys/devices", 0);
    scan_dir("/sys/class", 0);

    /* 4. Try to read kptr_restrict setting */
    printf("\n--- Kernel pointer protection ---\n");
    {
        FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "r");
        if (f) {
            char buf[32];
            if (fgets(buf, sizeof(buf), f)) {
                printf("kptr_restrict = %s", buf);
            }
            fclose(f);
        } else {
            printf("kptr_restrict: can't read\n");
        }
    }
    {
        FILE *f = fopen("/proc/sys/kernel/dmesg_restrict", "r");
        if (f) {
            char buf[32];
            if (fgets(buf, sizeof(buf), f)) {
                printf("dmesg_restrict = %s", buf);
            }
            fclose(f);
        } else {
            printf("dmesg_restrict: can't read\n");
        }
    }

    printf("\n=== RESULTS: %d potential kernel pointer leaks found ===\n", leaks_found);
    return leaks_found > 0 ? 0 : 1;
}
