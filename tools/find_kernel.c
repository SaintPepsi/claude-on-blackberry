/*
 * find_kernel.c — Find boot partition and extract kernel symbol addresses
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o find_kernel find_kernel.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>

/* Read and print /proc/partitions */
static void dump_partitions(void) {
    printf("=== /proc/partitions ===\n");
    FILE *f = fopen("/proc/partitions", "r");
    if (!f) { perror("  fopen partitions"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f)) printf("  %s", line);
    fclose(f);
}

/* List /dev/block/ entries */
static void list_block_devs(void) {
    printf("\n=== /dev/block/ ===\n");
    DIR *d = opendir("/dev/block/");
    if (!d) { perror("  opendir /dev/block/"); return; }
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "/dev/block/%s", ent->d_name);
        char link[512] = {0};
        ssize_t len = readlink(path, link, sizeof(link)-1);
        if (len > 0) {
            link[len] = '\0';
            printf("  %s -> %s\n", ent->d_name, link);
        } else {
            printf("  %s\n", ent->d_name);
        }
    }
    closedir(d);
}

/* List /dev/block/platform/ recursively for by-name */
static void find_by_name(const char *base) {
    DIR *d = opendir(base);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", base, ent->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (strcmp(ent->d_name, "by-name") == 0 ||
                strcmp(ent->d_name, "by-num") == 0) {
                printf("\n=== %s ===\n", path);
                DIR *d2 = opendir(path);
                if (d2) {
                    struct dirent *e2;
                    while ((e2 = readdir(d2))) {
                        if (e2->d_name[0] == '.') continue;
                        char lpath[1536];
                        snprintf(lpath, sizeof(lpath), "%s/%s", path, e2->d_name);
                        char link[512] = {0};
                        ssize_t len = readlink(lpath, link, sizeof(link)-1);
                        if (len > 0) { link[len] = '\0'; printf("  %s -> %s\n", e2->d_name, link); }
                        else printf("  %s\n", e2->d_name);
                    }
                    closedir(d2);
                }
            }
            find_by_name(path);
        }
    }
    closedir(d);
}

/* Try to read first 4KB of a block device to check for kernel magic */
static void probe_boot(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  open %s: %s\n", path, strerror(errno));
        return;
    }
    unsigned char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 0) {
        printf("  read %s: %s\n", path, strerror(errno));
        return;
    }
    printf("  read %s: %zd bytes\n", path, n);

    /* Check for Android boot image magic "ANDROID!" */
    if (n >= 8 && memcmp(buf, "ANDROID!", 8) == 0) {
        printf("  >>> ANDROID BOOT IMAGE FOUND! <<<\n");
        /* Parse boot image header */
        uint32_t kernel_size = *(uint32_t *)(buf + 8);
        uint32_t kernel_addr = *(uint32_t *)(buf + 12);
        uint32_t ramdisk_size = *(uint32_t *)(buf + 16);
        uint32_t ramdisk_addr = *(uint32_t *)(buf + 20);
        uint32_t page_size = *(uint32_t *)(buf + 36);
        printf("  kernel_size=0x%x (%u)\n", kernel_size, kernel_size);
        printf("  kernel_addr=0x%x\n", kernel_addr);
        printf("  ramdisk_size=0x%x (%u)\n", ramdisk_size, ramdisk_size);
        printf("  ramdisk_addr=0x%x\n", ramdisk_addr);
        printf("  page_size=%u\n", page_size);
        /* cmdline at offset 64 */
        buf[64 + 512 - 1] = '\0';
        printf("  cmdline: %.128s\n", buf + 64);
    }

    /* Check for gzip magic (compressed kernel) */
    for (int i = 0; i < n - 1; i++) {
        if (buf[i] == 0x1f && buf[i+1] == 0x8b) {
            printf("  gzip magic at offset %d\n", i);
        }
    }

    /* Print first 64 bytes hex */
    printf("  hex: ");
    for (int i = 0; i < 64 && i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

/* Try to find kernel version string in /proc */
static void kernel_info(void) {
    printf("\n=== Kernel Info ===\n");
    FILE *f;

    f = fopen("/proc/version", "r");
    if (f) { char buf[512]; if (fgets(buf, sizeof(buf), f)) printf("  version: %s", buf); fclose(f); }

    f = fopen("/proc/cmdline", "r");
    if (f) { char buf[1024]; if (fgets(buf, sizeof(buf), f)) printf("  cmdline: %s", buf); fclose(f); }

    /* Check /proc/config.gz existence */
    if (access("/proc/config.gz", R_OK) == 0) printf("  /proc/config.gz: EXISTS\n");
    else printf("  /proc/config.gz: %s\n", strerror(errno));

    /* Check /proc/iomem */
    printf("\n=== /proc/iomem (first 50 lines) ===\n");
    f = fopen("/proc/iomem", "r");
    if (f) {
        char buf[256]; int lines = 0;
        while (fgets(buf, sizeof(buf), f) && lines < 50) { printf("  %s", buf); lines++; }
        fclose(f);
    } else perror("  fopen iomem");
}

/* Scan /sys/class/block for partition info */
static void scan_sys_block(void) {
    printf("\n=== /sys/class/block/ (partitions) ===\n");
    DIR *d = opendir("/sys/class/block/");
    if (!d) { perror("  opendir"); return; }
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        /* Only show partitions with "boot" or numbered partitions */
        char path[512];
        snprintf(path, sizeof(path), "/sys/class/block/%s/size", ent->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            char size[32] = {0};
            if (fgets(size, sizeof(size), f)) {
                unsigned long sectors = strtoul(size, NULL, 10);
                if (sectors > 0) {
                    printf("  %s: %lu sectors (%lu MB)\n", ent->d_name,
                           sectors, sectors * 512 / (1024*1024));
                }
            }
            fclose(f);
        }
    }
    closedir(d);
}

int main(void) {
    printf("=== Boot Partition Finder ===\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    kernel_info();
    dump_partitions();
    list_block_devs();
    find_by_name("/dev/block/platform");
    scan_sys_block();

    /* Try common boot partition paths */
    printf("\n=== Probing Boot Partitions ===\n");
    const char *boot_paths[] = {
        "/dev/block/bootdevice/by-name/boot",
        "/dev/block/platform/soc.0/7824900.sdhci/by-name/boot",
        "/dev/block/platform/msm_sdcc.1/by-name/boot",
        "/dev/block/platform/7824900.sdhci/by-name/boot",
        "/dev/block/platform/f9824900.sdhci/by-name/boot",
        "/dev/block/platform/f9200000.ssusb/by-name/boot",
        "/dev/block/mmcblk0p19",  /* common boot partition */
        "/dev/block/mmcblk0p20",
        "/dev/block/mmcblk0p21",
        "/dev/block/mmcblk0p36",
        "/dev/block/mmcblk0p37",
        "/dev/block/mmcblk0p38",
        NULL
    };
    for (int i = 0; boot_paths[i]; i++) {
        if (access(boot_paths[i], F_OK) == 0) {
            printf("  EXISTS: %s\n", boot_paths[i]);
            probe_boot(boot_paths[i]);
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
