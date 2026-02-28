/*
 * Ralph Wiggum v2 — Structure-Aware KGSL Fuzzer
 * "My cat's breath smells like cat food" -- Ralph Wiggum
 *
 * Targets /dev/kgsl-3d0 (Qualcomm Adreno 418, kernel 3.10.84, Oct 2017 patches)
 * on BlackBerry Priv (Snapdragon 808).
 *
 * v1 was dumb fuzzing — random bytes, generic sizes. Got past the ioctl number
 * gate but not the struct-size gate. v2 uses actual KGSL struct layouts from
 * the msm-3.10 kernel source, correct ioctl encodings, and targeted attack
 * patterns (use-after-free, double-free, race conditions, info leaks).
 *
 * Attack patterns:
 *   1. Context lifecycle: create → use → destroy → use-after-destroy
 *   2. Memory lifecycle: alloc → free → use-after-free, double-free
 *   3. Sync source: create → fence → destroy-while-pending
 *   4. Race conditions: concurrent create/destroy on same IDs
 *   5. Info leaks: check response buffers for kernel addresses
 *   6. Integer overflow: huge sizes, negative values in size fields
 *
 * Compile: gcc -static -O2 -o ralph2 ralph2.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <setjmp.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* ===== ioctl encoding (arm64 Linux) ===== */
#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  8
#define _IOC_SIZESHIFT  16
#define _IOC_DIRSHIFT   30

#define _IOC_NONE    0U
#define _IOC_WRITE   1U
#define _IOC_READ    2U

#define _MY_IOC(dir,type,nr,size) \
    (((dir) << _IOC_DIRSHIFT) | \
     ((type) << _IOC_TYPESHIFT) | \
     ((nr) << _IOC_NRSHIFT) | \
     ((size) << _IOC_SIZESHIFT))

#define _MY_IOW(type,nr,sz)  _MY_IOC(_IOC_WRITE,(type),(nr),(sz))
#define _MY_IOR(type,nr,sz)  _MY_IOC(_IOC_READ,(type),(nr),(sz))
#define _MY_IOWR(type,nr,sz) _MY_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(sz))

#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOC_TYPE 0x09

/* ===== KGSL structs (from msm_kgsl.h, arm64 sizes) ===== */

/* nr=0x13: DRAWCTXT_CREATE — _IOWR, 8 bytes */
struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;    /* out */
};
#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _MY_IOWR(KGSL_IOC_TYPE, 0x13, sizeof(struct kgsl_drawctxt_create))

/* nr=0x14: DRAWCTXT_DESTROY — _IOW, 4 bytes */
struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};
#define IOCTL_KGSL_DRAWCTXT_DESTROY \
    _MY_IOW(KGSL_IOC_TYPE, 0x14, sizeof(struct kgsl_drawctxt_destroy))

/* nr=0x2f: GPUMEM_ALLOC — _IOWR */
struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;      /* out */
    size_t size;                /* in */
    unsigned int flags;         /* in */
};
#define IOCTL_KGSL_GPUMEM_ALLOC \
    _MY_IOWR(KGSL_IOC_TYPE, 0x2f, sizeof(struct kgsl_gpumem_alloc))

/* nr=0x34: GPUMEM_ALLOC_ID — _IOWR */
struct kgsl_gpumem_alloc_id {
    unsigned int id;            /* out */
    unsigned int flags;         /* in/out */
    size_t size;                /* in/out */
    size_t mmapsize;            /* out */
    unsigned long gpuaddr;      /* out */
    unsigned long __pad[2];
};
#define IOCTL_KGSL_GPUMEM_ALLOC_ID \
    _MY_IOWR(KGSL_IOC_TYPE, 0x34, sizeof(struct kgsl_gpumem_alloc_id))

/* nr=0x35: GPUMEM_FREE_ID — _IOWR, 8 bytes */
struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};
#define IOCTL_KGSL_GPUMEM_FREE_ID \
    _MY_IOWR(KGSL_IOC_TYPE, 0x35, sizeof(struct kgsl_gpumem_free_id))

/* nr=0x36: GPUMEM_GET_INFO — _IOWR */
struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;
    unsigned int id;
    unsigned int flags;         /* out */
    size_t size;                /* out */
    size_t mmapsize;            /* out */
    unsigned long useraddr;     /* out */
    unsigned long __pad[4];
};
#define IOCTL_KGSL_GPUMEM_GET_INFO \
    _MY_IOWR(KGSL_IOC_TYPE, 0x36, sizeof(struct kgsl_gpumem_get_info))

/* nr=0x21: SHAREDMEM_FREE — _IOW */
struct kgsl_sharedmem_free {
    unsigned long gpuaddr;
};
#define IOCTL_KGSL_SHAREDMEM_FREE \
    _MY_IOW(KGSL_IOC_TYPE, 0x21, sizeof(struct kgsl_sharedmem_free))

/* nr=0x10: RINGBUFFER_ISSUEIBCMDS — _IOWR */
struct kgsl_ringbuffer_issueibcmds {
    unsigned int drawctxt_id;
    unsigned long ibdesc_addr;
    unsigned int numibs;
    unsigned int timestamp;     /* out */
    unsigned int flags;
};
#define IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS \
    _MY_IOWR(KGSL_IOC_TYPE, 0x10, sizeof(struct kgsl_ringbuffer_issueibcmds))

/* nr=0x40: SYNCSOURCE_CREATE — _IOWR */
struct kgsl_syncsource_create {
    unsigned int id;            /* out */
};
#define IOCTL_KGSL_SYNCSOURCE_CREATE \
    _MY_IOWR(KGSL_IOC_TYPE, 0x40, sizeof(struct kgsl_syncsource_create))

/* nr=0x41: SYNCSOURCE_DESTROY — _IOWR */
struct kgsl_syncsource_destroy {
    unsigned int id;
};
#define IOCTL_KGSL_SYNCSOURCE_DESTROY \
    _MY_IOWR(KGSL_IOC_TYPE, 0x41, sizeof(struct kgsl_syncsource_destroy))

/* nr=0x42: SYNCSOURCE_CREATE_FENCE — _IOWR */
struct kgsl_syncsource_create_fence {
    unsigned int id;            /* in: syncsource id */
    int fence_fd;               /* out */
};
#define IOCTL_KGSL_SYNCSOURCE_CREATE_FENCE \
    _MY_IOWR(KGSL_IOC_TYPE, 0x42, sizeof(struct kgsl_syncsource_create_fence))

/* nr=0x43: SYNCSOURCE_SIGNAL_FENCE — _IOWR */
struct kgsl_syncsource_signal_fence {
    unsigned int id;            /* in: syncsource id */
    int fence_fd;               /* in: fence to signal */
};
#define IOCTL_KGSL_SYNCSOURCE_SIGNAL_FENCE \
    _MY_IOWR(KGSL_IOC_TYPE, 0x43, sizeof(struct kgsl_syncsource_signal_fence))

/* nr=0x33: TIMESTAMP_EVENT — _IOWR */
struct kgsl_timestamp_event {
    int type;
    unsigned int timestamp;
    unsigned int context_id;
    void *priv;
    size_t len;
};
#define IOCTL_KGSL_TIMESTAMP_EVENT \
    _MY_IOWR(KGSL_IOC_TYPE, 0x33, sizeof(struct kgsl_timestamp_event))

/* nr=0x32: SETPROPERTY — _IOW */
struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    size_t sizebytes;
};
#define IOCTL_KGSL_SETPROPERTY \
    _MY_IOW(KGSL_IOC_TYPE, 0x32, sizeof(struct kgsl_device_getproperty))

/* nr=0x02: GETPROPERTY — _IOWR */
#define IOCTL_KGSL_DEVICE_GETPROPERTY \
    _MY_IOWR(KGSL_IOC_TYPE, 0x02, sizeof(struct kgsl_device_getproperty))

/* nr=0x3a: PERFCOUNTER_QUERY — _IOWR (adreno) */
struct kgsl_perfcounter_query {
    unsigned int groupid;
    unsigned int *countables;   /* user pointer */
    unsigned int count;
    unsigned int max_counters;  /* out */
    unsigned int __pad[2];
};
#define IOCTL_KGSL_PERFCOUNTER_QUERY \
    _MY_IOWR(KGSL_IOC_TYPE, 0x3a, sizeof(struct kgsl_perfcounter_query))

/* nr=0x38: PERFCOUNTER_GET — _IOWR (adreno) */
struct kgsl_perfcounter_get {
    unsigned int groupid;
    unsigned int countable;
    unsigned int offset;        /* out */
    unsigned int offset_hi;     /* out */
    unsigned int __pad;
};
#define IOCTL_KGSL_PERFCOUNTER_GET \
    _MY_IOWR(KGSL_IOC_TYPE, 0x38, sizeof(struct kgsl_perfcounter_get))

/* GPUOBJ ioctls (may not exist on this kernel — nr=0x45-0x4C) */
struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;          /* out */
    unsigned int id;            /* out */
    unsigned int metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC \
    _MY_IOWR(KGSL_IOC_TYPE, 0x45, sizeof(struct kgsl_gpuobj_alloc))

struct kgsl_gpuobj_free {
    uint64_t flags;
    unsigned int id;
    unsigned int type;
};
#define IOCTL_KGSL_GPUOBJ_FREE \
    _MY_IOW(KGSL_IOC_TYPE, 0x46, sizeof(struct kgsl_gpuobj_free))

struct kgsl_gpuobj_info {
    uint64_t gpuaddr;           /* out */
    uint64_t flags;             /* out */
    uint64_t size;              /* out */
    uint64_t va_len;            /* out */
    uint64_t va_addr;           /* out */
    unsigned int id;            /* in */
};
#define IOCTL_KGSL_GPUOBJ_INFO \
    _MY_IOWR(KGSL_IOC_TYPE, 0x47, sizeof(struct kgsl_gpuobj_info))

struct kgsl_gpuobj_set_info {
    uint64_t flags;
    uint64_t metadata;
    unsigned int id;
    unsigned int metadata_len;
    unsigned int type;
};
#define IOCTL_KGSL_GPUOBJ_SET_INFO \
    _MY_IOW(KGSL_IOC_TYPE, 0x4C, sizeof(struct kgsl_gpuobj_set_info))

/* ===== Context flags ===== */
#define KGSL_CONTEXT_SUBMIT_IB_LIST      0x00000004
#define KGSL_CONTEXT_PER_CONTEXT_TS      0x00000040
#define KGSL_CONTEXT_TYPE_GL             (1 << 20)
#define KGSL_CONTEXT_TYPE_CL             (2 << 20)

/* ===== Memory flags ===== */
#define KGSL_MEMFLAGS_GPUREADONLY     0x01000000U

/* ===== Property types ===== */
#define KGSL_PROP_DEVICE_INFO     0x1
#define KGSL_PROP_VERSION         0x8

/* ===== Signal recovery ===== */
static sigjmp_buf jmp;
static volatile sig_atomic_t caught_sig = 0;

static void sighandler(int sig) {
    caught_sig = sig;
    siglongjmp(jmp, sig);
}

/* ===== xorshift64 PRNG ===== */
static unsigned long long rng;

static unsigned long long rand64(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

/* ===== Logging ===== */
static FILE *logfp;

static void lg(const char *test, const char *tag, int ret, int err,
               const char *detail) {
    fprintf(logfp, "%s | ret=%d err=%d(%s) | %s | %s\n",
            test, ret, err, strerror(err), tag, detail);
    fflush(logfp);
    printf("%s | ret=%d err=%s | %s | %s\n",
           test, ret, strerror(err), tag, detail);
}

/* ===== Pointer leak check ===== */
static int check_leak(const void *buf, size_t len, const char *label) {
    const uint64_t *p = (const uint64_t *)buf;
    int found = 0;
    size_t i;
    for (i = 0; i < len / 8; i++) {
        uint64_t v = p[i];
        if (v == 0 || v == (uint64_t)-1) continue;
        /* Kernel address range on arm64: 0xffffffc0_00000000 - 0xffffffff_ffffffff */
        if ((v >> 32) >= 0xffffffc0ULL) {
            printf("!! KERNEL LEAK in %s: offset %zu = 0x%016llx\n",
                   label, i*8, (unsigned long long)v);
            fprintf(logfp, "!! KERNEL LEAK in %s: offset %zu = 0x%016llx\n",
                    label, i*8, (unsigned long long)v);
            found++;
        }
        /* Also check for kernel text range */
        if (v >= 0xffffffc000000000ULL && v <= 0xffffffc0FFFFFFFFULL) {
            printf("!! KERNEL TEXT LEAK in %s: offset %zu = 0x%016llx\n",
                   label, i*8, (unsigned long long)v);
            found++;
        }
    }
    return found;
}

/* ===== Safe ioctl wrapper ===== */
static int safe_ioctl(int fd, unsigned long cmd, void *arg, const char *name) {
    int ret;
    caught_sig = 0;
    if (sigsetjmp(jmp, 1) == 0) {
        errno = 0;
        ret = ioctl(fd, cmd, arg);
        return ret;
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "!! CRASH sig=%d !! POTENTIAL EXPLOIT VECTOR", caught_sig);
        lg(name, msg, -1, 0, "SIGNAL CAUGHT");
        return -999;
    }
}

/* ===== Reopen device ===== */
static int reopen(void) {
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0)
        printf("!! reopen failed: %s\n", strerror(errno));
    return fd;
}

/* ===== Race condition thread data ===== */
struct race_data {
    int fd;
    volatile int running;
    volatile int crashes;
    unsigned int target_id;
    int test_type;  /* 0=ctx create/destroy, 1=mem alloc/free, 2=sync create/destroy */
};

static void *race_thread(void *arg) {
    struct race_data *rd = (struct race_data *)arg;
    int ret;
    unsigned int i = 0;

    while (rd->running) {
        caught_sig = 0;
        if (sigsetjmp(jmp, 1) != 0) {
            rd->crashes++;
            printf("!! RACE CRASH sig=%d in thread !!\n", caught_sig);
            rd->fd = reopen();
            if (rd->fd < 0) { rd->running = 0; break; }
            continue;
        }

        errno = 0;
        switch (rd->test_type) {
        case 0: { /* context destroy race */
            struct kgsl_drawctxt_destroy d;
            d.drawctxt_id = rd->target_id;
            ret = ioctl(rd->fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d);
            if (ret == 0) {
                printf("RACE: thread destroyed ctx %u\n", rd->target_id);
            }
            break;
        }
        case 1: { /* memory free race */
            struct kgsl_gpumem_free_id f;
            f.id = rd->target_id;
            f.__pad = 0;
            ret = ioctl(rd->fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f);
            if (ret == 0) {
                printf("RACE: thread freed mem %u\n", rd->target_id);
            }
            break;
        }
        case 2: { /* syncsource destroy race */
            struct kgsl_syncsource_destroy d;
            d.id = rd->target_id;
            ret = ioctl(rd->fd, IOCTL_KGSL_SYNCSOURCE_DESTROY, &d);
            if (ret == 0) {
                printf("RACE: thread destroyed sync %u\n", rd->target_id);
            }
            break;
        }
        }
        i++;
    }
    return NULL;
}

/* ===== TEST FUNCTIONS ===== */

/* Test A: Probe ioctls with correct struct sizes */
static void test_probe(int fd) {
    printf("\n=== TEST A: STRUCT-SIZE PROBE ===\n");
    fprintf(logfp, "\n=== TEST A: STRUCT-SIZE PROBE ===\n");

    struct {
        const char *name;
        unsigned long cmd;
        size_t size;
    } probes[] = {
        {"DRAWCTXT_CREATE",    IOCTL_KGSL_DRAWCTXT_CREATE,   sizeof(struct kgsl_drawctxt_create)},
        {"DRAWCTXT_DESTROY",   IOCTL_KGSL_DRAWCTXT_DESTROY,  sizeof(struct kgsl_drawctxt_destroy)},
        {"GPUMEM_ALLOC",       IOCTL_KGSL_GPUMEM_ALLOC,      sizeof(struct kgsl_gpumem_alloc)},
        {"GPUMEM_ALLOC_ID",    IOCTL_KGSL_GPUMEM_ALLOC_ID,   sizeof(struct kgsl_gpumem_alloc_id)},
        {"GPUMEM_FREE_ID",     IOCTL_KGSL_GPUMEM_FREE_ID,    sizeof(struct kgsl_gpumem_free_id)},
        {"GPUMEM_GET_INFO",    IOCTL_KGSL_GPUMEM_GET_INFO,   sizeof(struct kgsl_gpumem_get_info)},
        {"SHAREDMEM_FREE",     IOCTL_KGSL_SHAREDMEM_FREE,    sizeof(struct kgsl_sharedmem_free)},
        {"SYNCSOURCE_CREATE",  IOCTL_KGSL_SYNCSOURCE_CREATE,  sizeof(struct kgsl_syncsource_create)},
        {"SYNCSOURCE_DESTROY", IOCTL_KGSL_SYNCSOURCE_DESTROY, sizeof(struct kgsl_syncsource_destroy)},
        {"SYNCSOURCE_CREATE_FENCE", IOCTL_KGSL_SYNCSOURCE_CREATE_FENCE, sizeof(struct kgsl_syncsource_create_fence)},
        {"SYNCSOURCE_SIGNAL_FENCE", IOCTL_KGSL_SYNCSOURCE_SIGNAL_FENCE, sizeof(struct kgsl_syncsource_signal_fence)},
        {"TIMESTAMP_EVENT",    IOCTL_KGSL_TIMESTAMP_EVENT,    sizeof(struct kgsl_timestamp_event)},
        {"SETPROPERTY",        IOCTL_KGSL_SETPROPERTY,        sizeof(struct kgsl_device_getproperty)},
        {"GETPROPERTY",        IOCTL_KGSL_DEVICE_GETPROPERTY, sizeof(struct kgsl_device_getproperty)},
        {"PERFCOUNTER_QUERY",  IOCTL_KGSL_PERFCOUNTER_QUERY,  sizeof(struct kgsl_perfcounter_query)},
        {"PERFCOUNTER_GET",    IOCTL_KGSL_PERFCOUNTER_GET,    sizeof(struct kgsl_perfcounter_get)},
        {"ISSUEIBCMDS",        IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS, sizeof(struct kgsl_ringbuffer_issueibcmds)},
        {"GPUOBJ_ALLOC",       IOCTL_KGSL_GPUOBJ_ALLOC,      sizeof(struct kgsl_gpuobj_alloc)},
        {"GPUOBJ_FREE",        IOCTL_KGSL_GPUOBJ_FREE,       sizeof(struct kgsl_gpuobj_free)},
        {"GPUOBJ_INFO",        IOCTL_KGSL_GPUOBJ_INFO,       sizeof(struct kgsl_gpuobj_info)},
        {"GPUOBJ_SET_INFO",    IOCTL_KGSL_GPUOBJ_SET_INFO,   sizeof(struct kgsl_gpuobj_set_info)},
    };
    int nprobes = sizeof(probes) / sizeof(probes[0]);
    unsigned char buf[256];
    int i;

    for (i = 0; i < nprobes; i++) {
        memset(buf, 0, sizeof(buf));
        int ret = safe_ioctl(fd, probes[i].cmd, buf, probes[i].name);
        char detail[128];
        const char *tag;
        if (ret == -999) {
            tag = "!! CRASH !!";
            fd = reopen();
            if (fd < 0) return;
        } else if (ret == 0) {
            tag = "** ACCEPTED **";
        } else if (errno == ENOTTY) {
            tag = "NOT SUPPORTED";
        } else {
            tag = "RECOGNIZED";
        }
        snprintf(detail, sizeof(detail), "cmd=0x%08lx sz=%zu",
                 probes[i].cmd, probes[i].size);
        lg("PROBE", tag, ret, errno, detail);

        /* Check for info leaks in response */
        if (ret == 0) {
            check_leak(buf, probes[i].size, probes[i].name);
        }
    }
}

/* Test B: Context lifecycle and use-after-destroy */
static void test_context(int fd) {
    printf("\n=== TEST B: CONTEXT LIFECYCLE ===\n");
    fprintf(logfp, "\n=== TEST B: CONTEXT LIFECYCLE ===\n");

    struct kgsl_drawctxt_create c;
    struct kgsl_drawctxt_destroy d;
    int ret;
    unsigned int ctx_ids[64];
    int n_ctx = 0;
    unsigned int flags_to_try[] = {
        0,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS,
        KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PER_CONTEXT_TS,
        KGSL_CONTEXT_TYPE_CL,
        0xFFFFFFFF,
        0x80000000,
        0x7FFFFFFF,
    };
    int nflags = sizeof(flags_to_try) / sizeof(flags_to_try[0]);
    int i;

    /* Create contexts with various flags */
    for (i = 0; i < nflags && n_ctx < 64; i++) {
        memset(&c, 0, sizeof(c));
        c.flags = flags_to_try[i];
        ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c, "CTX_CREATE");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        char detail[128];
        snprintf(detail, sizeof(detail), "flags=0x%08x ctx_id=%u", flags_to_try[i], c.drawctxt_id);
        if (ret == 0) {
            lg("CTX", "** CREATED **", ret, errno, detail);
            ctx_ids[n_ctx++] = c.drawctxt_id;
        } else {
            lg("CTX", "create failed", ret, errno, detail);
        }
    }

    printf("Created %d contexts\n", n_ctx);

    if (n_ctx == 0) {
        printf("No contexts created, skipping lifecycle tests\n");
        return;
    }

    /* Destroy first context */
    d.drawctxt_id = ctx_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "CTX_DESTROY");
    if (ret == -999) { fd = reopen(); if (fd < 0) return; }
    char detail[128];
    snprintf(detail, sizeof(detail), "ctx_id=%u", ctx_ids[0]);
    lg("CTX", ret == 0 ? "** DESTROYED **" : "destroy failed", ret, errno, detail);

    /* USE-AFTER-DESTROY: try to use the destroyed context */
    printf("\n--- Use-after-destroy test ---\n");

    /* Try to destroy again (double-destroy) */
    d.drawctxt_id = ctx_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "CTX_DOUBLE_DESTROY");
    if (ret == -999) {
        lg("CTX_UAD", "!! CRASH ON DOUBLE-DESTROY !!", -1, 0, detail);
        fd = reopen();
        if (fd < 0) return;
    } else {
        lg("CTX_UAD", ret == 0 ? "!! DOUBLE-DESTROY ACCEPTED !!" : "rejected (safe)",
           ret, errno, detail);
    }

    /* Try to issue commands with destroyed context */
    struct kgsl_ringbuffer_issueibcmds ib;
    memset(&ib, 0, sizeof(ib));
    ib.drawctxt_id = ctx_ids[0];
    ib.flags = KGSL_CONTEXT_SUBMIT_IB_LIST;
    ret = safe_ioctl(fd, IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS, &ib, "IB_DESTROYED_CTX");
    if (ret == -999) {
        lg("CTX_UAD", "!! CRASH ON ISSUEIB WITH DESTROYED CTX !!", -1, 0, "");
        fd = reopen();
        if (fd < 0) return;
    } else {
        lg("CTX_UAD", ret == 0 ? "!! ACCEPTED WITH DESTROYED CTX !!" : "rejected (safe)",
           ret, errno, detail);
    }

    /* Try timestamp event with destroyed context */
    struct kgsl_timestamp_event te;
    memset(&te, 0, sizeof(te));
    te.type = 2; /* FENCE */
    te.context_id = ctx_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_TIMESTAMP_EVENT, &te, "TIMESTAMP_DESTROYED_CTX");
    if (ret == -999) {
        lg("CTX_UAD", "!! CRASH ON TIMESTAMP WITH DESTROYED CTX !!", -1, 0, "");
        fd = reopen();
        if (fd < 0) return;
    }

    /* Cleanup: destroy remaining contexts */
    for (i = 1; i < n_ctx; i++) {
        d.drawctxt_id = ctx_ids[i];
        safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "CTX_CLEANUP");
    }
}

/* Test C: Memory allocation and use-after-free */
static void test_memory(int fd) {
    printf("\n=== TEST C: MEMORY LIFECYCLE ===\n");
    fprintf(logfp, "\n=== TEST C: MEMORY LIFECYCLE ===\n");

    int ret;
    unsigned int alloc_ids[32];
    unsigned long alloc_addrs[32];
    int n_alloc = 0;

    /* Try GPUMEM_ALLOC_ID with various sizes */
    size_t sizes_to_try[] = {4096, 8192, 65536, 0x100000, 1, 0};
    int nsizes = sizeof(sizes_to_try) / sizeof(sizes_to_try[0]);
    int i;

    for (i = 0; i < nsizes && n_alloc < 32; i++) {
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = sizes_to_try[i];
        a.flags = 0;
        ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a, "GPUMEM_ALLOC_ID");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "size=%zu id=%u gpuaddr=0x%lx flags=0x%x mmapsize=%zu",
                 sizes_to_try[i], a.id, a.gpuaddr, a.flags, a.mmapsize);
        if (ret == 0) {
            lg("MEM", "** ALLOCATED **", ret, errno, detail);
            alloc_ids[n_alloc] = a.id;
            alloc_addrs[n_alloc] = a.gpuaddr;
            n_alloc++;
            /* Check for kernel address leaks in response */
            check_leak(&a, sizeof(a), "GPUMEM_ALLOC_ID response");
        } else {
            lg("MEM", "alloc failed", ret, errno, detail);
        }
    }

    /* Also try GPUMEM_ALLOC (older API) */
    struct kgsl_gpumem_alloc ga;
    memset(&ga, 0, sizeof(ga));
    ga.size = 4096;
    ga.flags = 0;
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC, &ga, "GPUMEM_ALLOC");
    if (ret == 0) {
        char detail[128];
        snprintf(detail, sizeof(detail), "gpuaddr=0x%lx size=%zu",
                 ga.gpuaddr, ga.size);
        lg("MEM", "** ALLOC (old API) **", ret, errno, detail);
        check_leak(&ga, sizeof(ga), "GPUMEM_ALLOC response");
    } else if (ret != -999) {
        lg("MEM", "old alloc failed", ret, errno, "");
    }

    /* Also try GPUOBJ_ALLOC (newer API, may not exist) */
    struct kgsl_gpuobj_alloc oa;
    memset(&oa, 0, sizeof(oa));
    oa.size = 4096;
    oa.flags = 0;
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &oa, "GPUOBJ_ALLOC");
    if (ret == 0) {
        char detail[128];
        snprintf(detail, sizeof(detail), "id=%u mmapsize=%llu", oa.id, (unsigned long long)oa.mmapsize);
        lg("MEM", "** GPUOBJ ALLOC **", ret, errno, detail);
    } else if (ret != -999) {
        if (errno == ENOTTY) {
            lg("MEM", "GPUOBJ_ALLOC not supported on this kernel", ret, errno, "");
        } else {
            lg("MEM", "GPUOBJ alloc failed", ret, errno, "");
        }
    }

    printf("Allocated %d GPU memory objects\n", n_alloc);

    if (n_alloc == 0) {
        printf("No allocations succeeded, skipping UAF tests\n");
        return;
    }

    /* GET_INFO on first allocation — check for kernel address leak */
    struct kgsl_gpumem_get_info gi;
    memset(&gi, 0, sizeof(gi));
    gi.id = alloc_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_GET_INFO, &gi, "GPUMEM_GET_INFO");
    if (ret == 0) {
        char detail[256];
        snprintf(detail, sizeof(detail),
                 "id=%u gpuaddr=0x%lx size=%zu mmapsize=%zu useraddr=0x%lx flags=0x%x",
                 gi.id, gi.gpuaddr, gi.size, gi.mmapsize, gi.useraddr, gi.flags);
        lg("MEM", "** GET_INFO **", ret, errno, detail);
        int leaks = check_leak(&gi, sizeof(gi), "GPUMEM_GET_INFO response");
        if (leaks > 0) {
            printf("!!! FOUND %d KERNEL ADDRESS LEAKS !!!\n", leaks);
        }
    }

    /* Free first allocation */
    struct kgsl_gpumem_free_id f;
    f.id = alloc_ids[0];
    f.__pad = 0;
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "GPUMEM_FREE");
    char detail[128];
    snprintf(detail, sizeof(detail), "id=%u", alloc_ids[0]);
    if (ret == -999) {
        fd = reopen();
        if (fd < 0) return;
    } else {
        lg("MEM", ret == 0 ? "** FREED **" : "free failed", ret, errno, detail);
    }

    /* USE-AFTER-FREE: get info on freed memory */
    printf("\n--- Use-after-free test ---\n");
    memset(&gi, 0, sizeof(gi));
    gi.id = alloc_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_GET_INFO, &gi, "GET_INFO_FREED");
    if (ret == -999) {
        lg("MEM_UAF", "!! CRASH ON GET_INFO AFTER FREE !!", -1, 0, detail);
        fd = reopen();
        if (fd < 0) return;
    } else if (ret == 0) {
        lg("MEM_UAF", "!! GET_INFO SUCCEEDED ON FREED MEM !!", ret, errno, detail);
        check_leak(&gi, sizeof(gi), "UAF GET_INFO response");
    } else {
        lg("MEM_UAF", "rejected (safe)", ret, errno, detail);
    }

    /* DOUBLE-FREE: free again */
    f.id = alloc_ids[0];
    f.__pad = 0;
    ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "GPUMEM_DOUBLE_FREE");
    if (ret == -999) {
        lg("MEM_UAF", "!! CRASH ON DOUBLE-FREE !!", -1, 0, detail);
        fd = reopen();
        if (fd < 0) return;
    } else {
        lg("MEM_UAF", ret == 0 ? "!! DOUBLE-FREE ACCEPTED !!" : "rejected (safe)",
           ret, errno, detail);
    }

    /* Try SHAREDMEM_FREE with the gpuaddr of freed memory */
    if (alloc_addrs[0]) {
        struct kgsl_sharedmem_free sf;
        sf.gpuaddr = alloc_addrs[0];
        ret = safe_ioctl(fd, IOCTL_KGSL_SHAREDMEM_FREE, &sf, "SHAREDMEM_FREE_FREED");
        if (ret == -999) {
            lg("MEM_UAF", "!! CRASH ON SHAREDMEM_FREE OF FREED !!", -1, 0, "");
            fd = reopen();
            if (fd < 0) return;
        } else {
            lg("MEM_UAF", ret == 0 ? "!! SHAREDMEM_FREE ACCEPTED ON FREED !!" : "rejected",
               ret, errno, "");
        }
    }

    /* Integer overflow: try to allocate huge memory */
    printf("\n--- Integer overflow tests ---\n");
    size_t overflow_sizes[] = {
        (size_t)-1,
        (size_t)-4096,
        0x7FFFFFFFFFFFFFFFULL,
        0x8000000000000000ULL,
        0xFFFFFFFF,
        0x100000000ULL,
    };
    int novsz = sizeof(overflow_sizes) / sizeof(overflow_sizes[0]);
    for (i = 0; i < novsz; i++) {
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = overflow_sizes[i];
        ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a, "ALLOC_OVERFLOW");
        if (ret == -999) {
            char d2[64];
            snprintf(d2, sizeof(d2), "size=0x%llx", (unsigned long long)overflow_sizes[i]);
            lg("OVERFLOW", "!! CRASH ON HUGE SIZE !!", -1, 0, d2);
            fd = reopen();
            if (fd < 0) return;
        } else if (ret == 0) {
            char d2[128];
            snprintf(d2, sizeof(d2), "!! HUGE ALLOC ACCEPTED !! size=0x%llx id=%u",
                     (unsigned long long)overflow_sizes[i], a.id);
            lg("OVERFLOW", d2, ret, errno, "");
            /* Free it */
            f.id = a.id;
            safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "FREE_OVERFLOW");
        }
    }

    /* Cleanup remaining allocations */
    for (i = 1; i < n_alloc; i++) {
        f.id = alloc_ids[i];
        f.__pad = 0;
        safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "MEM_CLEANUP");
    }
}

/* Test D: Sync source lifecycle and race */
static void test_sync(int fd) {
    printf("\n=== TEST D: SYNC SOURCE LIFECYCLE ===\n");
    fprintf(logfp, "\n=== TEST D: SYNC SOURCE LIFECYCLE ===\n");

    int ret;
    unsigned int sync_ids[16];
    int n_sync = 0;
    int i;

    /* Create sync sources */
    for (i = 0; i < 8; i++) {
        struct kgsl_syncsource_create sc;
        memset(&sc, 0, sizeof(sc));
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_CREATE, &sc, "SYNC_CREATE");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        if (ret == 0) {
            char detail[64];
            snprintf(detail, sizeof(detail), "sync_id=%u", sc.id);
            lg("SYNC", "** CREATED **", ret, errno, detail);
            sync_ids[n_sync++] = sc.id;
        }
    }

    printf("Created %d sync sources\n", n_sync);

    if (n_sync == 0) {
        printf("No sync sources created, skipping\n");
        return;
    }

    /* Create a fence from the first sync source */
    struct kgsl_syncsource_create_fence cf;
    memset(&cf, 0, sizeof(cf));
    cf.id = sync_ids[0];
    ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_CREATE_FENCE, &cf, "FENCE_CREATE");
    if (ret == 0) {
        char detail[64];
        snprintf(detail, sizeof(detail), "sync_id=%u fence_fd=%d", sync_ids[0], cf.fence_fd);
        lg("SYNC", "** FENCE CREATED **", ret, errno, detail);

        /* Destroy sync source while fence is live (UAF opportunity) */
        struct kgsl_syncsource_destroy sd;
        sd.id = sync_ids[0];
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_DESTROY, &sd, "DESTROY_WITH_FENCE");
        if (ret == -999) {
            lg("SYNC_UAF", "!! CRASH DESTROYING SOURCE WITH LIVE FENCE !!", -1, 0, "");
            fd = reopen();
            if (fd < 0) return;
        } else {
            lg("SYNC_UAF",
               ret == 0 ? "!! DESTROYED WITH LIVE FENCE !!" : "rejected (safe)",
               ret, errno, "");
        }

        /* Try to signal the fence on the destroyed source */
        struct kgsl_syncsource_signal_fence sf;
        sf.id = sync_ids[0];
        sf.fence_fd = cf.fence_fd;
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_SIGNAL_FENCE, &sf, "SIGNAL_DESTROYED");
        if (ret == -999) {
            lg("SYNC_UAF", "!! CRASH SIGNALING ON DESTROYED SOURCE !!", -1, 0, "");
            fd = reopen();
            if (fd < 0) return;
        } else {
            lg("SYNC_UAF",
               ret == 0 ? "!! SIGNAL ACCEPTED ON DESTROYED SOURCE !!" : "rejected",
               ret, errno, "");
        }

        /* Close fence fd */
        if (cf.fence_fd >= 0)
            close(cf.fence_fd);
    } else if (ret != -999) {
        lg("SYNC", "fence create failed", ret, errno, "");
    }

    /* Double destroy */
    if (n_sync > 0) {
        struct kgsl_syncsource_destroy sd;
        sd.id = sync_ids[0];
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_DESTROY, &sd, "SYNC_DOUBLE_DESTROY");
        if (ret == -999) {
            lg("SYNC_UAF", "!! CRASH ON DOUBLE-DESTROY !!", -1, 0, "");
            fd = reopen();
            if (fd < 0) return;
        } else {
            lg("SYNC_UAF",
               ret == 0 ? "!! DOUBLE-DESTROY ACCEPTED !!" : "rejected (safe)",
               ret, errno, "");
        }
    }

    /* Cleanup */
    for (i = 1; i < n_sync; i++) {
        struct kgsl_syncsource_destroy sd;
        sd.id = sync_ids[i];
        safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_DESTROY, &sd, "SYNC_CLEANUP");
    }
}

/* Test E: Info leak hunting */
static void test_info_leaks(int fd) {
    printf("\n=== TEST E: INFO LEAK HUNTING ===\n");
    fprintf(logfp, "\n=== TEST E: INFO LEAK HUNTING ===\n");

    int ret;

    /* GETPROPERTY — try various property types */
    unsigned int props[] = {
        KGSL_PROP_DEVICE_INFO, KGSL_PROP_VERSION,
        0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x9, 0xE, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    };
    int nprops = sizeof(props) / sizeof(props[0]);
    unsigned char valbuf[256];
    int i;

    for (i = 0; i < nprops; i++) {
        memset(valbuf, 0, sizeof(valbuf));
        struct kgsl_device_getproperty gp;
        gp.type = props[i];
        gp.value = valbuf;
        gp.sizebytes = sizeof(valbuf);

        ret = safe_ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &gp, "GETPROPERTY");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        char detail[128];
        snprintf(detail, sizeof(detail), "prop=0x%x", props[i]);
        if (ret == 0) {
            lg("LEAK", "** PROPERTY READ **", ret, errno, detail);
            int leaks = check_leak(valbuf, sizeof(valbuf), detail);
            if (leaks > 0) {
                printf("!!! %d KERNEL LEAKS IN PROPERTY 0x%x !!!\n", leaks, props[i]);
            }
            /* Print first 64 bytes of response */
            printf("  Data: ");
            int j;
            for (j = 0; j < 64 && j < (int)sizeof(valbuf); j++) {
                if (j > 0 && j % 16 == 0) printf("\n        ");
                printf("%02x ", valbuf[j]);
            }
            printf("\n");
        } else {
            lg("LEAK", "property failed", ret, errno, detail);
        }
    }

    /* PERFCOUNTER_QUERY — may leak counter structure data */
    unsigned int countbuf[256];
    memset(countbuf, 0, sizeof(countbuf));
    struct kgsl_perfcounter_query pq;
    memset(&pq, 0, sizeof(pq));
    pq.groupid = 0;
    pq.countables = countbuf;
    pq.count = 256;

    ret = safe_ioctl(fd, IOCTL_KGSL_PERFCOUNTER_QUERY, &pq, "PERFCOUNTER_QUERY");
    if (ret == 0) {
        char detail[128];
        snprintf(detail, sizeof(detail), "max_counters=%u", pq.max_counters);
        lg("LEAK", "** PERFCOUNTER QUERY **", ret, errno, detail);
        check_leak(countbuf, sizeof(countbuf), "PERFCOUNTER_QUERY response");
        check_leak(&pq, sizeof(pq), "PERFCOUNTER_QUERY struct");
    } else if (ret != -999) {
        lg("LEAK", "perfcounter query failed", ret, errno, "");
    }

    /* Try multiple perf counter groups */
    for (i = 0; i < 32; i++) {
        memset(countbuf, 0, sizeof(countbuf));
        memset(&pq, 0, sizeof(pq));
        pq.groupid = i;
        pq.countables = countbuf;
        pq.count = 256;
        ret = safe_ioctl(fd, IOCTL_KGSL_PERFCOUNTER_QUERY, &pq, "PERF_GROUP");
        if (ret == 0 && pq.max_counters > 0) {
            char detail[128];
            snprintf(detail, sizeof(detail), "group=%d max=%u", i, pq.max_counters);
            lg("LEAK", "** PERF GROUP **", ret, errno, detail);
        }
    }
}

/* Test F: Race conditions */
static void test_races(int fd) {
    printf("\n=== TEST F: RACE CONDITIONS ===\n");
    fprintf(logfp, "\n=== TEST F: RACE CONDITIONS ===\n");

    int ret, i;
    pthread_t thread;
    struct race_data rd;

    /* Race 1: Create context while thread destroys it */
    printf("\n--- Race: context create/destroy ---\n");
    for (i = 0; i < 100; i++) {
        struct kgsl_drawctxt_create c;
        memset(&c, 0, sizeof(c));
        c.flags = KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS;
        ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c, "RACE_CTX_CREATE");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        if (ret != 0) continue;

        /* Start thread to destroy it */
        rd.fd = fd;
        rd.running = 1;
        rd.crashes = 0;
        rd.target_id = c.drawctxt_id;
        rd.test_type = 0;
        pthread_create(&thread, NULL, race_thread, &rd);

        /* Main thread also tries to destroy */
        struct kgsl_drawctxt_destroy d;
        d.drawctxt_id = c.drawctxt_id;
        ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "RACE_CTX_DESTROY_MAIN");
        if (ret == -999) {
            rd.running = 0;
            pthread_join(thread, NULL);
            fd = reopen();
            if (fd < 0) return;
            continue;
        }

        rd.running = 0;
        pthread_join(thread, NULL);

        if (rd.crashes > 0) {
            printf("!!! RACE CRASH: context create/destroy race at iteration %d !!!\n", i);
            lg("RACE", "!! CRASH IN CONTEXT RACE !!", -1, 0, "");
        }
    }
    printf("Context race: 100 iterations complete\n");

    /* Race 2: Memory alloc/free race */
    printf("\n--- Race: memory alloc/free ---\n");
    for (i = 0; i < 100; i++) {
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = 4096;
        ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a, "RACE_MEM_ALLOC");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        if (ret != 0) continue;

        rd.fd = fd;
        rd.running = 1;
        rd.crashes = 0;
        rd.target_id = a.id;
        rd.test_type = 1;
        pthread_create(&thread, NULL, race_thread, &rd);

        /* Main thread also frees + tries to use */
        struct kgsl_gpumem_free_id f;
        f.id = a.id;
        f.__pad = 0;
        ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "RACE_MEM_FREE_MAIN");

        /* Immediately try get_info on potentially freed memory */
        struct kgsl_gpumem_get_info gi;
        memset(&gi, 0, sizeof(gi));
        gi.id = a.id;
        ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_GET_INFO, &gi, "RACE_MEM_GET_INFO");
        if (ret == 0) {
            check_leak(&gi, sizeof(gi), "RACE GET_INFO response");
        }

        rd.running = 0;
        pthread_join(thread, NULL);

        if (rd.crashes > 0) {
            printf("!!! RACE CRASH: memory alloc/free race at iteration %d !!!\n", i);
            lg("RACE", "!! CRASH IN MEMORY RACE !!", -1, 0, "");
        }
    }
    printf("Memory race: 100 iterations complete\n");

    /* Race 3: Sync source create/destroy race */
    printf("\n--- Race: sync create/destroy ---\n");
    for (i = 0; i < 100; i++) {
        struct kgsl_syncsource_create sc;
        memset(&sc, 0, sizeof(sc));
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_CREATE, &sc, "RACE_SYNC_CREATE");
        if (ret == -999) {
            fd = reopen();
            if (fd < 0) return;
            continue;
        }
        if (ret != 0) continue;

        rd.fd = fd;
        rd.running = 1;
        rd.crashes = 0;
        rd.target_id = sc.id;
        rd.test_type = 2;
        pthread_create(&thread, NULL, race_thread, &rd);

        /* Main: create fence then destroy source */
        struct kgsl_syncsource_create_fence cf;
        cf.id = sc.id;
        cf.fence_fd = -1;
        ret = safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_CREATE_FENCE, &cf, "RACE_FENCE");

        struct kgsl_syncsource_destroy sd;
        sd.id = sc.id;
        safe_ioctl(fd, IOCTL_KGSL_SYNCSOURCE_DESTROY, &sd, "RACE_SYNC_DESTROY_MAIN");

        if (cf.fence_fd >= 0) close(cf.fence_fd);

        rd.running = 0;
        pthread_join(thread, NULL);

        if (rd.crashes > 0) {
            printf("!!! RACE CRASH: sync create/destroy race at iteration %d !!!\n", i);
            lg("RACE", "!! CRASH IN SYNC RACE !!", -1, 0, "");
        }
    }
    printf("Sync race: 100 iterations complete\n");
}

/* Test G: Targeted mutation with correct struct sizes */
static void test_mutations(int fd) {
    printf("\n=== TEST G: TARGETED MUTATIONS (5000 rounds) ===\n");
    fprintf(logfp, "\n=== TEST G: TARGETED MUTATIONS ===\n");

    int ret, round;
    int crashes = 0, successes = 0, unusual = 0;

    /* First create a valid context to use */
    struct kgsl_drawctxt_create c;
    memset(&c, 0, sizeof(c));
    c.flags = KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS;
    ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c, "MUT_CTX");
    unsigned int valid_ctx = (ret == 0) ? c.drawctxt_id : 0;

    for (round = 0; round < 5000; round++) {
        int test = rand64() % 8;
        caught_sig = 0;

        switch (test) {
        case 0: { /* Fuzz DRAWCTXT_CREATE with random flags */
            struct kgsl_drawctxt_create cc;
            cc.flags = (unsigned int)(rand64());
            cc.drawctxt_id = 0;
            ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &cc, "MUT_CTX_CREATE");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) {
                successes++;
                /* Destroy it */
                struct kgsl_drawctxt_destroy d;
                d.drawctxt_id = cc.drawctxt_id;
                safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "MUT_CTX_DESTROY");
            }
            break;
        }
        case 1: { /* Fuzz GPUMEM_ALLOC_ID with random sizes/flags */
            struct kgsl_gpumem_alloc_id a;
            memset(&a, 0, sizeof(a));
            a.size = rand64() % 0x10000000;
            a.flags = (unsigned int)(rand64());
            ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a, "MUT_ALLOC");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) {
                successes++;
                struct kgsl_gpumem_free_id f;
                f.id = a.id;
                f.__pad = 0;
                safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "MUT_FREE");
            }
            break;
        }
        case 2: { /* Destroy random context IDs */
            struct kgsl_drawctxt_destroy d;
            d.drawctxt_id = (unsigned int)(rand64());
            ret = safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "MUT_DESTROY_RAND");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) { unusual++; }
            break;
        }
        case 3: { /* Free random memory IDs */
            struct kgsl_gpumem_free_id f;
            f.id = (unsigned int)(rand64());
            f.__pad = 0;
            ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f, "MUT_FREE_RAND");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) { unusual++; }
            break;
        }
        case 4: { /* Issue IB commands with random data + valid context */
            if (!valid_ctx) break;
            struct kgsl_ringbuffer_issueibcmds ib;
            memset(&ib, 0, sizeof(ib));
            ib.drawctxt_id = valid_ctx;
            ib.ibdesc_addr = rand64();
            ib.numibs = rand64() % 256;
            ib.flags = (unsigned int)(rand64());
            ret = safe_ioctl(fd, IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS, &ib, "MUT_IB");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) { successes++; }
            else if (errno != EINVAL && errno != EFAULT && errno != EBADF) { unusual++; }
            break;
        }
        case 5: { /* Timestamp event with random data */
            struct kgsl_timestamp_event te;
            memset(&te, 0, sizeof(te));
            te.type = rand64() % 4;
            te.timestamp = (unsigned int)(rand64());
            te.context_id = valid_ctx ? valid_ctx : (unsigned int)(rand64());
            te.priv = (void *)(rand64() & 0x7FFFFFFFULL); /* userspace-range pointer */
            te.len = rand64() % 256;
            ret = safe_ioctl(fd, IOCTL_KGSL_TIMESTAMP_EVENT, &te, "MUT_TIMESTAMP");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) { successes++; }
            else if (errno != EINVAL && errno != EFAULT) { unusual++; }
            break;
        }
        case 6: { /* SETPROPERTY with random data */
            unsigned char propbuf[256];
            int j;
            for (j = 0; j < 256; j++) propbuf[j] = rand64();
            struct kgsl_device_getproperty sp;
            sp.type = rand64() % 0x30;
            sp.value = propbuf;
            sp.sizebytes = rand64() % 256;
            ret = safe_ioctl(fd, IOCTL_KGSL_SETPROPERTY, &sp, "MUT_SETPROP");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) { successes++; }
            else if (errno != EINVAL && errno != EFAULT && errno != EACCES) { unusual++; }
            break;
        }
        case 7: { /* GET_INFO with random IDs */
            struct kgsl_gpumem_get_info gi;
            memset(&gi, 0, sizeof(gi));
            gi.id = (unsigned int)(rand64());
            ret = safe_ioctl(fd, IOCTL_KGSL_GPUMEM_GET_INFO, &gi, "MUT_GETINFO");
            if (ret == -999) { crashes++; fd = reopen(); if (fd < 0) return; break; }
            if (ret == 0) {
                successes++;
                check_leak(&gi, sizeof(gi), "MUT_GETINFO response");
            }
            break;
        }
        }

        if ((round + 1) % 1000 == 0) {
            printf("[mut %d/5000] crashes=%d successes=%d unusual=%d\n",
                   round + 1, crashes, successes, unusual);
        }
    }

    printf("Mutations complete: crashes=%d successes=%d unusual=%d\n",
           crashes, successes, unusual);
    fprintf(logfp, "Mutations: crashes=%d successes=%d unusual=%d\n",
            crashes, successes, unusual);

    /* Destroy our context */
    if (valid_ctx) {
        struct kgsl_drawctxt_destroy d;
        d.drawctxt_id = valid_ctx;
        safe_ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d, "MUT_CLEANUP");
    }
}

/* ===== MAIN ===== */
int main(int argc, char **argv) {
    int fd;
    int skip_races = 0;

    if (argc > 1 && strcmp(argv[1], "--no-races") == 0)
        skip_races = 1;

    rng = (unsigned long long)time(NULL) ^ ((unsigned long long)getpid() << 16);

    logfp = fopen("/data/data/com.termux/files/home/ralph2.log", "w");
    if (!logfp) logfp = fopen("ralph2.log", "w");
    if (!logfp) logfp = stdout;

    printf("=============================================\n");
    printf("  Ralph Wiggum v2 — Structure-Aware KGSL Fuzzer\n");
    printf("  \"My cat's breath smells like cat food\"\n");
    printf("=============================================\n");
    printf("Target: %s\n", KGSL_DEVICE);
    printf("PID: %d\n", getpid());
    printf("Races: %s\n\n", skip_races ? "DISABLED" : "ENABLED");

    fprintf(logfp, "=== Ralph Wiggum v2 ===\n");
    fprintf(logfp, "PID: %d | Races: %s\n\n", getpid(), skip_races ? "no" : "yes");

    /* Print struct sizes for verification */
    printf("Struct sizes (arm64):\n");
    printf("  kgsl_drawctxt_create:      %zu bytes\n", sizeof(struct kgsl_drawctxt_create));
    printf("  kgsl_drawctxt_destroy:     %zu bytes\n", sizeof(struct kgsl_drawctxt_destroy));
    printf("  kgsl_gpumem_alloc:         %zu bytes\n", sizeof(struct kgsl_gpumem_alloc));
    printf("  kgsl_gpumem_alloc_id:      %zu bytes\n", sizeof(struct kgsl_gpumem_alloc_id));
    printf("  kgsl_gpumem_free_id:       %zu bytes\n", sizeof(struct kgsl_gpumem_free_id));
    printf("  kgsl_gpumem_get_info:      %zu bytes\n", sizeof(struct kgsl_gpumem_get_info));
    printf("  kgsl_ringbuffer_issueibcmds: %zu bytes\n", sizeof(struct kgsl_ringbuffer_issueibcmds));
    printf("  kgsl_syncsource_create:    %zu bytes\n", sizeof(struct kgsl_syncsource_create));
    printf("  kgsl_timestamp_event:      %zu bytes\n", sizeof(struct kgsl_timestamp_event));
    printf("  kgsl_device_getproperty:   %zu bytes\n", sizeof(struct kgsl_device_getproperty));
    printf("  kgsl_perfcounter_query:    %zu bytes\n", sizeof(struct kgsl_perfcounter_query));
    printf("  kgsl_gpuobj_alloc:         %zu bytes\n", sizeof(struct kgsl_gpuobj_alloc));
    printf("\n");

    /* Signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("FATAL: open(%s): %s\n", KGSL_DEVICE, strerror(errno));
        return 1;
    }
    printf("Opened %s fd=%d\n\n", KGSL_DEVICE, fd);

    /* Run all tests */
    test_probe(fd);
    test_context(fd);
    test_memory(fd);
    test_sync(fd);
    test_info_leaks(fd);
    if (!skip_races)
        test_races(fd);
    test_mutations(fd);

    printf("\n=============================================\n");
    printf("  Ralph Wiggum says: \"I bent my Wookiee!\"\n");
    printf("=============================================\n");
    printf("All tests complete. Check ~/ralph2.log for details.\n");

    fprintf(logfp, "\n=== ALL TESTS COMPLETE ===\n");
    fflush(logfp);

    close(fd);
    if (logfp != stdout) fclose(logfp);
    return 0;
}
