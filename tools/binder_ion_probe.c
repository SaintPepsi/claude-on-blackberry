/*
 * binder_ion_probe.c — Enumerate binder and ION ioctl attack surface
 *
 * Tests which binder/ION ioctls are accessible and what information
 * they return. Focuses on finding kernel info leaks or write primitives.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

/* === BINDER DEFINITIONS === */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_SET_CONTEXT_MGR  _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

struct binder_version {
    signed long protocol_version;
};

/* === ION DEFINITIONS === */
/* ION ioctl numbers for kernel 3.10 */
struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;  /* output */
};

struct ion_fd_data {
    int handle;
    int fd;
};

struct ion_handle_data {
    int handle;
};

struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

#define ION_IOC_MAGIC       'I'
#define ION_IOC_ALLOC       _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE        _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP         _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE       _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT      _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC        _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM      _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

/* ION heap types */
#define ION_HEAP_SYSTEM         (1 << 0)
#define ION_HEAP_SYSTEM_CONTIG  (1 << 1)
#define ION_HEAP_CARVEOUT       (1 << 2)
#define ION_HEAP_TYPE_DMA       (1 << 3)
/* Qualcomm-specific ION heaps */
#define ION_HEAP_CP_MM          (1 << 8)
#define ION_HEAP_IOMMU          (1 << 25)

/* === ASHMEM DEFINITIONS === */
#define ASHMEM_SET_NAME     _IOW(0x77, 1, char[256])
#define ASHMEM_GET_NAME     _IOR(0x77, 2, char[256])
#define ASHMEM_SET_SIZE     _IOW(0x77, 3, size_t)
#define ASHMEM_GET_SIZE     _IO(0x77, 4)
#define ASHMEM_SET_PROT     _IOW(0x77, 5, unsigned long)
#define ASHMEM_PIN          _IOW(0x77, 7, struct ashmem_pin)
#define ASHMEM_UNPIN        _IOW(0x77, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS _IO(0x77, 9)
#define ASHMEM_PURGE_ALL    _IO(0x77, 10)

struct ashmem_pin {
    uint32_t offset;
    uint32_t len;
};

static void test_binder(void) {
    printf("=== BINDER PROBE ===\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        printf("  /dev/binder: OPEN FAILED (%s)\n", strerror(errno));
        return;
    }
    printf("  /dev/binder: opened fd=%d\n", fd);

    /* Test BINDER_VERSION */
    {
        struct binder_version ver;
        memset(&ver, 0, sizeof(ver));
        errno = 0;
        int ret = ioctl(fd, BINDER_VERSION, &ver);
        if (ret == 0) {
            printf("  VERSION: SUCCESS protocol=%ld\n", ver.protocol_version);
        } else {
            printf("  VERSION: FAILED errno=%d (%s)\n", errno, strerror(errno));
        }
    }

    /* Test SET_MAX_THREADS */
    {
        uint32_t max = 0;
        errno = 0;
        int ret = ioctl(fd, BINDER_SET_MAX_THREADS, &max);
        printf("  SET_MAX_THREADS(0): ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
    }

    /* Test mmap — binder requires mmap for its transaction buffer */
    {
        void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map != MAP_FAILED) {
            printf("  MMAP: SUCCESS addr=%p\n", map);
            /* Check if mmap'd area contains kernel pointers */
            unsigned long long *vals = (unsigned long long *)map;
            int i;
            for (i = 0; i < 512; i++) {
                if (vals[i] >= 0xffffffc000000000ULL) {
                    printf("  *** KERNEL PTR at offset %d: 0x%016llx ***\n",
                           i * 8, vals[i]);
                }
            }
            munmap(map, 4096);
        } else {
            printf("  MMAP: FAILED errno=%d (%s)\n", errno, strerror(errno));
        }
    }

    /* Test WRITE_READ with empty buffers (just to see if it responds) */
    {
        char rbuf[256];
        memset(rbuf, 0, sizeof(rbuf));
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = 0;
        bwr.write_buffer = 0;
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (unsigned long)rbuf;
        errno = 0;
        int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        printf("  WRITE_READ(empty): ret=%d errno=%d read_consumed=%ld\n",
               ret, errno, bwr.read_consumed);
    }

    close(fd);
    printf("\n");
}

static void test_ion(void) {
    printf("=== ION PROBE ===\n");
    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/ion", O_RDONLY);
        if (fd < 0) {
            printf("  /dev/ion: OPEN FAILED (%s)\n", strerror(errno));
            return;
        }
        printf("  /dev/ion: opened READ-ONLY fd=%d\n", fd);
    } else {
        printf("  /dev/ion: opened RDWR fd=%d\n", fd);
    }

    /* Try allocating from various heap types */
    unsigned int heaps[] = {
        ION_HEAP_SYSTEM,
        ION_HEAP_SYSTEM_CONTIG,
        ION_HEAP_IOMMU,
        ION_HEAP_CP_MM,
        ION_HEAP_TYPE_DMA,
    };
    char *heap_names[] = {
        "SYSTEM", "SYSTEM_CONTIG", "IOMMU", "CP_MM", "DMA"
    };
    int i;
    for (i = 0; i < 5; i++) {
        struct ion_allocation_data alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.len = 4096;
        alloc.align = 4096;
        alloc.heap_id_mask = heaps[i];
        alloc.flags = 0;
        errno = 0;
        int ret = ioctl(fd, ION_IOC_ALLOC, &alloc);
        if (ret == 0) {
            printf("  ALLOC %s: SUCCESS handle=%d\n", heap_names[i], alloc.handle);

            /* Try to mmap via ION_IOC_MAP */
            struct ion_fd_data fd_data;
            memset(&fd_data, 0, sizeof(fd_data));
            fd_data.handle = alloc.handle;
            errno = 0;
            ret = ioctl(fd, ION_IOC_MAP, &fd_data);
            if (ret == 0) {
                printf("  MAP %s: SUCCESS map_fd=%d\n", heap_names[i], fd_data.fd);
                /* mmap the returned fd */
                void *map = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_data.fd, 0);
                if (map != MAP_FAILED) {
                    printf("  MMAP %s: SUCCESS addr=%p\n", heap_names[i], map);
                    /* Write test pattern */
                    memset(map, 0x41, 4096);
                    printf("  WRITE %s: wrote 0x41 pattern\n", heap_names[i]);
                    munmap(map, 4096);
                } else {
                    printf("  MMAP %s: FAILED errno=%d\n", heap_names[i], errno);
                }
                close(fd_data.fd);
            } else {
                printf("  MAP %s: FAILED errno=%d (%s)\n", heap_names[i], errno, strerror(errno));
            }

            /* Free the allocation */
            struct ion_handle_data hdata;
            hdata.handle = alloc.handle;
            ioctl(fd, ION_IOC_FREE, &hdata);
        } else {
            printf("  ALLOC %s: FAILED errno=%d (%s)\n", heap_names[i], errno, strerror(errno));
        }
    }

    close(fd);
    printf("\n");
}

static void test_ashmem(void) {
    printf("=== ASHMEM PROBE ===\n");
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) {
        printf("  /dev/ashmem: OPEN FAILED (%s)\n", strerror(errno));
        return;
    }
    printf("  /dev/ashmem: opened fd=%d\n", fd);

    /* Set name and size */
    char name[256] = "probe_test";
    ioctl(fd, ASHMEM_SET_NAME, name);

    size_t sz = 4096;
    int ret = ioctl(fd, ASHMEM_SET_SIZE, &sz);
    printf("  SET_SIZE(4096): ret=%d\n", ret);

    /* Get size back */
    errno = 0;
    int gsz = ioctl(fd, ASHMEM_GET_SIZE);
    printf("  GET_SIZE: %d (errno=%d)\n", gsz, errno);

    /* mmap it */
    void *map = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (map != MAP_FAILED) {
        printf("  MMAP: SUCCESS addr=%p\n", map);
        /* Check initial content */
        unsigned char *bytes = (unsigned char *)map;
        int nonzero = 0;
        int i;
        for (i = 0; i < 4096; i++) {
            if (bytes[i] != 0) nonzero++;
        }
        printf("  Initial content: %d non-zero bytes (potential info leak if > 0)\n", nonzero);

        /* Pin/unpin test */
        struct ashmem_pin pin = { 0, 0 }; /* entire region */
        errno = 0;
        ret = ioctl(fd, ASHMEM_PIN, &pin);
        printf("  PIN: ret=%d errno=%d\n", ret, errno);

        ret = ioctl(fd, ASHMEM_UNPIN, &pin);
        printf("  UNPIN: ret=%d errno=%d\n", ret, errno);

        /* Check if content changed after unpin */
        nonzero = 0;
        for (i = 0; i < 4096; i++) {
            if (bytes[i] != 0) nonzero++;
        }
        printf("  After unpin: %d non-zero bytes\n", nonzero);

        munmap(map, 4096);
    } else {
        printf("  MMAP: FAILED errno=%d (%s)\n", errno, strerror(errno));
    }

    close(fd);
    printf("\n");
}

int main(void) {
    printf("=== BINDER / ION / ASHMEM PROBE ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());

    /* SELinux context */
    {
        char buf[256];
        int sfd = open("/proc/self/attr/current", O_RDONLY);
        if (sfd >= 0) {
            int n = read(sfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("SELinux: %s\n", buf); }
            close(sfd);
        }
    }
    printf("\n");

    test_binder();
    test_ion();
    test_ashmem();

    printf("=== PROBE COMPLETE ===\n");
    return 0;
}
