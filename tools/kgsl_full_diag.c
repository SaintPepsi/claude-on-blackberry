#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/* Flag definitions */
#define KGSL_CONTEXT_NO_GMEM_ALLOC     0x00000001
#define KGSL_CONTEXT_PREAMBLE          0x00000040
#define KGSL_CONTEXT_PER_CONTEXT_TS    0x00000100
#define KGSL_CONTEXT_USER_GENERATED_TS 0x00000200
#define KGSL_CONTEXT_TYPE_GL           0x00010000

/* Structs — keeping them identical to kernel headers */
struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

/* GETPROPERTY with CORRECT property constants */
#define KGSL_PROPERTY_DEVICE_INFO     0x1
#define KGSL_PROPERTY_VERSION         0x102

struct kgsl_devinfo {
    unsigned int device_id;
    unsigned int chip_id;
    unsigned int mmu_enabled;
    unsigned long gmem_gpubaseaddr;  /* NOTE: unsigned long! */
    unsigned int gpu_id;
    unsigned int gmem_sizebytes;
};
struct kgsl_version {
    unsigned int drv_major;
    unsigned int drv_minor;
    unsigned int dev_major;
    unsigned int dev_minor;
};
struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    unsigned int sizebytes;
};

/* TIMESTAMP_EVENT ioctl to test another known-working ioctl */
struct kgsl_timestamp_event {
    int type;
    unsigned int timestamp;
    unsigned int context_id;
    void *priv;
    unsigned int len;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE  _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)
#define IOCTL_KGSL_DEVICE_GETPROPERTY _IOWR(KGSL_IOC_TYPE, 0x02, struct kgsl_device_getproperty)

/* Also try raw ioctl numbers to bypass any macro encoding issues */

int main(void) {
    printf("=== FULL DIAGNOSTICS (32-bit) ===\n");
    printf("sizeof(void*) = %u\n", (unsigned)sizeof(void*));
    printf("sizeof(unsigned long) = %u\n", (unsigned)sizeof(unsigned long));
    printf("sizeof(kgsl_drawctxt_create) = %u\n", (unsigned)sizeof(struct kgsl_drawctxt_create));
    printf("sizeof(kgsl_devinfo) = %u\n", (unsigned)sizeof(struct kgsl_devinfo));
    printf("sizeof(kgsl_version) = %u\n", (unsigned)sizeof(struct kgsl_version));
    printf("sizeof(kgsl_device_getproperty) = %u\n", (unsigned)sizeof(struct kgsl_device_getproperty));
    printf("DRAWCTXT_CREATE  = 0x%08lx\n", (unsigned long)IOCTL_KGSL_DRAWCTXT_CREATE);
    printf("DEVICE_GETPROPERTY = 0x%08lx\n", (unsigned long)IOCTL_KGSL_DEVICE_GETPROPERTY);

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("OPEN FAILED: %s\n", strerror(errno)); return 1; }
    printf("KGSL opened: fd=%d\n\n", fd);

    /* Test 1: GETPROPERTY with VERSION (0x102) */
    printf("=== GETPROPERTY tests ===\n");
    {
        struct kgsl_version ver;
        memset(&ver, 0, sizeof(ver));
        struct kgsl_device_getproperty prop;
        memset(&prop, 0, sizeof(prop));
        prop.type = KGSL_PROPERTY_VERSION;  /* 0x102 */
        prop.value = &ver;
        prop.sizebytes = sizeof(ver);
        errno = 0;
        int ret = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &prop);
        if (ret == 0) {
            printf("VERSION(0x102) SUCCESS: drv=%u.%u dev=%u.%u\n",
                   ver.drv_major, ver.drv_minor, ver.dev_major, ver.dev_minor);
        } else {
            printf("VERSION(0x102) FAILED: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
        }
    }

    /* Test 2: GETPROPERTY with DEVICE_INFO (0x1) */
    {
        struct kgsl_devinfo info;
        memset(&info, 0, sizeof(info));
        struct kgsl_device_getproperty prop;
        memset(&prop, 0, sizeof(prop));
        prop.type = KGSL_PROPERTY_DEVICE_INFO;  /* 0x1 */
        prop.value = &info;
        prop.sizebytes = sizeof(info);
        errno = 0;
        int ret = ioctl(fd, IOCTL_KGSL_DEVICE_GETPROPERTY, &prop);
        if (ret == 0) {
            printf("DEVINFO(0x1) SUCCESS: chip_id=0x%x gpu_id=0x%x gmem=%u\n",
                   info.chip_id, info.gpu_id, info.gmem_sizebytes);
        } else {
            printf("DEVINFO(0x1) FAILED: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
        }
    }

    /* Test 3: DRAWCTXT_CREATE */
    printf("\n=== DRAWCTXT_CREATE tests ===\n");
    unsigned int flag_tests[] = { 0x41, 0x341, 0x10341 };
    char *names[] = { "0x41 min", "0x341 system", "0x10341 full" };
    int i;
    for (i = 0; i < 3; i++) {
        struct kgsl_drawctxt_create req;
        memset(&req, 0, sizeof(req));
        req.flags = flag_tests[i];
        errno = 0;
        int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
        if (ret == 0) {
            printf("*** SUCCESS *** %s -> ctx_id=%u\n", names[i], req.drawctxt_id);
            struct kgsl_drawctxt_destroy dreq;
            dreq.drawctxt_id = req.drawctxt_id;
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dreq);
        } else {
            printf("    FAILED     %s -> ret=%d errno=%d (%s)\n", names[i], ret, errno, strerror(errno));
        }
    }

    /* Test 4: Try raw ioctl numbers in case our macro encoding is wrong */
    printf("\n=== RAW IOCTL NUMBER tests ===\n");
    /* 32-bit DRAWCTXT_CREATE should be 0xc0080913 */
    {
        struct kgsl_drawctxt_create req;
        memset(&req, 0, sizeof(req));
        req.flags = 0x41;
        errno = 0;
        int ret = ioctl(fd, 0xc0080913, &req);
        printf("Raw 0xc0080913 (DRAWCTXT_CREATE): ret=%d errno=%d (%s) ctx=%u\n",
               ret, errno, strerror(errno), req.drawctxt_id);
        if (ret == 0) {
            struct kgsl_drawctxt_destroy dreq;
            dreq.drawctxt_id = req.drawctxt_id;
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dreq);
        }
    }

    /* Test 5: Try with GPUOBJ_ALLOC (ioctl 0x2A) to verify ioctl dispatch works at all */
    /* Use a simpler ioctl: KGSL_IOCTL_MAP_USER_MEM (0x0C) or PERFCOUNTER_GET (0x30) */
    /* Actually just try TIMESTAMP_EVENT read (0x33) which is simple */

    /* Test 6: Read /proc/self/attr/current for SELinux context */
    printf("\n=== PROCESS INFO ===\n");
    {
        char buf[256];
        int sfd = open("/proc/self/attr/current", O_RDONLY);
        if (sfd >= 0) {
            int n = read(sfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("SELinux: %s\n", buf); }
            else printf("SELinux: (empty read)\n");
            close(sfd);
        } else {
            printf("SELinux: can't read (%s)\n", strerror(errno));
        }
    }
    {
        printf("uid=%u gid=%u\n", getuid(), getgid());
    }

    close(fd);
    return 0;
}
