#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09
#define KGSL_CONTEXT_NO_GMEM_ALLOC     0x00000001
#define KGSL_CONTEXT_PREAMBLE          0x00000040
#define KGSL_CONTEXT_PER_CONTEXT_TS    0x00000100
#define KGSL_CONTEXT_USER_GENERATED_TS 0x00000200
#define KGSL_CONTEXT_TYPE_GL           0x00010000

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE  _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("OPEN FAILED: %s\n", strerror(errno)); return 1; }
    printf("KGSL opened: fd=%d\n", fd);
    printf("SELinux: "); fflush(stdout);
    system("cat /proc/self/attr/current 2>/dev/null"); printf("\n");
    printf("UID: "); fflush(stdout); system("id"); printf("\n");

    unsigned int tests[][2] = {
        {KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE, 0},  /* 0x41 - minimum */
        {KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_USER_GENERATED_TS, 0},  /* 0x341 - system flags */
        {KGSL_CONTEXT_NO_GMEM_ALLOC | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_USER_GENERATED_TS | KGSL_CONTEXT_TYPE_GL, 0},  /* 0x10341 - GL type */
        {KGSL_CONTEXT_PREAMBLE, 0},  /* 0x40 - missing NO_GMEM = should EINVAL */
        {KGSL_CONTEXT_NO_GMEM_ALLOC, 0},  /* 0x01 - missing PREAMBLE = should EINVAL */
        {0, 0},  /* 0x00 - nothing = should EINVAL */
    };
    char *names[] = {
        "0x41 (PREAMBLE|NO_GMEM) - MINIMUM",
        "0x341 (+PER_CTX_TS|USER_TS) - SYSTEM FLAGS",
        "0x10341 (+TYPE_GL) - FULL",
        "0x40 (PREAMBLE only) - SHOULD FAIL",
        "0x01 (NO_GMEM only) - SHOULD FAIL",
        "0x00 (nothing) - SHOULD FAIL",
    };
    int n = 6;

    for (int i = 0; i < n; i++) {
        struct kgsl_drawctxt_create req = { .flags = tests[i][0], .drawctxt_id = 0 };
        int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
        if (ret == 0) {
            printf("*** SUCCESS *** %s -> ctx_id=%u\n", names[i], req.drawctxt_id);
            struct kgsl_drawctxt_destroy dreq = { .drawctxt_id = req.drawctxt_id };
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dreq);
        } else {
            printf("    FAILED     %s -> errno=%d (%s)\n", names[i], errno, strerror(errno));
        }
    }
    close(fd);
    return 0;
}
