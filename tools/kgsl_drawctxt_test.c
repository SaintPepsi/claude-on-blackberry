#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

/* DRAWCTXT_CREATE ioctl */
#define KGSL_CONTEXT_NO_GMEM_ALLOC     0x00000001
#define KGSL_CONTEXT_SUBMIT_IB_LIST    0x00000010
#define KGSL_CONTEXT_CTX_SWITCH        0x00000020
#define KGSL_CONTEXT_PREAMBLE          0x00000040
#define KGSL_CONTEXT_TRASH_STATE       0x00000080
#define KGSL_CONTEXT_PER_CONTEXT_TS    0x00000100
#define KGSL_CONTEXT_USER_GENERATED_TS 0x00000200
#define KGSL_CONTEXT_NO_FAULT_TOLERANCE 0x00000400
#define KGSL_CONTEXT_TYPE_ANY          0x00000000
#define KGSL_CONTEXT_TYPE_GL           0x00010000
#define KGSL_CONTEXT_TYPE_CL           0x00020000
#define KGSL_CONTEXT_TYPE_C2D          0x00030000
#define KGSL_CONTEXT_TYPE_RS           0x00040000

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE \
    _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

#define IOCTL_KGSL_DRAWCTXT_DESTROY \
    _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("OPEN FAILED: %s\n", strerror(errno));
        return 1;
    }
    printf("KGSL opened: fd=%d\n", fd);
    printf("SELinux context: ");
    fflush(stdout);
    system("cat /proc/self/attr/current 2>/dev/null");
    printf("\nUID: ");
    fflush(stdout);
    system("id");
    printf("\n");

    unsigned int flags_to_test[] = {
        0,
        KGSL_CONTEXT_NO_GMEM_ALLOC,
        KGSL_CONTEXT_SUBMIT_IB_LIST,
        KGSL_CONTEXT_CTX_SWITCH,
        KGSL_CONTEXT_PREAMBLE,
        KGSL_CONTEXT_TRASH_STATE,
        KGSL_CONTEXT_PER_CONTEXT_TS,
        KGSL_CONTEXT_USER_GENERATED_TS,
        KGSL_CONTEXT_NO_FAULT_TOLERANCE,
        KGSL_CONTEXT_TYPE_GL,
        KGSL_CONTEXT_TYPE_CL,
        KGSL_CONTEXT_TYPE_C2D,
        KGSL_CONTEXT_TYPE_RS,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_TYPE_GL,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_TYPE_CL,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_NO_GMEM_ALLOC,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_CTX_SWITCH | KGSL_CONTEXT_PREAMBLE,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_CTX_SWITCH | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS,
        KGSL_CONTEXT_SUBMIT_IB_LIST | KGSL_CONTEXT_CTX_SWITCH | KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_PER_CONTEXT_TS | KGSL_CONTEXT_TYPE_GL,
    };
    int n = sizeof(flags_to_test)/sizeof(flags_to_test[0]);

    printf("Testing %d flag combinations for DRAWCTXT_CREATE...\n\n", n);

    for (int i = 0; i < n; i++) {
        struct kgsl_drawctxt_create req = { .flags = flags_to_test[i], .drawctxt_id = 0 };
        int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
        if (ret == 0) {
            printf("*** SUCCESS *** flags=0x%08x -> drawctxt_id=%u\n", flags_to_test[i], req.drawctxt_id);
            /* Try to destroy it */
            struct kgsl_drawctxt_destroy dreq = { .drawctxt_id = req.drawctxt_id };
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &dreq);
        } else {
            printf("FAILED flags=0x%08x -> errno=%d (%s)\n", flags_to_test[i], errno, strerror(errno));
        }
    }

    close(fd);
    return 0;
}
