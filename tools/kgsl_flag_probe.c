#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE  _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

/* All known KGSL context flags */
#define F_NO_GMEM    0x00000001
#define F_SUBMIT_IB  0x00000010
#define F_CTX_SWITCH 0x00000020
#define F_PREAMBLE   0x00000040
#define F_TRASH_STATE 0x00000080
#define F_PER_CTX_TS 0x00000100
#define F_USER_TS    0x00000200
#define F_NO_FT      0x00000400
#define F_PRIO_MASK  0x0000F000
#define F_TYPE_GL    0x00010000
#define F_TYPE_CL    0x00020000
#define F_TYPE_C2D   0x00030000
#define F_TYPE_RS    0x00040000
#define F_SECURE     0x00080000
#define F_PWR        0x00100000

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("OPEN FAILED: %s\n", strerror(errno)); return 1; }
    printf("KGSL fd=%d, uid=%u, SELinux=", fd, getuid());
    {
        char buf[256]; int sfd = open("/proc/self/attr/current", 0);
        if (sfd >= 0) { int n = read(sfd, buf, 255); if (n>0) { buf[n]=0; printf("%s", buf); } close(sfd); }
    }
    printf("\n\n=== FLAG PROBE (base: PREAMBLE|NO_GMEM = 0x41) ===\n");

    /* Test base (0x41) plus various additional flags */
    struct { unsigned int flags; char *name; } tests[] = {
        { F_PREAMBLE|F_NO_GMEM, "0x41 base" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS, "+PER_CTX_TS" },
        { F_PREAMBLE|F_NO_GMEM|F_USER_TS, "+USER_TS" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS, "+PER_CTX_TS+USER_TS (0x341)" },
        { F_PREAMBLE|F_NO_GMEM|F_PWR, "+PWR (0x100041)" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|F_PWR, "+all (0x100341)" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|F_TYPE_GL, "+GL (0x10341)" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|F_TYPE_GL|F_PWR, "+GL+PWR (0x110341)" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|F_TYPE_CL, "+CL" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|F_TYPE_C2D, "+C2D" },
        /* Priority variations */
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|0x1000, "+prio1" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|0x2000, "+prio2" },
        { F_PREAMBLE|F_NO_GMEM|F_PER_CTX_TS|F_USER_TS|0x6000, "+prio6(default)" },
        /* Various combos */
        { F_PREAMBLE|F_NO_GMEM|F_SUBMIT_IB, "+SUBMIT_IB" },
        { F_PREAMBLE|F_NO_GMEM|F_NO_FT, "+NO_FT" },
        { F_PREAMBLE|F_NO_GMEM|F_TRASH_STATE, "+TRASH_STATE" },
        { F_PREAMBLE|F_NO_GMEM|F_CTX_SWITCH, "+CTX_SWITCH" },
        { F_PREAMBLE|F_NO_GMEM|F_SECURE, "+SECURE" },
        /* Exact matches of active system contexts */
        { 0x00000341, "surfaceflinger setup (0x341)" },
        { 0x00100341, "surfaceflinger active (0x100341)" },
        { 0x00110341, "surfaceflinger GL+PWR" },
        /* Try everything the system uses */
        { 0x00100741, "+NO_FT+PWR (camera)" },
        /* Bit 31 — undocumented BB flag? */
        { F_PREAMBLE|F_NO_GMEM|0x80000000, "+bit31" },
        { F_PREAMBLE|F_NO_GMEM|0x40000000, "+bit30" },
        { F_PREAMBLE|F_NO_GMEM|0x20000000, "+bit29" },
        { F_PREAMBLE|F_NO_GMEM|0x10000000, "+bit28" },
        { F_PREAMBLE|F_NO_GMEM|0x01000000, "+bit24" },
        { F_PREAMBLE|F_NO_GMEM|0x00800000, "+bit23" },
        { F_PREAMBLE|F_NO_GMEM|0x00400000, "+bit22" },
        { F_PREAMBLE|F_NO_GMEM|0x00200000, "+bit21" },
        /* All bits */
        { 0xFFFFFFFF, "all bits" },
        { 0x001F07FF, "all known flags" },
    };
    int n = sizeof(tests)/sizeof(tests[0]);
    int i;
    for (i = 0; i < n; i++) {
        struct kgsl_drawctxt_create req;
        memset(&req, 0, sizeof(req));
        req.flags = tests[i].flags;
        errno = 0;
        int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
        if (ret == 0) {
            printf("*** SUCCESS *** flags=0x%08x %s -> ctx=%u\n",
                   tests[i].flags, tests[i].name, req.drawctxt_id);
            struct kgsl_drawctxt_destroy d = { .drawctxt_id = req.drawctxt_id };
            ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &d);
        } else {
            printf("    FAILED     flags=0x%08x %s -> errno=%d\n",
                   tests[i].flags, tests[i].name, errno);
        }
    }
    close(fd);
    return 0;
}
