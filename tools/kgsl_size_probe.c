#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* Manually construct ioctl numbers with different sizes */
/* _IOC(dir, type, nr, size) */
/* _IOWR = dir 3, type 0x09, nr 0x13 */
/* _IOC_DIRSHIFT=30, _IOC_TYPESHIFT=8, _IOC_NRSHIFT=0, _IOC_SIZESHIFT=16 */
#define MAKE_IOCTL(size) (0xC0000000 | ((size) << 16) | (0x09 << 8) | 0x13)

int main(void) {
    printf("=== IOCTL SIZE PROBE ===\n");
    printf("Testing DRAWCTXT_CREATE with different struct sizes\n\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("OPEN FAILED: %s\n", strerror(errno)); return 1; }
    printf("KGSL opened: fd=%d\n\n", fd);

    /* Try sizes 4 through 64 in steps of 4 */
    unsigned char buf[128];
    int size;
    for (size = 4; size <= 64; size += 4) {
        memset(buf, 0, sizeof(buf));
        /* Set flags = 0x41 (PREAMBLE|NO_GMEM_ALLOC) in first 4 bytes */
        buf[0] = 0x41;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;

        unsigned long cmd = MAKE_IOCTL(size);
        errno = 0;
        int ret = ioctl(fd, cmd, buf);

        if (ret == 0) {
            unsigned int ctx_id = *(unsigned int*)(buf + 4);
            printf("*** SIZE %2d: SUCCESS *** ioctl=0x%08lx ctx_id=%u\n",
                   size, cmd, ctx_id);
            /* Clean up: destroy the context */
            /* DRAWCTXT_DESTROY = _IOW(0x09, 0x14, ...) size 4 */
            unsigned int dreq = ctx_id;
            ioctl(fd, 0x40040914, &dreq);
        } else if (errno == 22) {
            printf("    size %2d: EINVAL    ioctl=0x%08lx\n", size, cmd);
        } else {
            printf("    size %2d: errno=%d (%s) ioctl=0x%08lx\n",
                   size, errno, strerror(errno), cmd);
        }
    }

    close(fd);
    return 0;
}
