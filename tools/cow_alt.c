#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>

/*
 * Alternative Dirty COW vectors + kernel hardening detection
 *
 * Since /proc/self/mem write is blocked by GRSEC, test:
 * 1. process_vm_writev() — alternative write-to-process
 * 2. ptrace (already known EPERM)
 * 3. splice/vmsplice — data transfer primitives
 * 4. /proc/self/mem write return value analysis
 * 5. Kernel hardening feature detection
 */

/* process_vm_writev syscall number for aarch64 */
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 271
#endif

int main(void) {
    printf("=== Alternative COW Vectors + Hardening Detection ===\n");
    printf("uid=%d pid=%d\n\n", getuid(), getpid());

    /* === 1. /proc/self/mem write analysis === */
    printf("--- /proc/self/mem write analysis ---\n");
    {
        int f = open("/proc/self/mem", O_RDWR);
        if (f >= 0) {
            /* Try writing to writable mmap region */
            void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (rw != MAP_FAILED) {
                uint32_t *u = (uint32_t *)rw;
                u[0] = 0xAAAAAAAA;

                off_t addr = (off_t)(uintptr_t)rw;
                lseek(f, addr, SEEK_SET);
                uint32_t newval = 0xBBBBBBBB;
                ssize_t w = write(f, &newval, 4);
                printf("  Write to RW mmap: write()=%zd errno=%d target=0x%08x %s\n",
                       w, w < 0 ? errno : 0, u[0],
                       u[0] == 0xBBBBBBBB ? "WORKS" : "BLOCKED");

                /* Try writing to read-only mapping */
                void *ro = mmap(NULL, 4096, PROT_READ,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (ro != MAP_FAILED) {
                    addr = (off_t)(uintptr_t)ro;
                    lseek(f, addr, SEEK_SET);
                    w = write(f, &newval, 4);
                    printf("  Write to RO mmap: write()=%zd errno=%d\n",
                           w, w < 0 ? errno : 0);
                    if (w > 0) {
                        volatile uint32_t val = *(volatile uint32_t *)ro;
                        printf("  Read back: 0x%08x %s\n", val,
                               val == 0xBBBBBBBB ? "COW WRITE WORKS!" : "");
                    }
                    munmap(ro, 4096);
                }

                /* Try write to heap */
                uint32_t *heap = malloc(4096);
                if (heap) {
                    heap[0] = 0xCCCCCCCC;
                    addr = (off_t)(uintptr_t)heap;
                    lseek(f, addr, SEEK_SET);
                    w = write(f, &newval, 4);
                    printf("  Write to heap: write()=%zd errno=%d target=0x%08x %s\n",
                           w, w < 0 ? errno : 0, heap[0],
                           heap[0] == 0xBBBBBBBB ? "WORKS" : "BLOCKED");
                    free(heap);
                }

                munmap(rw, 4096);
            }
            close(f);
        }
    }

    /* === 2. process_vm_writev === */
    printf("\n--- process_vm_writev ---\n");
    {
        volatile uint32_t target = 0xAAAAAAAA;
        uint32_t newval = 0xDDDDDDDD;

        struct iovec local = { .iov_base = &newval, .iov_len = 4 };
        struct iovec remote = { .iov_base = (void *)&target, .iov_len = 4 };

        long ret = syscall(__NR_process_vm_writev, getpid(),
                          &local, 1, &remote, 1, 0);
        printf("  process_vm_writev(self): ret=%ld errno=%d target=0x%08x %s\n",
               ret, ret < 0 ? errno : 0, target,
               target == 0xDDDDDDDD ? "WORKS" : "BLOCKED");
    }

    /* === 3. vmsplice === */
    printf("\n--- vmsplice ---\n");
    {
        int pfd[2];
        if (pipe(pfd) == 0) {
            char buf[4096];
            memset(buf, 'V', sizeof(buf));

            struct iovec iov = { .iov_base = buf, .iov_len = 4096 };
            long ret = syscall(SYS_vmsplice, pfd[1], &iov, 1, 0);
            printf("  vmsplice: ret=%ld errno=%d %s\n",
                   ret, ret < 0 ? errno : 0,
                   ret > 0 ? "OK" : "BLOCKED");

            /* splice test */
            int tmpfd = open("/dev/null", O_WRONLY);
            if (tmpfd >= 0 && ret > 0) {
                ret = syscall(SYS_splice, pfd[0], NULL, tmpfd, NULL, 4096, 0);
                printf("  splice: ret=%ld errno=%d %s\n",
                       ret, ret < 0 ? errno : 0,
                       ret > 0 ? "OK" : "BLOCKED");
                close(tmpfd);
            }

            close(pfd[0]);
            close(pfd[1]);
        }
    }

    /* === 4. Kernel hardening detection === */
    printf("\n--- Kernel hardening features ---\n");
    {
        /* PaX flags */
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "PaX") || strstr(line, "Grsec") ||
                    strstr(line, "NoNewPrivs") || strstr(line, "Seccomp") ||
                    strstr(line, "CapBnd") || strstr(line, "CapEff") ||
                    strstr(line, "Cpus_allowed"))
                    printf("  %s", line);
            }
            fclose(f);
        }

        /* Check for PaX in /proc/self/maps (mprotect restrictions) */
        f = fopen("/proc/self/maps", "r");
        if (f) {
            char line[256];
            int count = 0;
            int wx = 0;
            while (fgets(line, sizeof(line), f)) {
                count++;
                /* Check for W+X mappings */
                if (strlen(line) > 20 && line[1] == 'w' && line[2] == 'x')
                    wx++;
            }
            printf("  Total mappings: %d, W+X mappings: %d\n", count, wx);
            fclose(f);
        }

        /* Check for GRSEC sysctl */
        const char *sysctl_paths[] = {
            "/proc/sys/kernel/grsecurity/audit_group",
            "/proc/sys/kernel/grsecurity/chroot_deny_mount",
            "/proc/sys/kernel/grsecurity/deny_new_usb",
            "/proc/sys/kernel/grsecurity/dmesg",
            "/proc/sys/kernel/grsecurity/harden_ipc",
            "/proc/sys/kernel/grsecurity/rwxmap_logging",
            NULL
        };

        printf("  GRSEC sysctls:\n");
        for (int i = 0; sysctl_paths[i]; i++) {
            f = fopen(sysctl_paths[i], "r");
            if (f) {
                char val[32] = {0};
                fgets(val, sizeof(val), f);
                fclose(f);
                /* Get basename */
                const char *name = strrchr(sysctl_paths[i], '/') + 1;
                printf("    %s = %s", name, val);
            }
        }

        /* PAX mprotect test — can we make an anonymous mapping executable? */
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            int ret = mprotect(p, 4096, PROT_READ | PROT_EXEC);
            printf("  PAX_MPROTECT (RW→RX): %s (errno=%d)\n",
                   ret == 0 ? "ALLOWED" : "BLOCKED", ret < 0 ? errno : 0);

            /* Try RWX */
            void *p2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            printf("  PAX_MPROTECT (RWX mmap): %s (errno=%d)\n",
                   p2 != MAP_FAILED ? "ALLOWED" : "BLOCKED",
                   p2 == MAP_FAILED ? errno : 0);
            if (p2 != MAP_FAILED) munmap(p2, 4096);

            munmap(p, 4096);
        }

        /* Can we execute on stack? */
        printf("  Stack: ");
        void *stack_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack_page != MAP_FAILED) {
            int ret = mprotect(stack_page, 4096, PROT_READ | PROT_EXEC);
            printf("exec %s\n", ret == 0 ? "ALLOWED" : "BLOCKED");
            munmap(stack_page, 4096);
        } else {
            printf("MAP_STACK failed\n");
        }
    }

    /* === 5. Check for alternative write primitives === */
    printf("\n--- Alternative write primitives ---\n");
    {
        /* Can we use sendfile to trigger COW? */
        int tmpfd = open("/data/local/tmp/cow_alt_test", O_CREAT | O_RDWR, 0644);
        if (tmpfd >= 0) {
            write(tmpfd, "TESTDATA12345678", 16);
            close(tmpfd);

            /* mmap it RO + MAP_PRIVATE */
            int rofd = open("/data/local/tmp/cow_alt_test", O_RDONLY);
            if (rofd >= 0) {
                void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, rofd, 0);
                if (m != MAP_FAILED) {
                    printf("  RO MAP_PRIVATE: %.16s\n", (char *)m);

                    /* Try mprotect to make it writable */
                    int ret = mprotect(m, 4096, PROT_READ | PROT_WRITE);
                    printf("  mprotect(RO→RW): %s (errno=%d)\n",
                           ret == 0 ? "ALLOWED(!)" : "BLOCKED",
                           ret < 0 ? errno : 0);

                    if (ret == 0) {
                        /* This would be a way to trigger COW without /proc/self/mem */
                        char *cp = (char *)m;
                        cp[0] = 'X';
                        printf("  Write through mprotect'd mapping: %c\n", cp[0]);

                        /* Check if the file was modified */
                        close(rofd);
                        rofd = open("/data/local/tmp/cow_alt_test", O_RDONLY);
                        if (rofd >= 0) {
                            char buf[32] = {0};
                            read(rofd, buf, 16);
                            printf("  File after write: %.16s %s\n", buf,
                                   buf[0] == 'X' ? "FILE MODIFIED!" : "(file unchanged, COW worked correctly)");
                        }
                    }

                    munmap(m, 4096);
                }
                close(rofd);
            }
            unlink("/data/local/tmp/cow_alt_test");
        }
    }

    /* === 6. fork() capability check === */
    printf("\n--- fork() and exec capabilities ---\n");
    {
        pid_t pid = fork();
        if (pid < 0) {
            printf("  fork(): %s\n", strerror(errno));
        } else if (pid == 0) {
            /* Child */
            _exit(42);
        } else {
            int status;
            waitpid(pid, &status, 0);
            printf("  fork(): OK (child exited %d)\n", WEXITSTATUS(status));
        }

        /* Can we exec anything useful? */
        /* Check if run-as exists and is SUID */
        struct stat st;
        const char *suid_bins[] = {
            "/system/bin/run-as", "/system/xbin/su",
            "/system/bin/su", "/sbin/su",
            NULL
        };
        for (int i = 0; suid_bins[i]; i++) {
            if (stat(suid_bins[i], &st) == 0) {
                printf("  %s: mode=%o uid=%d gid=%d",
                       suid_bins[i], st.st_mode & 07777,
                       st.st_uid, st.st_gid);
                if (st.st_mode & S_ISUID) printf(" SUID!");
                if (st.st_mode & S_ISGID) printf(" SGID!");
                printf("\n");
            }
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
