#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <signal.h>
#include <linux/futex.h>
#include <dirent.h>

/*
 * Broad attack surface probe for kernel 3.10.84 on BlackBerry Priv
 *
 * 1. Network socket types (AF_NETLINK, AF_PACKET, AF_KEY, etc.)
 * 2. Futex operations (CVE-2014-3153 requeue detection)
 * 3. perf_event_open (various configs)
 * 4. Device files (/dev/ion, /dev/msm_*, etc.)
 * 5. Writable sysfs/proc/debugfs entries
 * 6. Additional syscalls (prctl, personality, etc.)
 */

/* perf_event_open syscall */
struct perf_event_attr_min {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;       /* disabled, inherit, etc. */
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t bp_addr;
    uint64_t bp_len;
};

int main(void) {
    printf("=== Broad Attack Surface Probe ===\n");
    printf("uid=%d pid=%d\n\n", getuid(), getpid());
    signal(SIGPIPE, SIG_IGN);

    /* === 1. Network socket types === */
    printf("--- Network socket types ---\n");
    {
        struct { int domain; int type; int proto; const char *name; } socks[] = {
            /* Netlink families */
            {16, SOCK_RAW, 0,  "NETLINK_ROUTE"},
            {16, SOCK_RAW, 1,  "NETLINK_UNUSED"},
            {16, SOCK_RAW, 4,  "NETLINK_FIREWALL"},
            {16, SOCK_RAW, 6,  "NETLINK_NFLOG"},
            {16, SOCK_RAW, 7,  "NETLINK_SELINUX"},
            {16, SOCK_RAW, 9,  "NETLINK_AUDIT"},
            {16, SOCK_RAW, 11, "NETLINK_KOBJECT_UEVENT"},
            {16, SOCK_RAW, 12, "NETLINK_GENERIC"},
            {16, SOCK_RAW, 15, "NETLINK_CONNECTOR"},
            {16, SOCK_DGRAM, 0, "NETLINK_ROUTE(DGRAM)"},
            /* Other families */
            {17, SOCK_RAW, 0x0300, "AF_PACKET(ETH_P_ALL)"},
            {17, SOCK_DGRAM, 0x0300, "AF_PACKET(DGRAM)"},
            {15, 2, 2, "AF_KEY"},
            {10, SOCK_STREAM, 6, "AF_INET6_TCP"},
            {10, SOCK_DGRAM, 17, "AF_INET6_UDP"},
            {10, SOCK_RAW, 58, "AF_INET6_ICMPv6"},
            {2, SOCK_RAW, 1, "AF_INET_RAW_ICMP"},
            {2, SOCK_RAW, 255, "AF_INET_RAW_255"},
            {1, SOCK_STREAM, 0, "AF_UNIX_STREAM"},
            {1, SOCK_DGRAM, 0, "AF_UNIX_DGRAM"},
            {1, SOCK_SEQPACKET, 0, "AF_UNIX_SEQPACKET"},
            {38, SOCK_STREAM, 0, "AF_QIPCRTR"},
            {27, SOCK_STREAM, 0, "AF_CAN"},
            {-1, -1, -1, NULL}
        };

        for (int i = 0; socks[i].domain >= 0; i++) {
            int s = socket(socks[i].domain, socks[i].type, socks[i].proto);
            printf("  %-28s: %s", socks[i].name,
                   s >= 0 ? "OK" : "FAIL");
            if (s < 0) printf(" (errno=%d)", errno);
            else close(s);
            printf("\n");
        }
    }

    /* === 2. Futex operations === */
    printf("\n--- Futex operations ---\n");
    {
        volatile int futex_val = 0;

        /* Basic operations */
        struct { int op; const char *name; } futex_ops[] = {
            {FUTEX_WAIT, "WAIT"},
            {FUTEX_WAKE, "WAKE"},
            {FUTEX_REQUEUE, "REQUEUE"},
            {FUTEX_CMP_REQUEUE, "CMP_REQUEUE"},
            {FUTEX_WAKE_OP, "WAKE_OP"},
            {FUTEX_WAIT_BITSET, "WAIT_BITSET"},
            {FUTEX_WAKE_BITSET, "WAKE_BITSET"},
            {FUTEX_LOCK_PI, "LOCK_PI"},
            {FUTEX_UNLOCK_PI, "UNLOCK_PI"},
            {FUTEX_TRYLOCK_PI, "TRYLOCK_PI"},
            {FUTEX_WAIT_REQUEUE_PI, "WAIT_REQUEUE_PI"},
            {FUTEX_CMP_REQUEUE_PI, "CMP_REQUEUE_PI"},
            {-1, NULL}
        };

        for (int i = 0; futex_ops[i].op >= 0; i++) {
            long ret;
            struct timespec ts = {0, 1000}; /* 1us timeout */
            volatile int futex2 = 0;

            switch (futex_ops[i].op) {
            case FUTEX_WAIT:
                /* Will return immediately since val != expected */
                ret = syscall(SYS_futex, &futex_val, FUTEX_WAIT, 1, &ts, NULL, 0);
                break;
            case FUTEX_WAKE:
                ret = syscall(SYS_futex, &futex_val, FUTEX_WAKE, 1, NULL, NULL, 0);
                break;
            case FUTEX_REQUEUE:
                ret = syscall(SYS_futex, &futex_val, FUTEX_REQUEUE, 0, (void*)1, &futex2, 0);
                break;
            case FUTEX_CMP_REQUEUE:
                ret = syscall(SYS_futex, &futex_val, FUTEX_CMP_REQUEUE, 0, (void*)1, &futex2, 0);
                break;
            case FUTEX_CMP_REQUEUE_PI:
                ret = syscall(SYS_futex, &futex_val, FUTEX_CMP_REQUEUE_PI, 0, (void*)1, &futex2, 0);
                break;
            case FUTEX_LOCK_PI:
                ret = syscall(SYS_futex, &futex_val, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
                break;
            case FUTEX_UNLOCK_PI:
                ret = syscall(SYS_futex, &futex_val, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
                break;
            case FUTEX_WAIT_REQUEUE_PI:
                ret = syscall(SYS_futex, &futex_val, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &futex2, 0);
                break;
            default:
                ret = syscall(SYS_futex, &futex_val, futex_ops[i].op, 1, &ts, NULL, 0);
                break;
            }
            printf("  %-20s: ret=%ld errno=%d\n", futex_ops[i].name,
                   ret, ret < 0 ? errno : 0);
        }

        /* CVE-2014-3153 specific test: REQUEUE_PI to non-PI futex
         * The bug: FUTEX_CMP_REQUEUE_PI allows requeuing from a PI futex
         * to a non-PI futex, which corrupts the waiter's state.
         * If this returns -1/EINVAL, it's likely patched.
         * If it returns 0 or succeeds in an unexpected way, it may be vulnerable. */
        printf("\n  CVE-2014-3153 indicator:\n");
        {
            volatile int pi_futex = 0;
            volatile int non_pi_futex = 0;

            /* Try requeue from non-PI to PI (should fail safely if patched) */
            long ret = syscall(SYS_futex, &non_pi_futex, FUTEX_CMP_REQUEUE_PI,
                              1, (void *)1, &pi_futex, non_pi_futex);
            printf("    non-PI→PI requeue: ret=%ld errno=%d %s\n",
                   ret, ret < 0 ? errno : 0,
                   (ret < 0 && errno == EINVAL) ? "(likely patched)" :
                   ret == 0 ? "(returned 0 — investigate!)" : "");
        }
    }

    /* === 3. perf_event_open === */
    printf("\n--- perf_event_open ---\n");
    {
        struct perf_event_attr_min attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);

        /* Try various perf types */
        struct { uint32_t type; uint64_t config; const char *name; } perf_tests[] = {
            {0, 0, "HARDWARE/CYCLES"},
            {0, 1, "HARDWARE/INSTRUCTIONS"},
            {1, 0, "SOFTWARE/CPU_CLOCK"},
            {1, 1, "SOFTWARE/TASK_CLOCK"},
            {1, 6, "SOFTWARE/PAGE_FAULTS_MAJ"},
            {1, 9, "SOFTWARE/DUMMY"},
            {2, 0, "TRACEPOINT/0"},
            {3, 0, "HW_CACHE/0"},
            {4, 0, "RAW/0"},
            {5, 0, "BREAKPOINT/0"},
            {-1, 0, NULL}
        };

        for (int i = 0; perf_tests[i].name; i++) {
            attr.type = perf_tests[i].type;
            attr.config = perf_tests[i].config;
            attr.flags = 1; /* disabled */
            int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
            printf("  %-26s: %s", perf_tests[i].name,
                   fd >= 0 ? "OK" : "FAIL");
            if (fd < 0) printf(" (errno=%d)", errno);
            else {
                /* Can we mmap the perf ring buffer? */
                void *p = mmap(NULL, 4096 * 2, PROT_READ, MAP_SHARED, fd, 0);
                if (p != MAP_FAILED) {
                    printf(" [mmap OK]");
                    munmap(p, 4096 * 2);
                }
                close(fd);
            }
            printf("\n");
        }
    }

    /* === 4. Device files === */
    printf("\n--- Device files ---\n");
    {
        const char *devs[] = {
            "/dev/ion",
            "/dev/alarm",
            "/dev/ashmem",
            "/dev/binder",
            "/dev/hwbinder",
            "/dev/vndbinder",
            "/dev/msm_thermal_query",
            "/dev/diag",
            "/dev/tty",
            "/dev/ptmx",
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
            "/dev/fuse",
            "/dev/device-mapper",
            "/dev/loop0",
            "/dev/snd/timer",
            "/dev/snd/hwC0D0",
            "/dev/video0",
            "/dev/media0",
            "/dev/msm_camera",
            "/dev/v4l-subdev0",
            "/dev/qseecom",
            "/dev/adsprpc-smd",
            "/dev/msm_aac",
            "/dev/msm_amrnb",
            "/dev/cpu_dma_latency",
            "/dev/xt_qtaguid",
            "/dev/socket/zygote",
            "/dev/socket/property_service",
            NULL
        };

        for (int i = 0; devs[i]; i++) {
            struct stat st;
            if (stat(devs[i], &st) == 0) {
                int fd = open(devs[i], O_RDWR);
                if (fd < 0) fd = open(devs[i], O_RDONLY);
                printf("  %-32s mode=%04o %s", devs[i],
                       st.st_mode & 07777,
                       fd >= 0 ? "OPEN" : "NOACCESS");
                if (fd < 0) printf(" (errno=%d)", errno);
                if (st.st_mode & S_ISUID) printf(" SUID");
                if (st.st_mode & S_ISGID) printf(" SGID");
                if (S_ISCHR(st.st_mode)) printf(" CHR(%d,%d)", (int)(st.st_rdev >> 8), (int)(st.st_rdev & 0xff));
                if (fd >= 0) close(fd);
                printf("\n");
            }
        }

        /* Also scan /dev for anything world-writable */
        printf("\n  World-writable /dev entries:\n");
        DIR *d = opendir("/dev");
        if (d) {
            struct dirent *de;
            int cnt = 0;
            while ((de = readdir(d)) != NULL && cnt < 50) {
                char path[256];
                snprintf(path, sizeof(path), "/dev/%s", de->d_name);
                struct stat st;
                if (stat(path, &st) == 0 && (st.st_mode & S_IWOTH)) {
                    printf("    %s (mode=%04o)\n", path, st.st_mode & 07777);
                    cnt++;
                }
            }
            closedir(d);
        }
    }

    /* === 5. Android sockets === */
    printf("\n--- Android sockets ---\n");
    {
        const char *sock_paths[] = {
            "/dev/socket/zygote",
            "/dev/socket/property_service",
            "/dev/socket/logd",
            "/dev/socket/logdr",
            "/dev/socket/logdw",
            "/dev/socket/lmkd",
            "/dev/socket/installd",
            "/dev/socket/netd",
            "/dev/socket/vold",
            "/dev/socket/dnsproxyd",
            "/dev/socket/mdns",
            "/dev/socket/adbd",
            NULL
        };

        for (int i = 0; sock_paths[i]; i++) {
            struct stat st;
            if (stat(sock_paths[i], &st) == 0) {
                /* Try connecting */
                int s = socket(AF_UNIX, SOCK_STREAM, 0);
                if (s >= 0) {
                    struct sockaddr_un {
                        uint16_t sun_family;
                        char sun_path[108];
                    } addr;
                    addr.sun_family = 1; /* AF_UNIX */
                    strncpy(addr.sun_path, sock_paths[i], sizeof(addr.sun_path) - 1);
                    int ret = connect(s, (struct sockaddr *)&addr,
                                     sizeof(uint16_t) + strlen(sock_paths[i]) + 1);
                    printf("  %-36s mode=%04o connect=%s",
                           sock_paths[i], st.st_mode & 07777,
                           ret == 0 ? "OK(!)" : "FAIL");
                    if (ret < 0) printf(" (errno=%d)", errno);
                    close(s);
                    printf("\n");
                }
            }
        }
    }

    /* === 6. prctl and personality === */
    printf("\n--- prctl capabilities ---\n");
    {
        #include <sys/prctl.h>

        /* PR_SET_NO_NEW_PRIVS */
        int nnp = prctl(39 /*PR_GET_NO_NEW_PRIVS*/, 0, 0, 0, 0);
        printf("  NO_NEW_PRIVS: %d\n", nnp);

        /* PR_SET_DUMPABLE */
        int dumpable = prctl(3 /*PR_GET_DUMPABLE*/, 0, 0, 0, 0);
        printf("  DUMPABLE: %d\n", dumpable);

        /* PR_GET_SECUREBITS */
        int secbits = prctl(27 /*PR_GET_SECUREBITS*/, 0, 0, 0, 0);
        printf("  SECUREBITS: 0x%x\n", secbits);

        /* Personality */
        long pers = syscall(SYS_personality, 0xffffffff);
        printf("  PERSONALITY: 0x%lx\n", pers);

        /* Try to change to ADDR_NO_RANDOMIZE */
        long ret = syscall(SYS_personality, pers | 0x0040000);
        printf("  ADDR_NO_RANDOMIZE: %s\n", ret >= 0 ? "SET OK" : "FAIL");
        syscall(SYS_personality, pers); /* restore */

        /* PR_SET_CHILD_SUBREAPER */
        ret = prctl(36 /*PR_SET_CHILD_SUBREAPER*/, 1, 0, 0, 0);
        printf("  CHILD_SUBREAPER: %s\n", ret == 0 ? "OK" : "FAIL");
    }

    /* === 7. Writable /proc and /sys entries === */
    printf("\n--- Writable /proc and /sys entries ---\n");
    {
        const char *paths[] = {
            "/proc/sys/kernel/sched_child_runs_first",
            "/proc/sys/kernel/shmmax",
            "/proc/sys/kernel/shmall",
            "/proc/sys/kernel/core_pattern",
            "/proc/sys/kernel/modprobe",
            "/proc/sys/kernel/hotplug",
            "/proc/sys/kernel/poweroff_cmd",
            "/proc/sys/vm/drop_caches",
            "/proc/sys/vm/overcommit_memory",
            "/proc/sys/vm/mmap_min_addr",
            "/proc/sys/fs/protected_hardlinks",
            "/proc/sys/fs/protected_symlinks",
            "/proc/sysrq-trigger",
            "/sys/kernel/uevent_helper",
            "/sys/kernel/security/lsm",
            "/proc/sys/net/core/bpf_jit_enable",
            "/proc/sys/kernel/perf_event_paranoid",
            NULL
        };

        for (int i = 0; paths[i]; i++) {
            /* Try to read current value */
            int fd = open(paths[i], O_RDONLY);
            char val[64] = {0};
            if (fd >= 0) {
                int n = read(fd, val, sizeof(val) - 1);
                if (n > 0 && val[n-1] == '\n') val[n-1] = 0;
                close(fd);
            }

            /* Try to write */
            fd = open(paths[i], O_WRONLY);
            printf("  %-48s %s val=%s\n", paths[i],
                   fd >= 0 ? "WRITABLE(!)" : "readonly",
                   val[0] ? val : "N/A");
            if (fd >= 0) close(fd);
        }

        /* Check perf_event_paranoid specifically */
        int fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
        if (fd >= 0) {
            char val[16] = {0};
            read(fd, val, sizeof(val));
            close(fd);
            printf("  perf_event_paranoid = %s", val);
        }
    }

    /* === 8. sysfs writable scan (key directories) === */
    printf("\n--- /sys writable entries (key dirs) ---\n");
    {
        const char *dirs[] = {
            "/sys/kernel/",
            "/sys/module/",
            "/sys/class/leds/",
            NULL
        };

        for (int d = 0; dirs[d]; d++) {
            DIR *dp = opendir(dirs[d]);
            if (!dp) continue;
            struct dirent *de;
            int found = 0;
            while ((de = readdir(dp)) != NULL && found < 10) {
                if (de->d_name[0] == '.') continue;
                char path[256];
                snprintf(path, sizeof(path), "%s%s", dirs[d], de->d_name);
                struct stat st;
                if (stat(path, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & S_IWOTH)) {
                    printf("  %s (mode=%04o)\n", path, st.st_mode & 07777);
                    found++;
                }
            }
            closedir(dp);
        }
    }

    /* === 9. Check for kernel version specifics === */
    printf("\n--- Kernel specifics ---\n");
    {
        /* dmesg access */
        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        printf("  /dev/kmsg: %s\n", fd >= 0 ? "readable" : "noaccess");
        if (fd >= 0) close(fd);

        /* kptr_restrict */
        fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
        if (fd >= 0) {
            char val[8] = {0};
            read(fd, val, sizeof(val));
            close(fd);
            printf("  kptr_restrict: %s", val);
        }

        /* kallsyms */
        fd = open("/proc/kallsyms", O_RDONLY);
        if (fd >= 0) {
            char line[128] = {0};
            read(fd, line, sizeof(line) - 1);
            close(fd);
            printf("  kallsyms first line: %s", line);
        }

        /* Modules */
        fd = open("/proc/modules", O_RDONLY);
        if (fd >= 0) {
            char buf[512] = {0};
            int n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            printf("  modules: %s\n", n > 0 ? "readable" : "empty");
            if (n > 0) {
                /* Count modules */
                int cnt = 0;
                for (int i = 0; i < n; i++)
                    if (buf[i] == '\n') cnt++;
                printf("  (first %d modules visible)\n", cnt);
            }
        }
    }

    printf("\n=== Done ===\n");
    return 0;
}
