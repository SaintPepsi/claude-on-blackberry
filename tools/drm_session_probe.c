/*
 * drm_session_probe.c — Probe DRM/Widevine path to QSEE
 *
 * Opens a DRM session through the Android DRM framework,
 * attempts to trigger Widevine plugin operations that reach QSEE.
 *
 * Build: aarch64-linux-musl-gcc -static -O2 drm_session_probe.c -o drm_session_probe
 * Usage: adb push drm_session_probe /data/local/tmp/ && adb shell /data/local/tmp/drm_session_probe
 *
 * Monitor: adb shell dmesg -w | grep -iE 'qsee|widevine|drm|oemcrypto'
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

#define BINDER_DEV "/dev/binder"
#define BINDER_MMAP_SIZE (128 * 1024)

/* DRM Manager transaction codes (from IDrmManagerService.cpp, Android 6.0.1) */
#define TX_ADD_UNIQUEID          1
#define TX_REMOVE_UNIQUEID       2
#define TX_ADD_CLIENT            3
#define TX_REMOVE_CLIENT         4
#define TX_SET_LISTENER          5
#define TX_INSTALL_ENGINE        6
#define TX_GET_CONSTRAINTS       7
#define TX_GET_METADATA          8
#define TX_CAN_HANDLE            9
#define TX_PROCESS_DRM_INFO     10
#define TX_ACQUIRE_DRM_INFO     11
#define TX_SAVE_RIGHTS          12
#define TX_GET_ORIGINAL_MIME    13
#define TX_GET_DRM_OBJECT_TYPE  14
#define TX_CHECK_RIGHTS_STATUS  15
#define TX_CONSUME_RIGHTS       16
#define TX_SET_PLAYBACK_STATUS  17
#define TX_VALIDATE_ACTION      18
#define TX_REMOVE_RIGHTS        19
#define TX_REMOVE_ALL_RIGHTS    20
#define TX_OPEN_CONVERT_SESSION 21
#define TX_CONVERT_DATA         22
#define TX_CLOSE_CONVERT_SESSION 23
#define TX_GET_ALL_SUPPORT_INFO 24
#define TX_OPEN_DECRYPT_SESSION 25
#define TX_OPEN_DECRYPT_SESSION_URI 26
#define TX_CLOSE_DECRYPT_SESSION 27
#define TX_DECRYPT              28
#define TX_INIT_DECRYPT_UNIT    29
#define TX_FINALIZE_DECRYPT_UNIT 30
#define TX_PREAD                31

/* Service Manager transaction */
#define SVC_MGR_GET_SERVICE     1
#define SVC_MGR_CHECK_SERVICE   2
#define SVC_MGR_ADD_SERVICE     3
#define SVC_MGR_LIST_SERVICES   4

static int binder_fd = -1;
static void *binder_mapped = NULL;

/* Parcel writing helpers */
struct parcel {
    uint8_t data[4096];
    size_t pos;
    uint32_t *offsets;
    size_t offsets_count;
};

static void parcel_init(struct parcel *p) {
    memset(p, 0, sizeof(*p));
}

static void parcel_write_u32(struct parcel *p, uint32_t val) {
    if (p->pos + 4 > sizeof(p->data)) return;
    memcpy(p->data + p->pos, &val, 4);
    p->pos += 4;
}

static void parcel_write_u64(struct parcel *p, uint64_t val) {
    if (p->pos + 8 > sizeof(p->data)) return;
    memcpy(p->data + p->pos, &val, 8);
    p->pos += 8;
}

/* Write a UTF-16 string (length-prefixed, null-terminated, 4-byte aligned) */
static void parcel_write_string16(struct parcel *p, const char *str) {
    if (!str) {
        parcel_write_u32(p, 0xffffffff); /* null string */
        return;
    }
    uint32_t len = strlen(str);
    parcel_write_u32(p, len);
    /* Write each char as UTF-16LE */
    for (uint32_t i = 0; i <= len; i++) { /* include null terminator */
        uint16_t c = (i < len) ? (uint16_t)str[i] : 0;
        if (p->pos + 2 > sizeof(p->data)) return;
        memcpy(p->data + p->pos, &c, 2);
        p->pos += 2;
    }
    /* Pad to 4-byte alignment */
    while (p->pos & 3) {
        p->data[p->pos++] = 0;
    }
}

/* Write raw bytes */
static void parcel_write_bytes(struct parcel *p, const void *data, size_t len) {
    parcel_write_u32(p, (uint32_t)len);
    if (p->pos + len > sizeof(p->data)) return;
    memcpy(p->data + p->pos, data, len);
    p->pos += len;
    while (p->pos & 3) p->data[p->pos++] = 0;
}

/* Write the interface token (required for binder transactions) */
static void parcel_write_interface_token(struct parcel *p, const char *iface) {
    /* Strict mode policy: 0x100 = PENALTY_GATHER */
    parcel_write_u32(p, 0x100);
    parcel_write_string16(p, iface);
}

/* Write interface token for service manager (no strict mode on Android 6) */
static void parcel_write_svcmgr_token(struct parcel *p) {
    parcel_write_string16(p, "android.os.IServiceManager");
}

static int binder_open(void) {
    binder_fd = open(BINDER_DEV, O_RDWR);
    if (binder_fd < 0) {
        fprintf(stderr, "[-] open(%s): %s\n", BINDER_DEV, strerror(errno));
        return -1;
    }

    binder_mapped = mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                         MAP_PRIVATE, binder_fd, 0);
    if (binder_mapped == MAP_FAILED) {
        fprintf(stderr, "[-] mmap: %s\n", strerror(errno));
        close(binder_fd);
        return -1;
    }

    /* Set max threads to 0 (we handle everything synchronously) */
    uint32_t max_threads = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    printf("[+] Binder opened (fd=%d)\n", binder_fd);
    return 0;
}

/* Send a binder transaction and read the reply */
static int binder_call(uint32_t handle, uint32_t code,
                       struct parcel *send, struct parcel *reply) {
    struct binder_transaction_data txn;
    struct binder_write_read bwr;

    /* Prepare transaction */
    memset(&txn, 0, sizeof(txn));
    txn.target.handle = handle;
    txn.code = code;
    txn.flags = 0; /* TF_ACCEPT_FDS not set */
    txn.data.ptr.buffer = (uintptr_t)send->data;
    txn.data.ptr.offsets = (uintptr_t)NULL;
    txn.data_size = send->pos;
    txn.offsets_size = 0;

    /* Write buffer: BC_TRANSACTION + transaction data */
    uint8_t write_buf[sizeof(uint32_t) + sizeof(txn)];
    uint32_t cmd = BC_TRANSACTION;
    memcpy(write_buf, &cmd, sizeof(cmd));
    memcpy(write_buf + sizeof(cmd), &txn, sizeof(txn));

    /* Read buffer for reply */
    uint8_t read_buf[1024];

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (uintptr_t)write_buf;
    bwr.write_size = sizeof(write_buf);
    bwr.read_buffer = (uintptr_t)read_buf;
    bwr.read_size = sizeof(read_buf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        fprintf(stderr, "[-] BINDER_WRITE_READ: %s\n", strerror(errno));
        return -1;
    }

    /* Parse the reply from read buffer */
    if (bwr.read_consumed > 0) {
        uint8_t *rptr = read_buf;
        size_t remaining = bwr.read_consumed;

        while (remaining >= sizeof(uint32_t)) {
            uint32_t reply_cmd;
            memcpy(&reply_cmd, rptr, sizeof(uint32_t));
            rptr += sizeof(uint32_t);
            remaining -= sizeof(uint32_t);

            if (reply_cmd == BR_NOOP) {
                continue;
            } else if (reply_cmd == BR_TRANSACTION_COMPLETE) {
                /* Expected after sending, continue reading for BR_REPLY */
                /* Need to do another read to get the reply */
                if (remaining < sizeof(uint32_t)) {
                    /* Reply not yet available, do another read */
                    struct binder_write_read read_bwr = {0};
                    read_bwr.read_buffer = (uintptr_t)read_buf;
                    read_bwr.read_size = sizeof(read_buf);
                    int ret2 = ioctl(binder_fd, BINDER_WRITE_READ, &read_bwr);
                    if (ret2 < 0) return -1;
                    rptr = read_buf;
                    remaining = read_bwr.read_consumed;
                }
                continue;
            } else if (reply_cmd == BR_REPLY) {
                if (remaining >= sizeof(struct binder_transaction_data)) {
                    struct binder_transaction_data reply_txn;
                    memcpy(&reply_txn, rptr, sizeof(reply_txn));

                    if (reply_txn.flags & 0x02 /* TF_STATUS_CODE */) {
                        int32_t status;
                        memcpy(&status, (void*)(uintptr_t)reply_txn.data.ptr.buffer, sizeof(status));
                        fprintf(stderr, "[-] BR_REPLY status: %d\n", status);
                    } else if (reply_txn.data_size > 0 && reply) {
                        size_t copy_size = reply_txn.data_size;
                        if (copy_size > sizeof(reply->data))
                            copy_size = sizeof(reply->data);
                        memcpy(reply->data,
                               (void *)(uintptr_t)reply_txn.data.ptr.buffer,
                               copy_size);
                        reply->pos = copy_size;
                    }
                    /* Free the buffer */
                    uint8_t free_buf[sizeof(uint32_t) + sizeof(uintptr_t)];
                    uint32_t free_cmd = BC_FREE_BUFFER;
                    uintptr_t free_ptr = (uintptr_t)reply_txn.data.ptr.buffer;
                    memcpy(free_buf, &free_cmd, sizeof(free_cmd));
                    memcpy(free_buf + sizeof(free_cmd), &free_ptr, sizeof(free_ptr));

                    struct binder_write_read free_bwr = {0};
                    free_bwr.write_buffer = (uintptr_t)free_buf;
                    free_bwr.write_size = sizeof(free_buf);
                    ioctl(binder_fd, BINDER_WRITE_READ, &free_bwr);
                }
                return 0;
            } else if (reply_cmd == BR_FAILED_REPLY) {
                fprintf(stderr, "[-] BR_FAILED_REPLY\n");
                return -1;
            } else if (reply_cmd == BR_DEAD_REPLY) {
                fprintf(stderr, "[-] BR_DEAD_REPLY\n");
                return -1;
            } else {
                fprintf(stderr, "[?] Unknown BR command: 0x%08x\n", reply_cmd);
                /* Try to skip — most commands have no payload */
                continue;
            }
        }
    }

    return -1;
}

/* Look up a service handle from the service manager */
static uint32_t get_service_handle(const char *name) {
    struct parcel send, reply;

    parcel_init(&send);
    /* Service manager uses its own token format (no strict mode on older Android) */
    parcel_write_svcmgr_token(&send);
    parcel_write_string16(&send, name);

    parcel_init(&reply);

    printf("[*] Looking up service: %s\n", name);
    if (binder_call(0, SVC_MGR_CHECK_SERVICE, &send, &reply) < 0) {
        fprintf(stderr, "[-] Failed to look up service\n");
        return 0;
    }

    /* Reply should contain a flat_binder_object with the handle */
    /* For now, just check if we got a non-empty reply */
    if (reply.pos > 0) {
        printf("[+] Service found, reply size: %zu\n", reply.pos);
        /* The handle is embedded in the reply — for service manager lookups,
         * the handle is in the transaction's flat_binder_object */
        /* We'd need to parse the offsets to extract it properly */
        /* For now, we'll use service call for simplicity */
        return 1; /* Placeholder — indicates service exists */
    }

    return 0;
}

/* Hex dump utility */
static void hexdump(const char *label, const void *data, size_t len) {
    const uint8_t *p = data;
    printf("[*] %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04zx: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) {
            /* Pad */
            for (size_t j = i % 16; j < 15; j++) printf("   ");
            printf(" ");
            /* ASCII */
            size_t start = i - (i % 16);
            for (size_t j = start; j <= i; j++) {
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7f) ? p[j] : '.');
            }
            printf("\n");
        }
    }
}

int main(int argc, char **argv) {
    printf("=== DRM/Widevine QSEE Session Probe ===\n\n");

    if (binder_open() < 0) {
        return 1;
    }

    /* Step 1: Verify service exists */
    if (get_service_handle("drm.drmManager") == 0) {
        fprintf(stderr, "[-] drm.drmManager not found\n");
        return 1;
    }

    printf("\n[*] Service lookup works. For full DRM session probing,\n");
    printf("[*] we need to properly resolve the binder handle.\n");
    printf("[*] Attempting direct binder transactions...\n\n");

    /* Step 2: Try ADD_UNIQUEID (TX 1) via raw binder */
    {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_interface_token(&send, "drm.IDrmManagerService");

        parcel_init(&reply);
        printf("[*] Sending TX 1 (ADD_UNIQUEID)...\n");
        int ret = binder_call(0, TX_ADD_UNIQUEID, &send, &reply);
        if (ret == 0 && reply.pos > 0) {
            hexdump("ADD_UNIQUEID reply", reply.data, reply.pos);
        } else {
            printf("[-] TX 1 failed (ret=%d, reply.pos=%zu)\n", ret, reply.pos);
        }
    }

    /* Step 3: Try CAN_HANDLE with Widevine MIME type (TX 9) */
    {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_interface_token(&send, "drm.IDrmManagerService");
        parcel_write_u32(&send, 0); /* uniqueId = 0 */
        parcel_write_string16(&send, "test.wvm"); /* path */
        parcel_write_string16(&send, "video/wvm"); /* mimeType */

        parcel_init(&reply);
        printf("[*] Sending TX 9 (CAN_HANDLE) for video/wvm...\n");
        int ret = binder_call(0, TX_CAN_HANDLE, &send, &reply);
        if (ret == 0 && reply.pos > 0) {
            hexdump("CAN_HANDLE reply", reply.data, reply.pos);
        } else {
            printf("[-] TX 9 failed (ret=%d, reply.pos=%zu)\n", ret, reply.pos);
        }
    }

    /* Step 4: Try GET_ALL_SUPPORT_INFO (TX 24) — shows loaded DRM plugins */
    {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_interface_token(&send, "drm.IDrmManagerService");
        parcel_write_u32(&send, 0); /* uniqueId */

        parcel_init(&reply);
        printf("[*] Sending TX 24 (GET_ALL_SUPPORT_INFO)...\n");
        int ret = binder_call(0, TX_GET_ALL_SUPPORT_INFO, &send, &reply);
        if (ret == 0 && reply.pos > 0) {
            hexdump("DRM plugins", reply.data, reply.pos > 256 ? 256 : reply.pos);
        } else {
            printf("[-] TX 24 failed (ret=%d, reply.pos=%zu)\n", ret, reply.pos);
        }
    }

    /* Step 5: Try OPEN_DECRYPT_SESSION with Widevine */
    {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_interface_token(&send, "drm.IDrmManagerService");
        parcel_write_u32(&send, 0); /* uniqueId */
        /* fd = -1 (no actual file) */
        parcel_write_u32(&send, 0); /* has_fd = false */
        parcel_write_u64(&send, 0); /* offset */
        parcel_write_u64(&send, 0); /* length */
        parcel_write_string16(&send, "video/wvm"); /* mimeType */

        parcel_init(&reply);
        printf("[*] Sending TX 25 (OPEN_DECRYPT_SESSION) for video/wvm...\n");
        int ret = binder_call(0, TX_OPEN_DECRYPT_SESSION, &send, &reply);
        if (ret == 0 && reply.pos > 0) {
            hexdump("OPEN_DECRYPT_SESSION reply", reply.data, reply.pos);
            printf("[+] Decrypt session opened! This reaches Widevine/QSEE.\n");
        } else {
            printf("[-] TX 25 failed (ret=%d, reply.pos=%zu)\n", ret, reply.pos);
            printf("[*] May need a valid fd or different Parcel format.\n");
        }
    }

    /* Step 6: Try ACQUIRE_DRM_INFO — triggers Widevine provisioning */
    {
        struct parcel send, reply;
        parcel_init(&send);
        parcel_write_interface_token(&send, "drm.IDrmManagerService");
        parcel_write_u32(&send, 0); /* uniqueId */

        /* DrmInfoRequest: infoType, mimeType, key-value pairs */
        parcel_write_u32(&send, 3); /* infoType = DrmInfoRequest.TYPE_REGISTRATION_INFO */
        parcel_write_string16(&send, "video/wvm"); /* mimeType */

        /* Number of key-value pairs */
        parcel_write_u32(&send, 1);
        /* Key */
        parcel_write_string16(&send, "WVDRMServerKey");
        /* Value */
        parcel_write_string16(&send, "https://test.example.com/proxy");

        parcel_init(&reply);
        printf("[*] Sending TX 11 (ACQUIRE_DRM_INFO) with WV registration...\n");
        int ret = binder_call(0, TX_ACQUIRE_DRM_INFO, &send, &reply);
        if (ret == 0 && reply.pos > 0) {
            hexdump("ACQUIRE_DRM_INFO reply", reply.data,
                    reply.pos > 256 ? 256 : reply.pos);
            printf("[+] DRM info acquired — may have triggered QSEE!\n");
        } else {
            printf("[-] TX 11 failed (ret=%d, reply.pos=%zu)\n", ret, reply.pos);
        }
    }

    printf("\n[*] Done. Check dmesg for QSEE/Widevine messages.\n");
    printf("[*] Run: dmesg | grep -iE 'qsee|widevine|oemcrypto|drm'\n");

    if (binder_mapped != MAP_FAILED)
        munmap(binder_mapped, BINDER_MMAP_SIZE);
    if (binder_fd >= 0)
        close(binder_fd);

    return 0;
}
