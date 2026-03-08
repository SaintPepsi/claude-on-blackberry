# Session 24 — TrustZone/QSEE Attack Surface Probe

**Date:** 2026-03-08
**Goal:** Assess whether CVE-2015-6639 and CVE-2016-2431 are exploitable on the BB Priv
**Related:** [Issue #8](https://github.com/SaintPepsi/claude-on-blackberry/issues/8)
**Access:** ADB shell (uid=2000, shell domain) + Termux SSH (uid=10110, untrusted_app)

---

## Summary

**Direct QSEE access is SELinux-blocked. Indirect DRM path exists but trustlet is likely patched (March 2018). Two new attack surfaces discovered: FIDO crypto daemon and keystore/gatekeeper HALs.**

---

## Findings

### 1. `/dev/qseecom` — SELinux Blocked

```
scontext=u:r:shell:s0  tcontext=u:object_r:tee_device:s0
avc: denied { getattr } for path="/dev/qseecom"
```

- Shell domain cannot `stat`, `open`, or `read` the qseecom device node
- All three open modes tested (O_RDONLY, O_WRONLY, O_RDWR): `EACCES`
- This is an SELinux policy denial, not a DAC (file permission) denial
- No alternative TZ device nodes exist: `/dev/tzcom`, `/dev/tee0`, `/dev/teepriv0` all ENOENT

**Implication:** Cannot directly communicate with QSEE trustlets from shell. Must go through a privileged intermediary service.

### 2. qseecomd Process

```
PID:  503 (parent) + 543 (child thread)
UID:  1000 (system)
SELinux: (not readable from shell)
VMSize: 11780 kB
```

- qseecomd is the userspace daemon that brokers Normal World ↔ QSEE communication
- Running as system (uid=1000) with its own SELinux domain
- `/proc/503/maps` and `/proc/503/fd/` are not readable from shell domain
- This process holds the qseecom fd and marshals ioctl commands to QSEE

### 3. Widevine Trustlet Analysis

**Location:** `/system/etc/firmware/widevine.{mdt,b00,b01,b02,b03}`
**Date:** 2018-03-03 (March 2018 — matches kernel build date)
**Architecture:** 32-bit ARM ELF (runs in QSEE's 32-bit secure world)

**Trustlet certificate (from widevine.mdt):**
```
Issuer:  BlackBerry / BBOS-Bootloader@blackberry.com
Subject: BB Attestation CA (secure)
SW_ID:   000000000000000C (12)
HW_ID:   009690E100000000
DEBUG:   0000000000000002
OEM_ID:  0000
MODEL_ID: 0000
SHA256 signed
```

**Key observations:**
- Signed by **BlackBerry**, not Qualcomm — uses BlackBerry's proprietary certificate chain
- 32-bit trustlet running on 64-bit SoC (normal for QSEE of this era)
- `b02` segment is 181,528 bytes (the code/data section)
- DEBUG field = 2 (not zero — may indicate some debug capability retained)

**Widevine Security Level:** L1 (hardware-backed)
```
"OEMCrypto_Initialize Level 1 success"
```
- Full hardware key ladder running inside QSEE
- OEMCrypto functions confirmed: GenerateDerivedKeys, LoadKeys, GenerateSignature, GenerateRSASignature, SelectKey, Generic_Encrypt/Decrypt/Sign/Verify, RewrapDeviceRSAKey

### 4. CVE-2015-6639 Assessment

**Vulnerability:** Buffer overflow in Widevine QSEE trustlet's PRDiag handler
**Discovered:** November 2015 (Gal Beniamini, Project Zero)
**Patched:** January 2016 security patch level
**Device security patch:** 2017-10-05

**Assessment: LIKELY PATCHED**

Reasoning:
1. The device's security patch level (2017-10-05) is 21 months after the fix
2. The Widevine trustlet binary is dated March 2018
3. BlackBerry's enterprise security focus makes it unlikely they shipped a known critical QSEE vulnerability 21 months after disclosure

**However:** BlackBerry re-signs trustlets with their own certificate chain (ECC-521/SHA-512). There's a non-zero chance they re-signed an old Qualcomm-provided binary without updating it. Definitive confirmation requires either:
- Reverse engineering the trustlet's PRDiag handler (extract b02 segment, load in Ghidra)
- Attempting the exploit (requires DRM binder access)

### 5. CVE-2016-2431 Assessment

**Vulnerability:** TrustZone kernel privilege escalation (QSEE app → TZ kernel EL3)
**Discovered:** March 2016 (Gal Beniamini)
**Patched:** May 2016 security patch level
**Device security patch:** 2017-10-05

**Assessment: LIKELY PATCHED** (same reasoning as CVE-2015-6639)

**Note:** CVE-2016-2431 requires QSEE app-level code execution first (i.e., CVE-2015-6639 or equivalent). If the first stage is patched, this is moot.

### 6. Available Attack Path: DRM Binder Service

Even though direct qseecom access is blocked, the DRM framework is accessible:

```
drm.drmManager: [drm.IDrmManagerService]  — accessible from shell
```

The CVE-2015-6639 attack chain was:
```
Attacker → MediaDrm API (binder) → mediaserver → Widevine plugin → OEMCrypto lib → qseecomd → QSEE trustlet
```

- `service call drm.drmManager 1` returns data (service responds to shell)
- mediaserver (PID 10952) has active ION allocations for DRM buffers
- The binder-based DRM path IS reachable from shell domain

**This means:** If a QSEE trustlet vulnerability exists (whether in Widevine or another trustlet), the DRM binder service provides a reachable path from shell context. Shell doesn't need direct qseecom access — it needs to send crafted data through a service that has qseecom access.

### 7. New Attack Surfaces Discovered

#### FIDO Crypto Daemon
```
Service: com.qualcomm.qti.auth.fidocryptodaemon
Binder: accessible from shell (returns "Invalid argument" on probe)
```
- Qualcomm's FIDO/U2F authentication daemon
- Runs with TrustZone access (handles cryptographic operations in QSEE)
- **Less audited than Widevine** — FIDO implementations have had multiple CVEs
- Accepts binder calls from shell domain

#### Keystore HAL (MSM8992-specific)
```
/system/vendor/lib/hw/keystore.msm8992.so   (32-bit, 30KB)
/system/vendor/lib64/hw/keystore.msm8992.so  (64-bit, 35KB)
```
- Hardware-backed keystore running through QSEE
- `sys.keymaster.loaded = true` — actively running
- Keystore vulnerabilities have been found in Qualcomm's QSEE implementation (CVE-2018-11976, keymaster key extraction — **but see note below: requires root, dead end for privilege escalation**)

#### Gatekeeper HAL
```
/system/vendor/lib/hw/gatekeeper.msm8992.so  (18KB)
gatekeeperd running (PID 642)
```
- Pattern/PIN verification via QSEE
- Smaller code surface but processes user-provided input

### 8. ION Memory Layout (QSEE)

```
qsecom heap allocations:
  0x22000, 0xb000, 0x1000, 0x2000, 0x5000, 0xb000,
  0x5000, 0x7e000, 0x1000, 0x5000, 0x5000

ADSP physical range: 0xcd020000
QSEECOM physical range: 0xcb800000 (from earlier sessions)
```

Active ION allocations confirm QSEE is actively processing secure operations. The physical addresses are known (no ASLR on ION).

---

## Accessible TZ Services from Shell

| Service | Binder | qseecom | Notes |
|---------|--------|---------|-------|
| drm.drmManager | Yes | Via mediaserver | DRM/Widevine path |
| fidocryptodaemon | Yes | Via daemon | FIDO auth, less audited |
| gatekeeperd | PID 642 | Via HAL | PIN verification |
| keymaster | Loaded | Via HAL | Key operations |
| trust_zone (BB) | Yes | Unknown | BlackBerry proprietary |

---

## Conclusion

### What's Blocked
- Direct `/dev/qseecom` access from shell (SELinux)
- Any direct QSEE trustlet communication

### What's Open
- DRM binder service (path to Widevine trustlet)
- FIDO crypto daemon binder (path to FIDO trustlet)
- BlackBerry trust_zone service binder
- Keystore/gatekeeper through system services

### What's Likely Patched
- CVE-2015-6639 (Widevine PRDiag) — patch predates firmware by 21 months
- CVE-2016-2431 (TZ kernel escalation) — patch predates firmware by 17 months

### Recommended Next Steps

1. **Extract and reverse engineer the Widevine trustlet** (`widevine.b02`, 181KB) — definitively confirm whether PRDiag is patched, and look for NEW vulnerabilities not covered by the 2015-2016 CVEs. The trustlet is 32-bit ARM, loadable in Ghidra.

2. **Probe the FIDO crypto daemon** — less publicly audited than Widevine. Research known FIDO/QSEE CVEs for this era. The binder interface is accessible.

3. ~~**Research keymaster CVEs** — CVE-2018-11976 (Qualcomm keymaster side-channel)~~ **DEAD END**: Requires root + custom kernel module (Cachegrab). This is a post-exploitation technique for extracting app-level ECDSA keys, not a privilege escalation path. NVD CVSS 5.5 MEDIUM, confidentiality-only impact. Sources: NCC Group Cachegrab README, whitepaper "Hardware-Backed Heist" pp.5/15/17, NVD.

4. **Investigate the BlackBerry `trust_zone` service** — proprietary, undocumented. What does `com.blackberry.security.trustzone.ITrustZoneService` actually do? What commands does it accept?

---

## Tools Deployed

| Tool | Location | Purpose |
|------|----------|---------|
| qsee_probe | /data/local/tmp/qsee_probe | Test qseecom/binder/ion/kgsl open |
| drm_probe | /data/local/tmp/drm_probe | Comprehensive TZ interface probe |
| widevine_version | /data/local/tmp/widevine_version | Extract Widevine/OEMCrypto version info |
