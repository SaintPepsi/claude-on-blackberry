# Device Modification Domain Research

**Date:** 2026-03-08
**Context:** Authorized security research on personally-owned BlackBerry Priv (STV100-3)
**Related:** [Issue #1](https://github.com/SaintPepsi/claude-on-blackberry/issues/1)

After 22 exploit sessions exhausting known software kernel exploit vectors against the BB Priv's GRSEC/PAX/SELinux/slab-isolation hardening, this document steps back to map the full domain of device modification techniques. The goal: find the correct terminology, understand what categories of approach exist, and identify which ones apply to this specific device.

---

## Table of Contents

1. [Terminology Glossary](#terminology-glossary)
2. [Technique Categories](#technique-categories)
3. [BlackBerry Priv Applicability](#blackberry-priv-applicability)
4. [Recommended Next Steps](#recommended-next-steps)
5. [Sources](#sources)

---

## Terminology Glossary

### Core Concepts

| Term | Definition | Platform |
|------|-----------|----------|
| **Rooting** | Gaining superuser (UID 0) access on a device, allowing all apps to run privileged commands | Android |
| **Jailbreaking** | Bypassing Apple's restrictions: modifying the OS, sideloading apps, granting elevated privileges. Broader scope than rooting because iOS locks down more | iOS |
| **Bootloader Unlocking** | Disabling the bootloader's signature verification so it loads unsigned boot images. Prerequisite for most rooting but NOT the same as rooting | Android |
| **OEM Unlock** | Developer option permitting bootloader unlock via `fastboot oem unlock`. Supported by Google, OnePlus, Xiaomi, Sony, Motorola. **Not supported by BlackBerry** | Android |
| **Stock ROM / Firmware** | Factory-installed OS including bootloader, kernel, system partition, vendor partition | All |
| **Custom ROM** | Third-party Android build (LineageOS, Pixel Experience, /e/OS) compiled from AOSP source. Requires unlocked bootloader | Android |
| **ROM Flashing** | Writing a ROM image to device storage partitions, replacing existing firmware | All |

### Recovery & Flashing Tools

| Term | Definition |
|------|-----------|
| **Custom Recovery (TWRP)** | Open-source touchscreen recovery replacing stock recovery partition. Enables: flashing custom ROMs, NANDroid backups, flashing ZIP packages (Magisk, GApps), partition wiping |
| **CWM (ClockworkMod)** | Older text-based custom recovery, superseded by TWRP |
| **Fastboot** | Protocol and tool for communicating with a device's bootloader over USB. Used for unlocking, flashing partitions, booting temp images |
| **ODIN Mode** | Samsung's proprietary download mode for flashing firmware. Uses ODIN (Windows) or Heimdall (cross-platform) |
| **Autoloader** | BlackBerry's self-extracting firmware package applied via USB. Still requires the existing bootloader to accept it (signed) |

### Boot Chain & Verification

| Term | Definition |
|------|-----------|
| **Chain of Trust** | Security model where each boot stage cryptographically verifies the next. Flow: Hardware Root of Trust -> PBL -> SBL -> ABOOT -> Kernel -> Android |
| **Hardware Root of Trust** | Crypto keys burned into SoC during manufacturing (OTP/eFuse). Cannot be modified. Anchors entire verification chain |
| **Verified Boot / AVB** | Google's framework ensuring all executable code is cryptographically verified before use. Covers kernel, device tree, system, vendor partitions |
| **dm-verity** | Linux kernel feature providing transparent integrity checking of block devices via Merkle hash trees. Used by Verified Boot at runtime |
| **Secure Boot** | Ensures only signed code executes during boot. On Qualcomm: PBL verifies SBL, SBL verifies ABOOT, etc. |
| **SecureBoot Bypass** | Any technique circumventing signature verification: PBL exploits, signing key leaks, verification logic bugs, downgrading to vulnerable bootloaders |

### Fuses & Anti-Tamper

| Term | Definition |
|------|-----------|
| **eFuse** | One-Time Programmable memory in the SoC. Once blown, permanently and irreversibly changed. Stores security keys, tamper state, anti-rollback counters |
| **Tamper Fuse** | eFuse recording whether device was tampered with (e.g., bootloader unlocked). Samsung Knox uses this. Once tripped, permanently disables warranty and some security features |
| **Anti-Rollback** | eFuse counters preventing firmware downgrade. Each update increments counter. Bootloader refuses firmware with lower counter value. Counter cannot be decremented |
| **S-ON / S-OFF** | HTC-specific. S-ON: NAND write-protected, signatures verified. S-OFF: all protections disabled, can flash anything. S-OFF was the "holy grail" for HTC devices |

### Hardware Debug Interfaces

| Term | Definition |
|------|-----------|
| **JTAG** | IEEE 1149.1 standard for hardware debugging. Provides CPU halt/step/resume, register/memory read/write. Requires physical access to PCB test points (TCK, TMS, TDI, TDO, TRST). Access level: **full CPU control below all software security** |
| **SWD** | ARM's two-wire alternative to JTAG (SWCLK + SWDIO). Equivalent functionality, fewer pins. Used on all ARM Cortex / Qualcomm Snapdragon SoCs |
| **UART** | Serial console interface. On mobile devices, can expose bootloader logs, kernel console, sometimes interactive shell. Requires identifying TX/RX/GND pads on PCB |
| **EUD** | Qualcomm's Embedded USB Debug — exposes SWD over USB. Only available on Snapdragon 845+ (post-2018). **Not available on MSM8992/Snapdragon 808** |

### Emergency / Download Modes

| Term | Definition |
|------|-----------|
| **EDL / 9008 Mode** | Qualcomm Emergency Download Mode in SoC's PBL ROM. Device appears as "Qualcomm HS-USB QDLoader 9008" over USB. Uses Sahara protocol to receive a signed programmer, then Firehose protocol for flash operations |
| **Sahara Protocol** | Qualcomm PBL protocol for receiving and authenticating the firehose programmer binary. Programmer must be signed with OEM's RSA key matching fuse-burned keys |
| **Firehose Protocol** | XML-based command protocol: `program` (flash), `read` (dump), `erase`, `peek`/`poke` (arbitrary memory read/write). Security-critical: peek/poke enables arbitrary memory access |
| **Test Point Booting** | Shorting specific PCB test points to force EDL entry. Works by triggering `pbl_sense_jtag_test_points_edl()` or preventing eMMC init (PBL EDL fallback) |

### Storage Access

| Term | Definition |
|------|-----------|
| **eMMC ISP** | In-System Programming — connecting directly to eMMC flash chip data lines (CMD, CLK, DATA0-7) while chip remains soldered. **Bypasses CPU and ALL software security entirely**. Less destructive than chip-off |
| **Chip-Off** | Physically desoldering the eMMC/UFS chip and reading with external programmer. Complete raw access. Destructive |

### Rooting Tools

| Term | Definition |
|------|-----------|
| **Magisk** | Current standard for Android rooting. Patches boot image to inject Magisk daemon. Supports systemless root (no /system modification), root hiding (Zygisk), and modules |
| **Boot Image Patching** | Extract stock boot.img, patch with Magisk Manager, flash patched image via fastboot. Primary method when custom recovery unavailable |

### Exploit Categories

| Term | Definition |
|------|-----------|
| **Bootrom Exploit** | Vulnerability in SoC's ROM-resident PBL. **Permanently unpatchable** (mask ROM). Example: checkm8 (USB DFU stack UAF, Apple A5-A11). Provides pre-boot code execution before any software security |
| **TrustZone / QSEE Exploit** | Attack against Trusted Execution Environment. Provides EL3 (highest ARM privilege): can disable hardware memory protections (XPUs), access all DRAM, extract secure storage keys |
| **Baseband Exploit** | Attack on cellular modem firmware (separate processor, typically Qualcomm Hexagon DSP). Provides modem-level access with potential lateral movement to application processor |
| **Firmware Downgrade** | Rolling back to older firmware with known vulnerabilities. Countered by anti-rollback eFuse counters |

---

## Technique Categories

### 1. Software Kernel Exploits

**What it is:** Exploiting vulnerabilities in the running Linux kernel to escalate privileges to root.

**Access level:** Root (UID 0) within kernel/userspace
**Prerequisites:** ADB or app execution; known unpatched kernel vulnerability
**Typical targets:** Unpatched devices, older kernels

**BB Priv status:** **EXHAUSTED** — 22 sessions, 14 dead vectors. GRSEC/PAX + per-callsite slab isolation + SELinux enforcing makes this the hardest possible target for kernel exploits. The unclaimed $1000 XDA bounty confirms community-wide failure.

### 2. Bootloader Unlock Commands

**What it is:** Using manufacturer-provided commands to disable boot signature verification.

**Access level:** Ability to flash unsigned images
**Prerequisites:** OEM unlock enabled; manufacturer support
**Commands:** `fastboot oem unlock`, `fastboot flashing unlock`

**BB Priv status:** **NOT AVAILABLE** — BlackBerry provides no unlock mechanism. No OEM unlock toggle exists. Permanently locked by design.

### 3. Qualcomm EDL/9008 Mode (Sahara/Firehose)

**What it is:** Using Qualcomm's emergency download mode built into the SoC's PBL ROM to read/write flash storage.

**Access level:** Raw flash read/write; potentially arbitrary memory access via peek/poke
**Prerequisites:** Physical access + EDL entry method + **valid signed firehose programmer**
**Critical constraint:** PBL verifies programmer's RSA signature against OEM-fused keys. Without a correctly signed programmer, EDL is accessible but non-functional.

**With a signed programmer you can:**
- Dump entire flash (all partitions)
- Modify partition table
- Write modified boot/system images directly
- Use peek/poke for arbitrary memory access
- Some programmers have hidden functionality enabling EL3 code execution

**BB Priv status:** MSM8992 supports EDL. **Gating factor: no known BlackBerry-signed firehose programmer in the wild.** BlackBerry's tight firmware control makes leaks unlikely. Test points for EDL entry on the Priv PCB have not been publicly documented. The Lumia 950 (also MSM8992) has the same unsolved problem — someone on XDA was still searching for a signed programmer as recently as 2025.

### 4. Hardware JTAG/SWD Debug

**What it is:** Using hardware debug interfaces for full CPU control at the silicon level.

**Access level:** Complete — halt, step, register/memory read/write below all software security
**Prerequisites:** PCB access; test point identification; JTAG not fuse-disabled; debug hardware (J-Link, OpenOCD adapter)
**Critical constraint:** Production devices often have JTAG disabled via eFuse (permanent, irreversible).

**BB Priv status:** No public documentation of JTAG/SWD pad locations. Given BlackBerry's security focus, **JTAG is almost certainly fuse-disabled on production units**. EUD not available on MSM8992. Worth verifying with a multimeter but expectations should be low.

### 5. UART Serial Console

**What it is:** Accessing the device's serial console for boot logs or interactive shell.

**Access level:** Varies — boot logs only, or interactive root shell
**Prerequisites:** PCB access; UART TX/RX/GND pad identification; USB-to-UART adapter (1.8V logic level); UART not disabled in firmware

**BB Priv status:** UART pads likely exist but locations not documented. BlackBerry likely disabled console output in production firmware. Still valuable for boot process analysis if found. Even read-only logs reveal boot chain sequence, error handling, and potentially undocumented modes.

### 6. eMMC ISP (In-System Programming)

**What it is:** Connecting directly to the eMMC flash chip's data lines on the PCB, communicating with the flash chip directly without involving the CPU.

**Access level:** Complete raw flash read/write, bypassing CPU and ALL software security
**Prerequisites:** PCB access; eMMC test point identification (CMD, CLK, DATA0-7, GND); ISP hardware (eMMC Pro, Easy JTAG); partition layout knowledge
**Key advantage:** The CPU, chain of trust, secure boot, GRSEC/PAX, SELinux — **none of it matters** because the CPU is not involved.
**Key limitation:** If bootloader verifies flash on boot (verified boot), modifications may be detected. But if the bootloader itself can be modified via ISP, this protection can potentially be circumvented.

**BB Priv status:** **MOST PROMISING AVENUE.** The eMMC on the Priv's PCB should have accessible test points. ISP would allow: (1) full flash dump for comprehensive offline analysis, (2) modification of boot partitions, (3) potentially replacing the bootloader. Even if secure boot detects modifications, the dump enables reverse engineering of ABOOT, SBL, Security Shim, and all signed components offline.

### 7. Test Point Booting

**What it is:** Shorting PCB test points to force the device into EDL or other low-level modes.

**Methods:**
- Short eMMC CMD to GND: prevents flash init, PBL enters EDL
- Short specific JTAG-related points: triggers `pbl_sense_jtag_test_points_edl()`
- Short USB D+ to GND: some devices enter download mode

**BB Priv status:** Test points not publicly mapped. Would need PCB reverse engineering (compare to MSM8992 reference design, probe with multimeter during boot).

### 8. Firmware Downgrade

**What it is:** Rolling back to older firmware with known exploitable vulnerabilities.

**Prerequisites:** Ability to flash older firmware (EDL, ISP, or unlocked bootloader); anti-rollback counter not exceeded; known vulnerability in target firmware

**BB Priv status:** BlackBerry likely implements anti-rollback. If flashing is possible via EDL/ISP, the anti-rollback counter may block downgrades. Early Priv firmware may have had exploitable vulnerabilities later patched.

### 9. Signing Key Compromise

**What it is:** Obtaining the OEM's private signing key to create validly-signed firmware.

**Methods:** Key extraction from compromised build servers, insider leaks, side-channel attacks on HSMs

**BB Priv status:** BlackBerry's signing keys have never been publicly compromised. Given their enterprise security focus, this is the hardest path but would provide complete control.

### 10. Boot Image Patching (Magisk)

**What it is:** Extracting boot.img, patching with Magisk, and flashing the patched image for systemless root.

**Prerequisites:** Unlocked bootloader OR alternative flash method (EDL with signed programmer, ISP)

**BB Priv status:** Cannot flash directly due to locked bootloader. Requires EDL or ISP as prerequisite. Even then, secure boot would need to be bypassed for the modified boot image to be accepted.

### 11. TrustZone / QSEE Exploits

**What it is:** Attacking the Trusted Execution Environment for highest-privilege code execution.

**Access level:** EL3 — can disable hardware memory protections (XPUs), access all DRAM, extract secure storage keys
**Prerequisites:** Known TZ vulnerability + ability to trigger it (usually needs some code execution first)
**Notable CVEs:** CVE-2015-6639 (QSEE privilege escalation), CVE-2016-2431 (TZ kernel escalation) — both affected the Snapdragon 808 era

**BB Priv status:** These CVEs affected this generation of chips. Requires: (1) initial code execution path (even unprivileged), (2) QSEE version to be unpatched. BlackBerry may have patched in their updates. If exploitable, could disable secure boot for subsequent boots and extract signing keys.

### 12. Bootrom / PBL Exploits

**What it is:** Exploiting vulnerabilities in the SoC's mask-ROM Primary Bootloader.

**Access level:** Pre-boot code execution before any software security
**Key property:** **Permanently unpatchable** — PBL is in ROM
**Example:** checkm8 (Apple A5-A11) — USB DFU stack UAF

**BB Priv status:** The MSM8992 PBL has been dumped by Aleph Security researchers. No public exploit disclosed for MSM8992 specifically, but the binary exists for reverse engineering. A PBL exploit would bypass everything — permanently, on every unit with that SoC.

### 13. Baseband/Modem Exploits

**What it is:** Attacking the cellular modem firmware (separate Qualcomm Hexagon DSP processor).

**BB Priv status:** Theoretically possible but extremely specialized. Requires crafted radio signals or IPC. Lateral movement from modem to AP is non-trivial.

---

## BlackBerry Priv Applicability

### Why the Priv Is So Hard

BlackBerry built arguably the most hardened Android device ever commercially released:

1. **Security Shim** — Proprietary layer between bootloader stages using ECC-521/SHA-512 (vs Qualcomm's standard RSA-2048/SHA-256)
2. **GRSEC/PAX** — Comprehensive kernel hardening with per-callsite slab isolation
3. **SELinux Enforcing** — Strict mandatory access control
4. **ABOOT Quality** — XDA reverse engineer concluded: "the aboot module is well written and no mistakes has been made"
5. **No OEM Unlock** — Bootloader permanently locked by design
6. **BID (Integrity Detection)** — Runtime monitoring via TrustZone secure enclave
7. **FIPS 140-2 Encryption** — Full disk encryption enabled by default

The $1,000 XDA root bounty was never claimed.

### Technique Applicability Matrix

| Technique | Feasible? | Status | Notes |
|-----------|-----------|--------|-------|
| Kernel exploits | Exhausted | 22 sessions, 14 dead vectors | GRSEC slab isolation blocks all known paths |
| Bootloader unlock | No | Permanently locked | No OEM unlock mechanism exists |
| EDL/Firehose | Blocked | No signed programmer | MSM8992 supports EDL but needs BB-signed programmer |
| JTAG/SWD | Unlikely | Probably fuse-disabled | Worth verifying but low expectations |
| UART | Possible | Not yet attempted | Boot logs valuable even if read-only |
| **eMMC ISP** | **Yes** | **Not yet attempted** | **Most promising — bypasses all software security** |
| Test points | Unknown | PCB not mapped | Needed for EDL entry |
| Firmware downgrade | Unknown | Depends on anti-rollback | Requires flash access first |
| TrustZone/QSEE | Maybe | Needs code execution + unpatched CVE | CVE-2015-6639, CVE-2016-2431 affected this SoC gen |
| PBL/Bootrom | Long shot | Binary available, no known exploit | Permanently unpatchable if found |
| Signing key | Extremely unlikely | Never compromised | Enterprise-grade key management |

### What Sessions 1-22 Already Covered

The existing exploit sessions thoroughly covered software kernel exploit vectors:

- **Dirty COW** (CVE-2016-5195): Patched + /proc/self/mem write blocked by GRSEC
- **Binder UAF** (CVE-2019-2215): UAF confirmed but GRSEC per-callsite slab isolation blocks reclamation
- **KGSL fuzzing**: 121K iterations, 0 crashes, driver hardened
- **KGSL source audit**: All known CVEs patched or unreachable
- **Towelroot** (CVE-2014-3153): Patched
- **QuadRooter**: All 4 CVEs patched
- **32-bit compat binder**: EINVAL on ENTER_LOOPER
- **AF_PACKET, perf_event, userfaultfd, SysV IPC**: All blocked
- **No SUID binaries, no writable /proc/sys, no /dev/mem**
- **PAX flags decoded**: MPROTECT off (RWX allowed), RANDMMAP off

---

## Recommended Next Steps

### Tier 1: Most Feasible (hardware)

1. **eMMC ISP** — Identify eMMC test points on PCB. Connect via ISP hardware (Easy JTAG or eMMC Pro). Dump full flash for offline analysis. This sidesteps ALL software security because the CPU is not involved. Even if you can't bypass secure boot, the dump enables comprehensive reverse engineering of ABOOT, SBL, Security Shim, and all signed components.

2. **UART Discovery** — Probe PCB for UART TX/RX pads during boot (logic analyzer or oscilloscope). Even read-only boot logs reveal boot chain sequence, error handling paths, and potentially undocumented modes.

### Tier 2: Feasible with Effort

3. **EDL Entry via Test Points** — Identify and short correct PCB test points to enter EDL/9008 mode. Even without a signed programmer, confirming EDL entry is valuable. A flash dump from ISP might contain signed components usable as a firehose programmer.

4. **TrustZone/QSEE Exploitation** — If any code execution path exists (even via third-party app), CVE-2015-6639 and CVE-2016-2431 may be exploitable if BlackBerry's last update didn't patch them. TrustZone exploitation provides EL3 and could disable secure boot.

5. **Firmware Analysis** — Dump flash via ISP, extract ABOOT and SBL binaries, reverse engineer for signing verification bugs, hidden commands, logic errors the XDA researcher may have missed.

### Tier 3: Possible but Unlikely

6. **PBL Reverse Engineering** — The MSM8992 PBL binary exists in Aleph Security's research. A checkm8-style bootrom exploit would be permanently unpatchable.

7. **Firehose Programmer Acquisition** — Search firmware packages (autoloaders), forensics tool databases, repair shop toolkits for leaked BlackBerry-signed programmers.

8. **JTAG Verification** — Probe with multimeter. If not fuse-disabled (unlikely), provides complete device control.

---

## Sources

- [Rooting (Android) — Wikipedia](https://en.wikipedia.org/wiki/Rooting_(Android))
- [Jailbreaking vs Rooting vs Unlocking — How-To Geek](https://www.howtogeek.com/135663/htg-explains-whats-the-difference-between-jailbreaking-rooting-and-unlocking/)
- [TWRP — Wikipedia](https://en.wikipedia.org/wiki/TWRP_(software))
- [Verified Boot — Android Source](https://source.android.com/docs/security/features/verifiedboot)
- [AVB 2.0 — Google Source](https://android.googlesource.com/platform/external/avb/+/master/README.md)
- [dm-verity — Android Source](https://source.android.com/docs/security/features/verifiedboot/dm-verity)
- [Qualcomm EDL Mode — Wikipedia](https://en.wikipedia.org/wiki/Qualcomm_EDL_mode)
- [Exploiting Qualcomm EDL Programmers — Aleph Security](https://alephsecurity.com/2018/01/22/qualcomm-edl-1/)
- [bkerler/edl — Qualcomm Firehose/Sahara Tools (GitHub)](https://github.com/bkerler/edl)
- [Hidden JTAG in Qualcomm/Snapdragon USB — Linaro](https://www.linaro.org/blog/hidden-jtag-qualcomm-snapdragon-usb/)
- [BlackBerry PRIV Root Bounty — XDA Forums](https://xdaforums.com/t/blackberry-priv-root-bounty.3243716/)
- [How BlackBerry Secured Android on the Priv — CrackBerry](https://crackberry.com/heres-how-blackberry-secured-android-priv)
- [GRSEC Confirmed on BB Priv — CrackBerry Forums](https://forums.crackberry.com/blackberry-priv-f440/blackberry-safeguard-grsecurity-confirmed-slider-1039008/)
- [QSEE Privilege Escalation CVE-2015-6639 — Bits Please](http://bits-please.blogspot.com/2016/05/qsee-privilege-escalation-vulnerability.html)
- [TrustZone Kernel CVE-2016-2431 — Bits Please](http://bits-please.blogspot.com/2016/06/trustzone-kernel-privilege-escalation.html)
- [checkm8 Explained — HackMag](https://hackmag.com/mobile/checkra1n)
- [eFuse — Wikipedia](https://en.wikipedia.org/wiki/EFuse)
- [eMMC ISP Forensics — MDPI](https://www.mdpi.com/2076-3417/10/12/4231)
- [BlackBerry Priv Teardown — iFixit](https://www.ifixit.com/Device/Blackberry_PRIV)
- [Magisk Installation Guide](https://topjohnwu.github.io/Magisk/install.html)
- [Android UART Hardware Hacking — Pen Test Partners](https://www.pentestpartners.com/security-blog/how-to-hardware-hack-android-over-uart/)
- [Lumia 950 MSM8992 Firehose Search — XDA](https://xdaforums.com/t/looking-for-microsoft-signed-firehose-for-lumia-950-rm-1104-msm8992.4774374/)
