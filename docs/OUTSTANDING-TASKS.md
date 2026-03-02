# Outstanding Tasks — BlackBerry Priv Root

**Device:** BlackBerry Priv STV100-3, Android 6.0.1, kernel 3.10.84-perf-gd46863f
**Architecture:** ARM64 (aarch64), Snapdragon 808/MSM8992
**Hardening:** GRSEC/PAX enabled, SELinux enforcing, shell UID=2000
**Patch level:** 2017-10-05
**Last updated:** 2026-03-02

## Ultimate Goal

**#22: Root access obtained and verified with `id` command**
**#23: Root persistence installed surviving reboots**

---

## Dead Vectors (14 total — do not revisit)

| # | Vector | Why Dead |
|---|--------|----------|
| 1 | CVE-2018-5831 (KGSL refcount race) | kref protection prevents UAF |
| 2 | CVE-2018-13905 (syncsource race) | kref prevents UAF |
| 3 | CVE-2016-2062 (KGSL perfcounter overflow) | Ioctls removed from this build |
| 4 | Binder UAF (CVE-2019-2215) from 64-bit | GRSEC per-callsite slab isolation |
| 5 | CVE-2018-9568 WrongZone | Wrong cross-cache direction for this kernel |
| 6 | SysV IPC heap spray | ENOSYS — not compiled into kernel |
| 7 | KGSL page-level UAF | VMA refcount prevents true page freeing |
| 8 | KGSL "double-free" via ioctl 0x24 | Not actually a free (idempotent) |
| 9 | Dirty COW (CVE-2016-5195) | /proc/self/mem write blocked by GRSEC |
| 10 | process_vm_writev | ENOSYS — not implemented |
| 11 | ptrace | EPERM — blocked by GRSEC |
| 12 | CVE-2014-3153 (towelroot) | PATCHED — futex requeue validated |
| 13 | perf_event_open | paranoid=3, all operations EPERM |
| 14 | 32-bit compat binder UAF | ENTER_LOOPER returns EINVAL from 32-bit (compat BWR struct mismatch) |

---

## Pending Exploitation Vectors

### Priority 1: Information Gathering (unblock everything else)

**#78 — Crash dump mining (dmesg + last_kmsg + pstore)**
- Status: PENDING
- Rationale: Kernel crash logs may contain stack traces with kernel addresses, leaked pointers, or evidence of other processes' exploitation attempts. Could reveal exploitable bugs we haven't considered.
- Approach: Check /proc/last_kmsg, /sys/fs/pstore/*, dmesg (if accessible), /data/system/dropbox/
- Effort: Low (read-only, no risk)

**#81 — Kernel address leak scan (dmesg + proc + sysfs)**
- Status: PENDING
- Rationale: Even though kptr_restrict zeroes /proc/kallsyms, there may be other leak paths: /proc/timer_list, /proc/iomem, /sys/kernel/debug/*, slab debug info, kernel log messages with %pK that aren't properly filtered.
- Approach: Comprehensive scan of all readable /proc and /sys entries for hex patterns matching kernel address range (0xffffffc0*)
- Effort: Low (read-only, no risk)
- Note: We already have known addresses from earlier sessions (commit_creds, prepare_kernel_cred, selinux_enforcing, init_cred) — but confirming these are still correct and finding additional ones is valuable.

### Priority 2: Unexplored Kernel Attack Surface

**#80 — CVE-2016-3842 ALLOC/FREE_ID race with socket BPF spray**
- Status: PENDING
- Rationale: KGSL ALLOC_ID/FREE_ID ioctls may have race conditions on 3.10.84. BPF spray works (confirmed 600 filters from both 32-bit and 64-bit). If ALLOC/FREE_ID creates a UAF in a generic kmalloc cache, BPF reclamation may succeed where binder-specific caches failed.
- Approach: Identify ALLOC_ID and FREE_ID ioctls, test for race with multi-threaded alloc/free while spraying BPF
- Blocker: Need to confirm these ioctls exist in this build

**#79 — KGSL syncsource ioctl probe (CVE-2018-13905)**
- Status: PENDING
- Rationale: Even though earlier assessment said kref prevents the UAF, we should verify the syncsource ioctls are actually present and test the exact trigger path. The kref assessment was based on source analysis, not runtime testing.
- Approach: Probe for syncsource-related ioctls (CREATE_SYNCSOURCE, CREATE_SYNC_FENCE, SIGNAL_SYNC_FENCE), test if they're accessible from shell
- Blocker: May already be dead (kref), but worth 10 minutes to confirm

**#72 — CVE-2018-9568 WrongZone (sk_clone_lock type confusion)**
- Status: PENDING (assessed as wrong direction, but not runtime-tested)
- Rationale: Earlier analysis concluded the cross-cache direction was wrong for exploitation, but this was theoretical. A quick runtime test confirming the actual slab caches used by sk_clone_lock would be definitive.
- Approach: Create TCP sockets, trigger sk_clone_lock via accept(), check /sys/kernel/slab/ for cache changes
- Effort: Low

**#74 — CVE-2018-5831 KGSL refcount race UAF**
- Status: PENDING (assessed as kref-protected, not runtime-tested)
- Rationale: Similar to #79 — source analysis says kref prevents it, but a focused runtime test with high thread counts might reveal timing windows.
- Approach: Multi-threaded GPUMEM_ALLOC/SHAREDMEM_FREE race test
- Effort: Medium

### Priority 3: Novel Angles

**32-bit compat binder (needs kernel source analysis)**
- The compat_binder_ioctl handler rejects our ENTER_LOOPER command (EINVAL, consumed=-22). This could mean:
  - The compat handler translates binder_write_read differently than the 48-byte __u64 struct
  - BC_ENTER_LOOPER has additional validation in the compat path
  - The binder_thread state machine rejects looper entry under some condition
- Next step: Read the kernel source's `compat_binder_ioctl()` and `compat_binder_write_read()` to understand the exact struct translation
- If the compat struct can be figured out, this is the most promising vector because GRSEC slab isolation likely keys on callsite, and compat_sys_writev is a different callsite than sys_writev

**NETLINK_ROUTE manipulation**
- NETLINK_ROUTE socket opens successfully
- Could potentially manipulate routing tables, add/delete routes
- Unlikely to lead to root directly but could enable MITM or redirect traffic to a local service
- Low priority

**NETLINK_SELINUX audit events**
- Can receive SELinux audit events
- Might leak information about other processes' security violations
- Low priority

### Priority 4: Long Shots

**#73 — CVE-2016-2062 KGSL perfcounter heap overflow**
- Status: PENDING (ioctls assessed as removed)
- Rationale: The perfcounter ioctls returned EINVAL during earlier brute-force scanning, suggesting they're compiled out. But the scan may have used wrong struct sizes.
- Approach: Try perfcounter ioctls with exact struct sizes from kernel source
- Effort: Low

**ION/ADSP from different context**
- /dev/ion and /dev/adsprpc-smd are system:system 0664
- Shell (uid=2000) can't write to them
- Could theoretically exploit another vulnerability to get system group membership first, then use ION/ADSP as the second stage
- Blocked on: having any working first-stage exploit

---

## Known Kernel Addresses

From earlier sessions (no KASLR on this device):

| Symbol | Address |
|--------|---------|
| commit_creds | 0xffffffc00024a840 |
| prepare_kernel_cred | 0xffffffc00024ab74 |
| selinux_enforcing | 0xffffffc001649178 |
| init_cred | 0xffffffc00162d688 |

---

## Key Constraints

| Constraint | Value |
|------------|-------|
| PaX flags | `Pemrs` — MPROTECT off (RWX allowed), RANDMMAP off |
| CapBnd | 0xc0 (CAP_SETUID + CAP_SETGID in bounding set) |
| CapEff | 0x0 (no effective capabilities) |
| NO_NEW_PRIVS | 0 (can still gain privileges) |
| Seccomp | 0 (no seccomp filter) |
| SELinux | Enforcing (shell domain) |
| Accessible devices | /dev/kgsl-3d0 (0666), /dev/binder (0666), /dev/ashmem (0666) |
| Inaccessible devices | /dev/ion (0664 system), /dev/adsprpc-smd (0664 system) |

---

## Cross-Compilers

| Target | Compiler |
|--------|----------|
| 64-bit ARM (aarch64) | `/opt/homebrew/bin/aarch64-linux-musl-gcc -static -O2` |
| 32-bit ARM (compat) | `/opt/homebrew/bin/arm-linux-musleabihf-gcc -static -O2` |

---

## Recommended Next Session Order

1. **#78 + #81** (crash dumps + address leak scan) — low effort, high info value, do in parallel
2. **#80** (KGSL ALLOC/FREE_ID race) — most promising unexplored exploitation vector
3. **Compat binder kernel source analysis** — read compat_binder_ioctl() to fix 32-bit struct layout
4. **#79 + #74** (syncsource + refcount race) — quick runtime tests to confirm source analysis
5. **#72** (WrongZone runtime test) — quick slab cache confirmation
