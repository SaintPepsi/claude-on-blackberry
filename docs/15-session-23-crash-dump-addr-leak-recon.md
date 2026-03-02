# Session 23: Crash Dump Mining & Kernel Address Leak Scan

## Summary

Executed tasks #78 and #81 from OUTSTANDING-TASKS.md. Read-only reconnaissance of crash dumps, kernel logs, and debugfs for kernel address leaks. Major discovery: **dmesg is readable from shell** and contains leaked kernel addresses from crash traces. debugfs (binder, kgsl, ion) is broadly readable but contains mostly userspace data. kptr_restrict effectively zeroes addresses in /proc/vmallocinfo, /proc/timer_list, and /proc/modules, but function names with offsets are still visible.

## Crash Dump Mining (#78)

### Sources Checked

| Source | Result |
|--------|--------|
| /proc/last_kmsg | Does not exist |
| /sys/fs/pstore | SELinux blocks shell access (avc: denied { read } pstorefs) |
| dmesg | **READABLE** — full kernel log accessible |
| /data/system/dropbox | Permission denied |

### dmesg Key Findings

**dmesg is readable from shell UID 2000.** Despite GRSEC hardening, the kernel log is accessible and contains:

1. **Crash traces from our earlier tools** (kgsl_race, kernel_probe) with full register dumps and kernel addresses
2. **Syncsource error with kernel address**: `[ffffffc081092180] kgsl-syncsource-pid-17300-1: error`
3. **KGSL malformed ioctl logs** from our probing sessions
4. **WiFi driver (dhd) ioctl logs** with kernel buffer addresses
5. **DWC3 USB driver** request addresses
6. **Battery/health daemon** status messages

### Syncsource Activity Confirmed

The dmesg log proves syncsource ioctls ARE accessible from shell:
```
[90801.319536] [ffffffc081092180] kgsl-syncsource-pid-17300-1: error
[90801.319735]   kgsl-syncsource-pid-17300_pt error@90801.311529
```
This is from a process (pid 17300) that successfully created a syncsource and triggered a fence error. The kernel address `ffffffc081092180` was leaked through the error message. This confirms task #79 (syncsource ioctl probe) is worth pursuing.

## Kernel Address Leak Scan (#81)

### 32 Unique Kernel Addresses from dmesg

All leaked through crash traces (task_struct, thread_info, pgd addresses):

| Type | Addresses |
|------|-----------|
| task_struct | ffffffc0be5fbc00, ffffffc03e815000, ffffffc09523bc00, ffffffc0bb7fee00, ffffffc05ccf9400, ffffffc05ccfb200, ffffffc05ccfe400, ffffffc05ccfee00 |
| thread_info | ffffffc049810000, ffffffc0aa4a4000, ffffffc03344c000, ffffffc03dedc000, ffffffc0a6030000, ffffffc040f38000 |
| pgd | ffffffc05008b000, ffffffc02e9bb000, ffffffc043b0d000, ffffffc0ae879000, ffffffc0372a1000, ffffffc0aea8e000 |
| kgsl syncsource | ffffffc081092180 |
| dhd WiFi buffers | ffffffc01ad69200, ffffffc01ad69bc0, ffffffc048da8580, ffffffc04ad09b00, ffffffc0570c1f00, ffffffc09fe47af8, ffffffc09fe47afc, ffffffc09fe47b50, ffffffc09fe47b54, ffffffc0aa62a880 |
| USB dwc3 | ffffffc0c3166600 |

### kptr_restrict Status

| Source | Addresses Visible | Function Names |
|--------|-------------------|----------------|
| /proc/kallsyms | Zeroed | Yes |
| /proc/vmallocinfo | Zeroed | Yes (with offsets) |
| /proc/timer_list | Zeroed | Yes (function names) |
| /proc/modules | Zeroed | Yes (module names) |
| /proc/iomem | Permission denied | N/A |
| /proc/slabinfo | Does not exist | N/A |

### Function Names from vmallocinfo (62 unique)

Key functions with offsets (useful for computing addresses from known base):
```
binder_mmap+0xa4/0x290
kgsl_sharedmem_page_alloc_user+0x5e8/0x690
kgsl_iommu_init+0x35c/0x6c8
kgsl_mmu_getpagetable+0x124/0x320
ipa_uc_event_handler+0xdc/0x198
module_alloc_update_bounds_rw+0x18/0x80
module_alloc_update_bounds_rx+0x18/0x7c
```

### debugfs Accessibility

| Path | Readable | Contents |
|------|----------|----------|
| /sys/kernel/debug/binder/state | Yes | Userspace node addresses, thread states |
| /sys/kernel/debug/binder/transactions | Yes | Transaction buffer addresses (zeroed) |
| /sys/kernel/debug/binder/transaction_log | Yes | PID-to-PID transaction history |
| /sys/kernel/debug/binder/failed_transaction_log | Yes | Failed transactions (our exploit attempts visible: handle 0xDEAD) |
| /sys/kernel/debug/binder/proc/* | Yes | Per-process binder state |
| /sys/kernel/debug/kgsl/kgsl-3d0/ctx/* | Yes | Context entries (numbered) |
| /sys/kernel/debug/kgsl/events | Yes | Event group counters |
| /sys/kernel/debug/ion/heaps/* | Yes | ION heap allocations with physical addresses |
| /sys/kernel/debug/ion/clients/* | Yes | ION client info |

### ION Heap Physical Memory Layout

From debugfs, ION heaps show physical address ranges:
- **ADSP heap**: 0xcd020000-0xcd2fffff (adsprpc-smd, camera)
- **QSEECOM heap**: 0xcb800000-0xcb814fff (secure execution env)
- **Audio heap**: mediaserver allocations (no address map)
- **System heap**: surfaceflinger framebuffers (~17MB each)
- **MM heap**: Empty

### Kernel Security Settings

| Setting | Value |
|---------|-------|
| kptr_restrict | Cannot read (Permission denied), but confirmed active |
| dmesg_restrict | Cannot read, but dmesg IS accessible |
| perf_event_paranoid | 3 (all perf blocked) |
| Loaded modules | core_ctl, fipsm, qdrbg_module, qcrypto_module |

## Impact on Exploitation Strategy

### New Information

1. **dmesg leak path is LIVE** — We can trigger crashes and read back kernel addresses from dmesg. This means any crash we trigger will leak task_struct, thread_info, and pgd addresses.

2. **Syncsource ioctls confirmed accessible** — The dmesg log proves pid 17300 successfully used syncsource ioctls. Task #79 is worth pursuing as a runtime test.

3. **ION physical addresses available** — The ADSP and QSEECOM heap physical addresses could be useful if we find a physical-to-virtual translation path.

4. **Function names + known base = computed addresses** — With commit_creds at 0xffffffc00024a840 and function+offset strings from vmallocinfo, we can potentially compute addresses of other kernel functions.

### Updated Known Addresses

Previous (confirmed still valid, no KASLR):

| Symbol | Address |
|--------|---------|
| commit_creds | 0xffffffc00024a840 |
| prepare_kernel_cred | 0xffffffc00024ab74 |
| selinux_enforcing | 0xffffffc001649178 |
| init_cred | 0xffffffc00162d688 |

New (from dmesg, dynamic allocations):

| Type | Example Address | Notes |
|------|----------------|-------|
| task_struct | 0xffffffc0be5fbc00 | Heap allocated, changes per process |
| thread_info | 0xffffffc049810000 | Page-aligned, heap allocated |
| pgd | 0xffffffc05008b000 | Page-aligned, per-process |
| kgsl syncsource | 0xffffffc081092180 | KGSL driver internal structure |

## Recommended Next Steps

1. **#79 — Syncsource ioctl probe**: CONFIRMED accessible. Write a test that creates syncsources, creates sync fences, and tests for race conditions.
2. **#80 — KGSL ALLOC_ID/FREE_ID race**: Still highest priority exploitation vector.
3. **Deliberate crash for address harvesting**: We can intentionally trigger crashes in controlled ways and read back leaked addresses from dmesg. This could be used to defeat any address randomization for heap objects.
