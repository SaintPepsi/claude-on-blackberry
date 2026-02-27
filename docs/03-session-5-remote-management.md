# Session 5: SSH Multiplexing & Device Management Audit

**Date:** 2026-02-28
**Goal:** Break out of Termux sandbox for full remote device management (install/remove apps)

## SSH Multiplexing Setup

### Problem
Each SSH command required a full TCP handshake + key exchange (~2-3 seconds overhead).
With multiple commands per session, this adds up fast.

### Solution: SSH ControlMaster

Created `~/.ssh/config` on the Mac:

```
Host bb
    HostName 192.168.4.51
    Port 8022
    User u0_a110
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 4h
    Compression yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ConnectTimeout 10
```

**Before:** `ssh -p 8022 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes 192.168.4.51 'command'` (~2-3s)
**After:** `ssh bb 'command'` (~0.3s)

### How It Works

1. First `ssh bb` opens a master connection and holds it in background
2. All subsequent `ssh bb` calls reuse the existing TCP connection via a Unix socket
3. Connection persists for 4 hours (`ControlPersist 4h`)
4. Keepalive every 30 seconds prevents WiFi idle disconnects

### Commands

```bash
# Establish master connection (run once, persists 4 hours)
ssh -fN bb

# Check if master is alive
ssh -O check bb

# Kill the master connection
ssh -O exit bb

# Run any command on the phone (instant via multiplex)
ssh bb 'pm list packages'
ssh bb 'am start -a android.settings.SETTINGS'
```

## Permissions Wildcard

Updated `/root/.claude/settings.json` (inside Alpine proot) to allow all tools:

```json
{
  "hasCompletedOnboarding": true,
  "theme": "dark",
  "permissions": {
    "allow": ["*"],
    "deny": [],
    "defaultMode": "default"
  }
}
```

This replaces the individual tool list and is the workaround for `--dangerously-skip-permissions`
being blocked by proot's fake root (uid 0 security check).

## Device Management Audit

### Android Details
- Model: STV100-3 (BlackBerry Priv)
- Android: 6.0.1 (API 23)
- Installed packages: 178

### What Works from Termux User (uid 10110)

| Command | Status | Example |
|---------|--------|---------|
| `pm list packages` | **WORKS** | Lists all 178 installed packages |
| `pm path <pkg>` | **WORKS** | `pm path com.google.android.youtube` → `/system/app/YouTube/YouTube.apk` |
| `am start <intent>` | **WORKS** | `am start -a android.settings.SETTINGS` opens Settings app |
| `am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS` | **WORKS** | Opens Developer Options |

### What's Blocked (requires ADB shell uid 2000 or root)

| Command | Error |
|---------|-------|
| `pm uninstall` | `SecurityException: Package null does not belong to 10110` |
| `pm disable-user` | `SecurityException: Permission Denial: attempt to change component state` |
| `pm hide` | `SecurityException: Neither user 10110 nor current process has android.permission.MANAGE_USERS` |
| `settings get/put` | `SecurityException: Permission Denial: requires android.permission.ACCESS_CONTENT_PROVIDERS_EXTERNALLY` |
| `pm install` | Needs testing with actual APK, likely blocked |

### Why ADB Shell Is Needed

Termux runs as app user `u0_a110` (uid 10110). Android's security model blocks cross-package
operations from app UIDs. ADB shell runs as `shell` user (uid 2000), which has elevated
permissions for device management:

```
App user (10110) → can only manage own data
Shell user (2000) → can manage all packages, system settings
Root (0)          → can do everything
```

### ADB Over WiFi: Not Available

The BlackBerry Priv's Developer Options does **not** include an "ADB over network" toggle.
Available wireless options:
- Wireless display certification
- Enable WiFi verbose logging
- Aggressive WiFi to mobile handover
- Allow WiFi roam scans
- Use legacy DHCP client
- Mobile data always active

`adbd` is running but in USB-only mode (no TCP port set):
```
getprop service.adb.tcp.port  → (empty)
getprop persist.adb.tcp.port  → (empty)
getprop init.svc.adbd         → running
```

### Path to Full Device Management

**One-time USB requirement:**

1. Get a **micro USB data cable** (must carry data, not charge-only)
2. Connect phone to Mac
3. Run: `adb tcpip 5555`
4. Then: `adb connect 192.168.4.51:5555`
5. Disconnect cable — ADB over WiFi persists until reboot

After that, full remote management from Mac:
```bash
adb -s 192.168.4.51:5555 install app.apk
adb -s 192.168.4.51:5555 uninstall com.example.app
adb -s 192.168.4.51:5555 shell settings put global ...
adb -s 192.168.4.51:5555 shell pm disable-user --user 0 com.bloatware.app
```

To make ADB WiFi survive reboots, add to Termux `.bashrc`:
```bash
# After sshd start, before Alpine launch:
setprop service.adb.tcp.port 5555  # requires root, alternative is to reconnect via USB after each reboot
```

### Root Status

- `su` binary exists at `/data/data/com.termux/files/usr/bin/su` — but it's a **Termux stub**
- Running `su` produces: "No su program found on this device. Termux does not supply tools for rooting"
- Device is **not rooted**
- `setprop` is **not available** in Termux
