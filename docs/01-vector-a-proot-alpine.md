# Vector A: proot + Alpine Linux ARM64

**Status:** NOT STARTED
**Estimated difficulty:** Medium
**Estimated time:** 30-60 minutes

## Overview

Install a community-built `proot` binary for Android 5-7, download an Alpine Linux
aarch64 minirootfs, enter it via proot with kernel version spoofing, and install Node.js
20+ from Alpine's package manager.

## Prerequisites

- Termux installed and running on the BlackBerry Priv
- Internet connection on the phone
- (Optional) SSH access from Mac for easier typing

## Step 1: Fix Termux Package Sources (if needed)

The default Termux repos for Android 5/6 are dead. If `pkg update` fails:

```bash
# Point to the archived legacy repo
echo "deb https://archive.org/download/termux-repositories-legacy/termux-main-21-12-2019 stable main" > $PREFIX/etc/apt/sources.list
apt update
```

If that also fails, packages can be sideloaded via `adb push` from the Mac.

## Step 2: Install proot for Android 5-7

A community member (TokiZeng) maintains pre-built proot .deb files for Android 5-7:

```bash
# Download the community proot build
curl -L -O https://github.com/TokiZeng/proot-distro-for-Termux-Android-5.0-7.0/raw/main/proot_5.1.107-65_aarch64.deb

# Install it
apt install ./proot_5.1.107-65_aarch64.deb
```

**Note:** This is an unofficial community build. It's the most commonly referenced solution
for proot on Android 5/6, but review the repo if you have concerns.

### If curl/wget aren't available

Transfer the .deb from the Mac via ADB:

```bash
# On Mac:
curl -L -O https://github.com/TokiZeng/proot-distro-for-Termux-Android-5.0-7.0/raw/main/proot_5.1.107-65_aarch64.deb
adb push proot_5.1.107-65_aarch64.deb /data/data/com.termux/files/home/

# On phone (Termux):
apt install ./proot_5.1.107-65_aarch64.deb
```

## Step 3: Download Alpine Linux aarch64 Minirootfs

```bash
mkdir -p ~/alpine && cd ~/alpine

# Download Alpine 3.20 minirootfs (latest stable)
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz

# Extract it
tar --warning=no-unknown-keyword -xf alpine-minirootfs-3.20.0-aarch64.tar.gz
```

If wget isn't available, download on Mac and ADB push:

```bash
# On Mac:
curl -L -O https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz
adb push alpine-minirootfs-3.20.0-aarch64.tar.gz /data/data/com.termux/files/home/alpine/
```

## Step 4: Configure DNS

Networking inside proot won't work without explicit DNS config:

```bash
echo "nameserver 8.8.8.8" > ~/alpine/etc/resolv.conf
echo "nameserver 1.1.1.1" >> ~/alpine/etc/resolv.conf
```

## Step 5: Enter Alpine via proot

```bash
proot \
  --kill-on-exit \
  -k 4.14.0 \
  -r ~/alpine \
  -b /proc:/proc \
  -b /sys:/sys \
  -b /dev:/dev \
  -b /dev/urandom:/dev/urandom \
  --link2symlink \
  -w /root \
  /bin/sh -l
```

Key flags:
- `-k 4.14.0` — Spoofs kernel version so Node doesn't reject kernel 3.10
- `-r ~/alpine` — Root filesystem
- `-b /proc:/proc` etc. — Bind-mount essential filesystems
- `--link2symlink` — Required because Android's /data doesn't support hard links

### Verify you're in Alpine:

```bash
cat /etc/os-release
uname -r  # Should show 4.14.0 (spoofed)
```

## Step 6: Install Node.js

```bash
apk update
apk add nodejs npm git
node --version  # Expect v20.x or v22.x
npm --version
```

## Step 7: Install Claude Code

```bash
npm install -g @anthropic-ai/claude-code
```

### Fix the sharp module (if it errors):

```bash
npm install -g @img/sharp-wasm32 --force
npm install -g sharp --force
```

### Fix /tmp paths (if Claude Code fails with EACCES):

```bash
mkdir -p /tmp/claude
export TMPDIR=/tmp
```

## Step 8: Run Claude Code

```bash
export ANTHROPIC_API_KEY="your-key-here"
claude
```

## Step 9: Create a Launcher Script

Save this to `~/start-alpine.sh` in Termux (outside proot):

```bash
#!/data/data/com.termux/files/usr/bin/bash
proot \
  --kill-on-exit \
  -k 4.14.0 \
  -r ~/alpine \
  -b /proc:/proc \
  -b /sys:/sys \
  -b /dev:/dev \
  -b /dev/urandom:/dev/urandom \
  --link2symlink \
  -w /root \
  /bin/sh -l
```

```bash
chmod +x ~/start-alpine.sh
```

## Known Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| proot .deb is community-built | Medium | Inspect before installing |
| Networking hangs inside Alpine | High | Manual DNS in Step 4 |
| getrandom syscall missing (kernel 3.17+) | Low | Bind-mount /dev/urandom; proot redirects |
| Performance overhead (ptrace mode) | Medium | CLI is viable; API latency dominates anyway |
| No seccomp fast path on kernel 3.10 | Medium | Falls back to pure ptrace; slower but functional |

## Actual Results

> Document what actually happened here as you go through the steps.

### Step 1 Result:
### Step 2 Result:
### Step 3 Result:
### Step 4 Result:
### Step 5 Result:
### Step 6 Result:
### Step 7 Result:
### Step 8 Result:
