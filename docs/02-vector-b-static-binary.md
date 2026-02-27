# Vector B: Cross-Compiled Static Node.js Binary

**Status:** NOT STARTED (fallback if Vector A fails)
**Estimated difficulty:** Hard
**Estimated time:** 2-4 hours (mostly build time)

## Overview

Build a fully static Node.js 18 binary on macOS using Docker with musl cross-compilation
toolchains. The resulting binary has zero runtime dependencies and runs directly on Android
without proot, Termux packages, or any shared libraries.

## Why This Works (In Theory)

A fully static binary:
- Carries its own libc (musl), so no glibc or Bionic dependency
- Makes direct kernel syscalls, bypassing the Android userland entirely
- Only needs a compatible kernel ABI, which aarch64 Linux has had since 3.10

## The Kernel Syscall Risk

| Syscall | Added in Kernel | Node.js Behavior on 3.10 |
|---------|----------------|--------------------------|
| getrandom | 3.17 | Falls back to /dev/urandom (safe) |
| io_uring | 5.1 | Disabled on Android; falls back to epoll (safe) |
| memfd_create | 3.17 | V8 may use for code space. UNKNOWN fallback. Main risk. |
| epoll_pwait2 | 5.11 | Falls back to epoll_wait (safe) |

**memfd_create is the wildcard.** If V8 calls it unconditionally at startup and it returns
ENOSYS without a fallback, Node will crash. This needs empirical testing.

## Prerequisites

- Docker Desktop on Mac (Apple Silicon = native aarch64, Intel = QEMU emulation)
- ~10 GB disk space for build
- 30-60 min build time (Apple Silicon), 2-4 hours (Intel Mac via QEMU)

## Method 1: dockcross (Simplest)

```bash
# Get the cross-compilation Docker image
docker run --rm dockcross/linux-arm64-musl > ./dockcross-arm64-musl
chmod +x ./dockcross-arm64-musl

# Download Node.js source
curl -L -O https://nodejs.org/dist/v18.20.4/node-v18.20.4.tar.gz
tar xf node-v18.20.4.tar.gz

# Cross-compile with full static linking
./dockcross-arm64-musl bash -c "
  cd node-v18.20.4 &&
  CC=aarch64-linux-musl-gcc \
  CXX=aarch64-linux-musl-g++ \
  ./configure \
    --dest-cpu=arm64 \
    --dest-os=linux \
    --without-intl \
    --without-snapshot \
    --openssl-no-asm \
    --fully-static &&
  make -j\$(nproc)
"

# Result: node-v18.20.4/out/Release/node (static binary, ~50-80 MB)
```

## Method 2: Alpine Docker (Alternative)

```bash
# On Apple Silicon Mac, this runs natively as aarch64
docker run --rm -it -v $(pwd):/build alpine:3.20 sh -c "
  apk add --no-cache build-base python3 linux-headers &&
  cd /build &&
  wget https://nodejs.org/dist/v18.20.4/node-v18.20.4.tar.gz &&
  tar xf node-v18.20.4.tar.gz &&
  cd node-v18.20.4 &&
  ./configure \
    --without-intl \
    --without-snapshot \
    --openssl-no-asm \
    --fully-static &&
  make -j\$(nproc)
"
```

## Method 3: Termux Build System Fork

The most battle-tested Android path. Termux already has patches for Node.js on Android.

```bash
git clone https://github.com/termux/termux-packages.git
cd termux-packages

# Build Node.js for aarch64 Android
./build-package.sh -a aarch64 nodejs
```

This targets Bionic libc (not static), but has all the Android-specific patches applied.
The resulting binary lives in Termux's prefix (/data/data/com.termux/files/usr).

## Deploying to Phone

```bash
# Transfer the binary
adb push out/Release/node /data/data/com.termux/files/home/node

# On the phone (Termux):
chmod +x ~/node
UV_USE_IO_URING=0 ~/node --version
```

If it prints the version, the binary works on kernel 3.10. If it crashes with SIGILL
or SIGSYS, the kernel is blocking a syscall and we need to investigate which one.

## Then Install Claude Code

```bash
# Create a local npm prefix
mkdir -p ~/npm-global
~/node ~/npm-global/bin/npm config set prefix ~/npm-global
export PATH=~/npm-global/bin:$PATH

# Install
~/node ~/npm-global/bin/npm install -g @anthropic-ai/claude-code

# Run
UV_USE_IO_URING=0 ~/node ~/npm-global/bin/claude
```

## Build Flags Reference

| Flag | Purpose |
|------|---------|
| `--fully-static` | Link everything statically, no .so dependencies |
| `--without-intl` | Skip ICU (saves ~30MB, loses internationalization) |
| `--without-snapshot` | Skip V8 snapshot (reduces memfd_create risk) |
| `--openssl-no-asm` | Use C OpenSSL, not hand-tuned ASM (broader compat) |
| `UV_USE_IO_URING=0` | Runtime: force epoll, skip io_uring probe |
| `--v8-options="--jitless"` | Runtime: no JIT compilation (saves memory, slower) |

## Actual Results

> Document what actually happened here as you go through the steps.
