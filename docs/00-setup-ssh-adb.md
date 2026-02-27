# Step 0: Connecting Mac to BlackBerry Priv

**Status:** COMPLETE (SSH over WiFi)

## Option A: ADB (USB Connection)

### On Mac:

```bash
# Install Android platform tools
brew install android-platform-tools

# Verify device is connected
adb devices
```

### On Phone:
1. Settings > About Phone > tap Build Number 7 times to enable Developer Options
2. Settings > Developer Options > enable USB Debugging
3. Connect USB cable, authorize the Mac when prompted

### Transferring files:

```bash
# Mac to phone
adb push local-file.txt /data/data/com.termux/files/home/

# Phone to Mac
adb pull /data/data/com.termux/files/home/remote-file.txt ./
```

## Option B: SSH into Phone from Mac

Once Termux is running on the phone:

### On Phone (Termux):

```bash
# Install SSH server
pkg install openssh

# Set a password (required for first connection)
passwd

# Start SSH server (runs on port 8022 by default)
sshd

# Get the phone's IP
ifconfig wlan0 | grep "inet "
```

### On Mac:

```bash
ssh -p 8022 PHONE_IP_ADDRESS
# Use the password you set above
```

### SSH Key Auth (no password prompts):

```bash
# On Mac:
ssh-copy-id -p 8022 PHONE_IP_ADDRESS

# Now connect without password:
ssh -p 8022 PHONE_IP_ADDRESS
```

## Option C: SSH from Phone to Mac (Reverse — for using Mac as compute)

### On Mac:
1. System Settings > General > Sharing > Remote Login (enable)
2. Note your Mac username and IP

### On Phone (Termux):

```bash
pkg install openssh
ssh YOUR_MAC_USER@YOUR_MAC_IP
```

## Actual Results

### ADB (USB): FAILED
- USB cable chain: Mac USB-C → adapter → USB-A → Micro USB → Phone
- macOS sees no USB device at all (`system_profiler SPUSBDataType` empty, `ioreg -p IOUSB` shows nothing)
- Cable or adapter is charge-only (no data lines)
- **Verdict:** ADB not viable without a data-capable micro USB cable

### SSH over WiFi: SUCCESS
- `pkg install openssh` succeeded on the phone
- `passwd` set to "nani" (change this later)
- `sshd` started successfully on port 8022
- Phone IP: `192.168.4.51`
- From Mac terminal: `ssh -p 8022 -o PubkeyAuthentication=no 192.168.4.51` with password "nani" = CONNECTED
- Key auth setup in progress (authorized_keys being configured)

### Key Auth Setup: SUCCESS
- `mkdir -p ~/.ssh && chmod 700 ~/.ssh` — worked
- Pasting the echo command as ONE LINE is critical. Line breaks from terminal wrapping cause bash syntax errors.
- What worked: `echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9U1ezsV3qOaq/uwE3BIKHkECi5IVCWgFtzXvrRB8Fa' > ~/.ssh/authorized_keys`
- `chmod 600 ~/.ssh/authorized_keys` — worked
- Maple can now connect: `ssh -p 8022 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes 192.168.4.51`
- `-o IdentitiesOnly=yes` is needed because Mac has many SSH keys; without it, too many auth failures before the right key is tried
- Confirmed output: `Linux localhost 3.10.84-perf-gd46863f aarch64 Android`, user `u0_a110`

### Lesson Learned
When pasting long commands into a Termux SSH session, use SINGLE QUOTES around the value and ensure the entire command is on one line. Terminal line-wrapping is fine, but actual newline characters in the paste will break bash.
