#!/bin/sh
# VeraCrypt OpenMediaVault Plugin - Standalone Diagnostic & Debug Script
# Saves diagnostics to /tmp/veracrypt_debug.log and prints to stdout.

LOG_FILE="/tmp/veracrypt_debug.log"

log_msg() {
    local MSG="$1"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${TIMESTAMP}] [DIAG] ${MSG}"
    echo "[${TIMESTAMP}] [DIAG] ${MSG}" >> "$LOG_FILE" 2>/dev/null || true
}

# Ensure log file exists and is writable
touch "$LOG_FILE" 2>/dev/null || true
chmod 666 "$LOG_FILE" 2>/dev/null || true

log_msg "=========================================================="
log_msg "🚀 VeraCrypt OMV Plugin Diagnostic Check Started"
log_msg "=========================================================="

# 1. Check User & Permissions
log_msg "Current User: $(whoami) (UID: $(id -u))"

# 2. Check VeraCrypt Installation Status
log_msg "--------------------------------------------------------"
log_msg "🔍 Checking VeraCrypt Installation..."
log_msg "--------------------------------------------------------"

INSTALLED=false

# Method A: command -v
if command -v veracrypt >/dev/null 2>&1; then
    log_msg "Method A: 'command -v veracrypt' found binary at: $(command -v veracrypt)"
    INSTALLED=true
else
    log_msg "Method A: 'command -v veracrypt' failed to find binary."
fi

# Method B: test paths
testPaths="/usr/bin/veracrypt /usr/sbin/veracrypt /usr/local/bin/veracrypt /bin/veracrypt /sbin/veracrypt /usr/bin/veracrypt-console /usr/sbin/veracrypt-console"
for path in $testPaths; do
    if [ -f "$path" ]; then
        log_msg "Method B: Found VeraCrypt file on disk at: $path"
        INSTALLED=true
    fi
done

# Method C: dpkg check
dpkgPkg=$(dpkg -l | grep -E "veracrypt|veracrypt-console" || true)
if [ -n "$dpkgPkg" ]; then
    log_msg "Method C: dpkg check found package(s):"
    echo "$dpkgPkg" | while read -r line; do
        log_msg "  $line"
    done
    INSTALLED=true
else
    log_msg "Method C: dpkg check found no veracrypt packages."
fi

# Method D: Run --version
if $INSTALLED; then
    if veracrypt -t --version >/dev/null 2>&1; then
        VER=$(veracrypt -t --version 2>&1)
        log_msg "Method D: veracrypt -t --version output: ${VER}"
    else
        log_msg "Method D: veracrypt -t --version command failed to execute."
    fi
else
    log_msg "VeraCrypt is NOT detected as installed."
fi

# 3. Check Active Mounts
log_msg "--------------------------------------------------------"
log_msg "🔍 Listing Active Mounts..."
log_msg "--------------------------------------------------------"

if command -v veracrypt >/dev/null 2>&1; then
    # Run veracrypt -t -l
    if veracrypt -t -l >/tmp/vc_mounts_raw.tmp 2>&1; then
        log_msg "VeraCrypt Active Mounts Raw Output:"
        while read -r line; do
            log_msg "  $line"
        done < /tmp/vc_mounts_raw.tmp

        log_msg "Parsed Mountpoints / Destination Folders:"
        while read -r line; do
            if [ -n "$line" ]; then
                # Match slot and parse rest
                slot=$(echo "$line" | cut -d':' -f1)
                rest=$(echo "$line" | cut -d':' -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

                # Split by space and find mountpoint (last element)
                mountpoint=""
                # Extract parts
                device=""
                container=""

                # Check for standard paths starting with /
                # If there are 3 absolute paths
                # We can split the line into array-like parts
                parts=""
                for part in $rest; do
                    parts="$parts|$part"
                done

                # Robust extraction of the last part starting with /
                last_part=$(echo "$rest" | awk '{print $NF}')
                log_msg "  - Slot $slot: Mountpoint is -> $last_part"
            fi
        done < /tmp/vc_mounts_raw.tmp
        rm -f /tmp/vc_mounts_raw.tmp
    else
        log_msg "veracrypt -t -l returned non-zero (meaning no volumes are mounted, or command failed)."
    fi
else
    log_msg "Cannot check active mounts because veracrypt command was not found."
fi

# 4. Check system mounts
log_msg "--------------------------------------------------------"
log_msg "🔍 Checking System Mountpoint commands..."
log_msg "--------------------------------------------------------"
procMounts=$(grep "veracrypt" /proc/mounts || true)
if [ -n "$procMounts" ]; then
    log_msg "Found veracrypt entries in /proc/mounts:"
    echo "$procMounts" | while read -r line; do
        log_msg "  $line"
    done
else
    log_msg "No veracrypt entries found in /proc/mounts."
fi

log_msg "=========================================================="
log_msg "🏁 Diagnostic Check Completed"
log_msg "=========================================================="
