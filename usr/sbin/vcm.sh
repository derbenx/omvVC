#!/bin/bash
# veracrypt mount file:
# Usage: ./vcm.sh <container-path> <mountpoint-path> <password> <permissions>

CONTAINER="$1"
MOUNTPOINT="$2"
PASSWORD="$3"
PERM="$4"

log_debug() {
    local MSG="$1"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${TIMESTAMP}] [vcm.sh] ${MSG}" >> /var/log/openmediavault/veracrypt_debug.log 2>/dev/null || true
    echo "[${TIMESTAMP}] [vcm.sh] ${MSG}" >> /tmp/veracrypt_debug.log 2>/dev/null || true
}

log_debug "vcm.sh helper mount file script started."
log_debug "Arguments: CONTAINER='${CONTAINER}', MOUNTPOINT='${MOUNTPOINT}', PERM='${PERM}'"

if [ -z "$CONTAINER" ] || [ -z "$MOUNTPOINT" ]; then
    log_debug "Error: Missing required CONTAINER or MOUNTPOINT parameters."
    echo "Usage: $0 <container-path> <mountpoint-path> [password] [permissions]"
    exit 1
fi

# Check if veracrypt is installed
if ! command -v veracrypt >/dev/null 2>&1; then
    log_debug "Error: veracrypt binary is NOT installed on the host system!"
else
    log_debug "VeraCrypt is installed. Executing mount sequence..."
fi

# 1. Create the mount folder
log_debug "Creating mount point directory: ${MOUNTPOINT}"
mkdir -p "$MOUNTPOINT"

# 2. Convert standard permissions (e.g. 770) to umask (e.g. 007)
# Formula: umask digit = 7 - perm digit
UMASK="000"
if [[ "$PERM" =~ ^[0-7]{3}$ ]]; then
    D1=$(( 7 - ${PERM:0:1} ))
    D2=$(( 7 - ${PERM:1:1} ))
    D3=$(( 7 - ${PERM:2:1} ))
    UMASK="${D1}${D2}${D3}"
fi
FS_OPTS="umask=${UMASK}"

# 3. Mount the file container with specified permissions, falling back if fs-options fails
MOUNT_OK=false
if [ -n "$PASSWORD" ]; then
    if printf "%s\n" "$PASSWORD" | veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --fs-options="$FS_OPTS" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive --stdin; then
        MOUNT_OK=true
    else
        echo "Mounting with fs-options failed, trying fallback without fs-options..."
        # Dismount first to release any partially-mapped slots/devices
        veracrypt -t -u "$CONTAINER" 2>/dev/null || veracrypt -t -u "$MOUNTPOINT" 2>/dev/null || true
        if printf "%s\n" "$PASSWORD" | veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive --stdin; then
            MOUNT_OK=true
            chmod "$PERM" "$MOUNTPOINT" 2>/dev/null || true
        fi
    fi
else
    if veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --fs-options="$FS_OPTS" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive; then
        MOUNT_OK=true
    else
        echo "Mounting with fs-options failed, trying fallback without fs-options..."
        # Dismount first to release any partially-mapped slots/devices
        veracrypt -t -u "$CONTAINER" 2>/dev/null || veracrypt -t -u "$MOUNTPOINT" 2>/dev/null || true
        if veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive; then
            MOUNT_OK=true
            chmod "$PERM" "$MOUNTPOINT" 2>/dev/null || true
        fi
    fi
fi

if [ "$MOUNT_OK" = "true" ]; then
    log_debug "Mount command succeeded successfully!"
    exit 0
else
    log_debug "Error: Mount command failed completely."
    exit 1
fi
