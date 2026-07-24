#!/bin/bash
# veracrypt unmount drive/file:
# Usage: ./vcu.sh <mountpoint-path>

MOUNTPOINT="$1"

log_debug() {
    local MSG="$1"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${TIMESTAMP}] [vcu.sh] ${MSG}" >> /var/log/openmediavault/veracrypt_debug.log 2>/dev/null || true
    echo "[${TIMESTAMP}] [vcu.sh] ${MSG}" >> /tmp/veracrypt_debug.log 2>/dev/null || true
}

log_debug "vcu.sh helper unmount script started."
log_debug "Arguments: MOUNTPOINT='${MOUNTPOINT}'"

if [ -z "$MOUNTPOINT" ]; then
    log_debug "Error: Missing required MOUNTPOINT parameter."
    echo "Usage: $0 <mountpoint-path>"
    exit 1
fi

# Check if veracrypt is installed
if ! command -v veracrypt >/dev/null 2>&1; then
    log_debug "Error: veracrypt binary is NOT installed on the host system!"
else
    log_debug "VeraCrypt is installed. Executing unmount..."
fi

# Dismount the container cleanly
log_debug "Executing veracrypt unmount on: ${MOUNTPOINT}"
if veracrypt -t -u "$MOUNTPOINT"; then
    log_debug "veracrypt unmount completed successfully."
else
    log_debug "veracrypt unmount completed or encountered errors."
fi

# Wait a second to allow dismount to finish
sleep 1

# Delete the folder if it is empty and no longer a mountpoint.
# Crucial: Use rmdir (NEVER rm -rf) so that if unmount failed or was delayed,
# we do not recursively delete user files inside the encrypted mount!
if [ -d "$MOUNTPOINT" ]; then
    log_debug "Attempting to cleanly remove empty mountpoint folder: ${MOUNTPOINT}"
    if rmdir "$MOUNTPOINT" 2>/dev/null; then
        log_debug "Successfully removed mountpoint folder."
    else
        log_debug "Info: mountpoint folder is busy or not empty, leaving on disk."
        echo "Info: mountpoint folder is busy or not empty, leaving on disk."
    fi
fi
log_debug "vcu.sh helper unmount script completed."
