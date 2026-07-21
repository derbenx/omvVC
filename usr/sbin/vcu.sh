#!/bin/bash
# veracrypt unmount drive/file:
# Usage: ./vcu.sh <mountpoint-path>

MOUNTPOINT="$1"

if [ -z "$MOUNTPOINT" ]; then
    echo "Usage: $0 <mountpoint-path>"
    exit 1
fi

# Dismount the container cleanly
veracrypt -t -u "$MOUNTPOINT"

# Wait a second to allow dismount to finish
sleep 1

# Delete the folder if it is empty and no longer a mountpoint.
# Crucial: Use rmdir (NEVER rm -rf) so that if unmount failed or was delayed,
# we do not recursively delete user files inside the encrypted mount!
if [ -d "$MOUNTPOINT" ]; then
    rmdir "$MOUNTPOINT" 2>/dev/null || echo "Info: mountpoint folder is busy or not empty, leaving on disk."
fi
