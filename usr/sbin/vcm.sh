#!/bin/bash
# veracrypt mount file:
# Usage: ./vcm.sh <container-path> <mountpoint-path> <password> <permissions>

CONTAINER="$1"
MOUNTPOINT="$2"
PASSWORD="$3"
PERM="$4"

if [ -z "$CONTAINER" ] || [ -z "$MOUNTPOINT" ]; then
    echo "Usage: $0 <container-path> <mountpoint-path> [password] [permissions]"
    exit 1
fi

# 1. Create the mount folder
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

# 3. Mount the file container with specified permissions
if [ -n "$PASSWORD" ]; then
    printf "%s\n" "$PASSWORD" | veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --fs-options="$FS_OPTS" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive --stdin
else
    veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --fs-options="$FS_OPTS" --pim=0 --keyfiles="" --protect-hidden=no --non-interactive
fi
