#!/bin/bash
# veracrypt mount drive:
# Check if a name argument was provided
if [ -z "$1" ]; then
    echo "Usage: ./vcd.sh <partition-name>"
    echo "Usage: ./vcd.sh sdc1/"
    exit 1
fi

NAME="$1"

# Map the input to your drive path (e.g., sdb1) and destination folder
DEVICE="/dev/$NAME"
#mount dir needs to be set in app
MOUNT_DIR="/srv/dev-disk-by-uuid-##"
MOUNTPOINT="$MOUNT_DIR/$NAME"

# 1. Create the mount folder
mkdir -p "$MOUNTPOINT"

# 2. Mount the physical device partition with 777 permissions
veracrypt -t --mount "$DEVICE" "$MOUNTPOINT" --fs-options="umask=000" --pim=0 --keyfiles="" --protect-hidden=no
# currently the script asks for a manual password, it can be included as $2
# I only need password in the plugin GUI, but we could setup pim and such too later.

