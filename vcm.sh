#!/bin/bash
# veracrypt mount file:
## USAGE ./vcm.sh container
if [ -z "$1" ]; then
    echo "Usage: ./vcm.sh <name>"
    exit 1
fi
NAME="$1"

#these two need paths set in OMV GUI
CONTAINER_DIR="/srv/dev-disk-by-uuid-##"
MOUNT_DIR="/srv/dev-disk-by-uuid-##"

CONTAINER="$CONTAINER_DIR$NAME"
MOUNTPOINT="$MOUNT_DIR/$NAME"
mkdir "$MOUNTPOINT"
veracrypt -t --mount "$CONTAINER" "$MOUNTPOINT" --fs-options="umask=000" --pim=0 --keyfiles="" --protect-hidden=no
# need password defined and sent as $2