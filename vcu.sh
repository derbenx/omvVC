#!/bin/bash
# veracrypt unmount drive/file:
# container path here should be set by GUI
CONTAINER="/srv/dev-disk-by-uuid-##"
MOUNTPOINT="$CONTAINER$1"

# Dismount the container cleanly
veracrypt -t -u "$MOUNTPOINT"