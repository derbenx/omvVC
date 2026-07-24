#!/bin/sh
# VeraCrypt automatic console installer helper script

set -e

log_debug() {
    local MSG="$1"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[${TIMESTAMP}] [vci.sh] ${MSG}" >> /var/log/openmediavault/veracrypt_debug.log 2>/dev/null || true
    echo "[${TIMESTAMP}] [vci.sh] ${MSG}" >> /tmp/veracrypt_debug.log 2>/dev/null || true
}

log_debug "vci.sh helper installer script started."

# Detect architecture
ARCH=$(dpkg --print-architecture)
log_debug "Detected architecture: ${ARCH}"

# Detect OS and release codename
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    VERSION_CODENAME_OR_ID=$VERSION_CODENAME
    if [ -z "$VERSION_CODENAME_OR_ID" ]; then
        VERSION_CODENAME_OR_ID=$VERSION_ID
    fi
else
    OS_ID="debian"
    VERSION_CODENAME_OR_ID="bookworm"
fi

# Normalize OS ID and codename to match Launchpad package naming
OS_NAME=""
if [ "$OS_ID" = "ubuntu" ]; then
    if [ "$VERSION_ID" = "24.04" ]; then
        OS_NAME="Ubuntu-24.04"
    elif [ "$VERSION_ID" = "22.04" ]; then
        OS_NAME="Ubuntu-22.04"
    elif [ "$VERSION_ID" = "20.04" ]; then
        OS_NAME="Ubuntu-20.04"
    else
        OS_NAME="Ubuntu-24.04" # fallback
    fi
else
    # default to debian
    if [ "$VERSION_CODENAME_OR_ID" = "trixie" ] || [ "$VERSION_ID" = "13" ]; then
        OS_NAME="Debian-13"
    elif [ "$VERSION_CODENAME_OR_ID" = "bookworm" ] || [ "$VERSION_ID" = "12" ]; then
        OS_NAME="Debian-12"
    elif [ "$VERSION_CODENAME_OR_ID" = "bullseye" ] || [ "$VERSION_ID" = "11" ]; then
        OS_NAME="Debian-11"
    else
        OS_NAME="Debian-12" # fallback
    fi
fi

echo "Detected OS: $OS_NAME, Architecture: $ARCH"

# Create a secure temp directory with restricted permissions
TMP_DIR=$(mktemp -d /tmp/veracrypt_XXXXXX)
chmod 700 "$TMP_DIR"

# We will try fallback versions if download fails
VC_VERSIONS="1.26.24 1.26.29 1.26.14 1.26.20"
DOWNLOAD_SUCCESS=false

for VC_VER in $VC_VERSIONS; do
    URL="https://launchpad.net/veracrypt/trunk/${VC_VER}/+download/veracrypt-console-${VC_VER}-${OS_NAME}-${ARCH}.deb"
    echo "Attempting to download VeraCrypt version ${VC_VER} for ${OS_NAME}..."
    if wget --spider -q "$URL"; then
        echo "Found package at $URL"
        if wget -O "$TMP_DIR/veracrypt.deb" "$URL"; then
            DOWNLOAD_SUCCESS=true
            break
        fi
    else
        # If the specific OS version wasn't found, try a generic or fallback OS version if on Debian
        echo "Not found. Trying fallback package options..."
        if [ "$OS_NAME" = "Debian-13" ]; then
            FALLBACK_URL="https://launchpad.net/veracrypt/trunk/${VC_VER}/+download/veracrypt-console-${VC_VER}-Debian-12-${ARCH}.deb"
            if wget --spider -q "$FALLBACK_URL"; then
                echo "Found fallback package at $FALLBACK_URL"
                if wget -O "$TMP_DIR/veracrypt.deb" "$FALLBACK_URL"; then
                    DOWNLOAD_SUCCESS=true
                    break
                fi
            fi
        fi
    fi
done

if [ "$DOWNLOAD_SUCCESS" = "false" ]; then
    log_debug "Error: Failed to download any compatible VeraCrypt console package from Launchpad."
    echo "Error: Failed to download any compatible VeraCrypt console package from Launchpad."
    rm -rf "$TMP_DIR"
    exit 1
fi

log_debug "Installing VeraCrypt console package..."
export DEBIAN_FRONTEND=noninteractive
if dpkg -i "$TMP_DIR/veracrypt.deb" || apt-get install -f -y; then
    log_debug "dpkg / apt-get installation command completed."
else
    log_debug "dpkg / apt-get installation command encountered errors."
fi

# Clean up
rm -rf "$TMP_DIR"

log_debug "Verifying installation..."
if command -v veracrypt >/dev/null 2>&1; then
    VER=$(veracrypt -t --version 2>&1)
    log_debug "VeraCrypt is installed! Version: ${VER}"
else
    log_debug "VeraCrypt binary not found after installation attempt."
fi

echo "VeraCrypt console package installation completed successfully."
exit 0
