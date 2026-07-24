#!/bin/sh
# Rebuild and install OpenMediaVault VeraCrypt plugin, then restart engine daemon cleanly.

set -e

echo "=========================================================="
echo "🔧 Rebuilding Debian package..."
echo "=========================================================="
dpkg-buildpackage -us -uc -b -d

echo ""
echo "=========================================================="
echo "📦 Installing generated Debian package..."
echo "=========================================================="
sudo dpkg -i ../openmediavault-veracrypt_1.0.0_all.deb
sudo apt-get install -f -y

echo ""
echo "=========================================================="
echo "🔨 Compiling OpenMediaVault Web UI workbench cache..."
echo "=========================================================="
sudo omv-mkworkbench all || true

echo ""
echo "=========================================================="
echo "🔄 Stopping openmediavault-engined service..."
echo "=========================================================="
sudo systemctl stop openmediavault-engined.service || true
sudo pkill -f omv-engined || true

echo ""
echo "=========================================================="
echo "🚀 Starting openmediavault-engined service..."
echo "=========================================================="
sudo systemctl start openmediavault-engined.service

echo ""
echo "=========================================================="
echo "🎉 Done! VeraCrypt plugin has been successfully reloaded."
echo "📝 You can run a full system and mount diagnostic check using:"
echo "   sudo vcdiag.sh"
echo "📝 You can also follow backend logs live using:"
echo "   tail -f /var/log/openmediavault/veracrypt_debug.log"
echo "=========================================================="
