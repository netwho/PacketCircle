#!/bin/bash
# =============================================================================
# PacketCircle Installer for Linux (x86_64)
# =============================================================================
#
# This script installs the PacketCircle Wireshark plugin on Linux.
#
# What it does:
#   1. Detects your Wireshark installation and version
#   2. Determines the correct plugin API version directory (e.g., 4.6)
#   3. Creates the epan plugin directory if it doesn't exist
#   4. Copies the plugin binary (packetcircle.so) to the plugin directory
#   5. Sets correct file permissions
#
# Plugin directory:
#   - ~/.local/lib/wireshark/plugins/<version>/epan/
#
# Requirements:
#   - Wireshark 4.4.x installed (with Qt6 UI)
#   - Linux x86_64
#
# IMPORTANT: This binary is built against Wireshark 4.4.7 (plugin ABI 4.4).
# It will NOT work with Wireshark 4.6.x, 4.2.x, 4.0.x or other versions.
# If you have a different version, use the matching installer or build from
# source (see src/BUILD.md).
#
# Note: On Linux, plugin directories use dots (e.g., 4.6/epan/),
# on macOS they use dashes (e.g., 4-6/epan/).
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# To uninstall, simply remove the packetcircle.so file from the plugin directory.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_FILE="$SCRIPT_DIR/packetcircle.so"
PLUGIN_NAME="packetcircle.so"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║      PacketCircle Installer for Linux            ║${NC}\n"
printf "${BLUE}║      x86_64 (64-bit Intel/AMD)                   ║${NC}\n"
printf "${BLUE}╚══════════════════════════════════════════════════╝${NC}\n"
printf "\n"

# --- Step 1: Verify the plugin binary exists ---
if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: %s not found in %s${NC}\n" "$PLUGIN_NAME" "$SCRIPT_DIR"
    printf "Please ensure the plugin binary is in the same directory as this script.\n"
    exit 1
fi

printf "${GREEN}✓${NC} Found plugin binary: %s\n" "$PLUGIN_FILE"

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    printf "${YELLOW}Warning: This binary is built for x86_64 but you are running %s${NC}\n" "$ARCH"
    printf "The plugin may not work on this system.\n"
    printf "Continue anyway? [y/N]: "
    read -r CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        exit 1
    fi
fi

# --- Step 2: Find Wireshark and determine version ---
WS_VERSION=""

# Helper: extract version X.Y.Z from a dpkg Version: line
# Handles Debian epoch format like "4:4.6.3-1~deb13u1" -> "4.6.3"
extract_dpkg_version() {
    # Remove epoch (everything up to and including first colon)
    # Then extract first X.Y.Z pattern
    sed 's/^[0-9]*://' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

# Method 1: tshark (command-line, works without display)
if [ -z "$WS_VERSION" ] && command -v tshark >/dev/null 2>&1; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Method 2: wireshark binary (may need display — try anyway)
if [ -z "$WS_VERSION" ] && command -v wireshark >/dev/null 2>&1; then
    WS_VERSION=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Method 3: dpkg (Debian/Ubuntu) — try all common package names
if [ -z "$WS_VERSION" ] && command -v dpkg-query >/dev/null 2>&1; then
    for pkg in wireshark-common wireshark wireshark-qt wireshark-gtk libwireshark-data libwireshark19; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            WS_VERSION=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | extract_dpkg_version)
            if [ -n "$WS_VERSION" ]; then
                break
            fi
        fi
    done
fi

# Method 4: apt-cache as fallback (works even if package is only partially installed)
if [ -z "$WS_VERSION" ] && command -v apt-cache >/dev/null 2>&1; then
    WS_VERSION=$(apt-cache policy wireshark-common 2>/dev/null | grep 'Installed:' | grep -v '(none)' | extract_dpkg_version)
fi
if [ -z "$WS_VERSION" ] && command -v apt-cache >/dev/null 2>&1; then
    WS_VERSION=$(apt-cache policy wireshark 2>/dev/null | grep 'Installed:' | grep -v '(none)' | extract_dpkg_version)
fi

# Method 5: rpm (Fedora/RHEL/SUSE)
if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    WS_VERSION=$(rpm -q wireshark 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi
if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    WS_VERSION=$(rpm -q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Method 6: pacman (Arch Linux)
if [ -z "$WS_VERSION" ] && command -v pacman >/dev/null 2>&1; then
    WS_VERSION=$(pacman -Q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Method 7: look for the library version in known paths
if [ -z "$WS_VERSION" ]; then
    for lib in /usr/lib/x86_64-linux-gnu/libwireshark.so.* \
               /usr/lib64/libwireshark.so.* \
               /usr/lib/libwireshark.so.*; do
        if [ -f "$lib" ] || [ -L "$lib" ]; then
            # Extract from library filename or soname
            SOVERSION=$(basename "$lib" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            if [ -n "$SOVERSION" ]; then
                # Library version doesn't directly map to Wireshark version,
                # but we can look at the plugin dir instead
                break
            fi
        fi
    done
fi

# Method 8: detect from existing system plugin directories
if [ -z "$WS_VERSION" ]; then
    for dir in /usr/lib/x86_64-linux-gnu/wireshark/plugins/* \
               /usr/lib64/wireshark/plugins/* \
               /usr/lib/wireshark/plugins/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+\.[0-9]+$'; then
                # Convert directory name (e.g., "4.6") to version
                DIR_MAJOR=$(printf "%s" "$DIRNAME" | cut -d. -f1)
                DIR_MINOR=$(printf "%s" "$DIRNAME" | cut -d. -f2)
                WS_VERSION="${DIR_MAJOR}.${DIR_MINOR}.0"
                printf "  (detected from plugin directory: %s)\n" "$dir"
                break
            fi
        fi
    done
fi

if [ -z "$WS_VERSION" ]; then
    printf "${YELLOW}Warning: Could not detect Wireshark version.${NC}\n"
    printf "Please ensure Wireshark is installed.\n"
    printf "\n"
    printf "  Diagnostic commands to try:\n"
    printf "    dpkg -l | grep wireshark\n"
    printf "    apt-cache policy wireshark-common\n"
    printf "    ls /usr/lib/x86_64-linux-gnu/wireshark/plugins/\n"
    printf "    tshark --version\n"
    printf "\n"
    printf "Enter Wireshark major.minor version (e.g., 4.6): "
    read -r WS_VERSION
    WS_VERSION="${WS_VERSION}.0"
fi

printf "${GREEN}✓${NC} Wireshark version: %s\n" "$WS_VERSION"

# Determine plugin path ID from version
WS_MAJOR=$(printf "%s" "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(printf "%s" "$WS_VERSION" | cut -d. -f2)

# --- Version compatibility check ---
REQUIRED_MAJOR=4
REQUIRED_MINOR=4

if [ "$WS_MAJOR" != "$REQUIRED_MAJOR" ] || [ "$WS_MINOR" != "$REQUIRED_MINOR" ]; then
    printf "\n"
    printf "${RED}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${RED}║  INCOMPATIBLE WIRESHARK VERSION                         ║${NC}\n"
    printf "${RED}╚══════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Your Wireshark version:   ${YELLOW}%s${NC}\n" "$WS_VERSION"
    printf "  Required version:         ${GREEN}4.4.x${NC}\n"
    printf "\n"
    printf "  This pre-built plugin binary was compiled against Wireshark\n"
    printf "  4.4.7 (plugin ABI 4.4) and is NOT compatible with %s.\n" "$WS_VERSION"
    printf "\n"
    printf "  Options:\n"
    printf "  1. Use the matching installer for your Wireshark version\n"
    printf "     (e.g., linux-x86_64 for Wireshark 4.6.x)\n"
    printf "  2. Build from source for your version (see src/BUILD.md)\n"
    printf "\n"
    printf "  Install anyway (will NOT work)? [y/N]: "
    read -r FORCE_INSTALL
    if [ "$FORCE_INSTALL" != "y" ] && [ "$FORCE_INSTALL" != "Y" ]; then
        printf "Installation cancelled.\n"
        exit 1
    fi
    printf "${YELLOW}Warning: Installing incompatible binary. The plugin will not load.${NC}\n"
fi

# Look for version-like directories in system plugin paths
# Linux uses dots (4.6), macOS uses dashes (4-6)
PLUGIN_PATH_ID=""
for dir in /usr/lib/x86_64-linux-gnu/wireshark/plugins/* \
           /usr/lib64/wireshark/plugins/* \
           /usr/lib/wireshark/plugins/* \
           /usr/local/lib/wireshark/plugins/* \
           /usr/local/lib64/wireshark/plugins/* \
           /snap/wireshark/current/usr/lib/x86_64-linux-gnu/wireshark/plugins/*; do
    if [ -d "$dir" ]; then
        DIRNAME=$(basename "$dir")
        # Only match version-like directory names (e.g., "4.6", "4-6", "4.4")
        if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+[-\.][0-9]+$'; then
            PLUGIN_PATH_ID="$DIRNAME"
            break
        fi
    fi
done

# Check personal plugin directory for version-like dirs
if [ -z "$PLUGIN_PATH_ID" ]; then
    for dir in "$HOME/.local/lib/wireshark/plugins"/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+[-\.][0-9]+$'; then
                PLUGIN_PATH_ID="$DIRNAME"
                break
            fi
        fi
    done
fi

# Fallback: construct from version (Linux uses dots: 4.6)
if [ -z "$PLUGIN_PATH_ID" ]; then
    PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"
fi

printf "${GREEN}✓${NC} Plugin API version: %s\n" "$PLUGIN_PATH_ID"

# --- Step 3: Install ---
INSTALL_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"

printf "\n"
printf "${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"

mkdir -p "$INSTALL_DIR"
cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"

# --- Step 4: Verify ---
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Plugin installed to:\n"
    printf "  ${BLUE}%s/%s${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
    printf "\n"
    printf "  Next steps:\n"
    printf "  1. Restart Wireshark (if running)\n"
    printf "  2. Open a capture file or start a live capture\n"
    printf "  3. Look for PacketCircle in the Tools menu\n"
    printf "\n"
    printf "  To uninstall:\n"
    printf "  ${YELLOW}rm \"%s/%s\"${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
    printf "\n"
    printf "  ${YELLOW}Troubleshooting:${NC}\n"
    printf "  If the plugin doesn't appear in the Tools menu:\n"
    printf "  - Verify the path: Help → About Wireshark → Folders → Personal Plugins\n"
    printf "  - Check Wireshark loads it: wireshark -o log.level:debug 2>&1 | grep packetcircle\n"
    printf "  - 'DBus not running' warnings are harmless and can be ignored\n"
    printf "\n"
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
