#!/bin/bash
# =============================================================================
# PacketCircle Unified Installer for Linux (x86_64)
# =============================================================================
#
# This script installs the PacketCircle Wireshark plugin on Linux.
# It includes pre-built binaries for multiple Wireshark versions and
# automatically selects the correct one for your system.
#
# Supported Wireshark versions:
#   - 4.2.x  (plugin ABI 4.2)
#   - 4.4.x  (plugin ABI 4.4)
#   - 4.6.x  (plugin ABI 4.6)
#
# What it does:
#   1. Detects your Wireshark installation and version
#   2. Selects the matching pre-built binary
#   3. Creates the epan plugin directory if it doesn't exist
#   4. Copies the plugin binary (packetcircle.so) to the plugin directory
#   5. Sets correct file permissions
#
# Plugin directory:
#   ~/.local/lib/wireshark/plugins/<version>/epan/
#
# Note: On Linux, plugin directories use dots (e.g., 4.6/epan/).
#       On macOS they use dashes (e.g., 4-6/epan/).
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# To uninstall, simply remove the packetcircle.so file from the plugin directory.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
PLUGIN_NAME="packetcircle.so"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║   PacketCircle Unified Installer for Linux       ║${NC}\n"
printf "${BLUE}║   x86_64 (64-bit Intel/AMD)                      ║${NC}\n"
printf "${BLUE}║                                                   ║${NC}\n"
printf "${BLUE}║   Supports Wireshark 4.2.x, 4.4.x, 4.6.x        ║${NC}\n"
printf "${BLUE}╚══════════════════════════════════════════════════╝${NC}\n"
printf "\n"

# --- Step 1: Verify binaries exist ---
MISSING=0
for ver in ws42 ws44 ws46; do
    if [ ! -f "$BIN_DIR/packetcircle-${ver}.so" ]; then
        printf "${RED}Error: bin/packetcircle-${ver}.so not found${NC}\n"
        MISSING=1
    fi
done
if [ "$MISSING" = "1" ]; then
    printf "Please ensure the bin/ directory is intact.\n"
    exit 1
fi

printf "${GREEN}✓${NC} Found plugin binaries for Wireshark 4.2, 4.4, and 4.6\n"

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    printf "${YELLOW}Warning: These binaries are built for x86_64 but you are running %s${NC}\n" "$ARCH"
    printf "The plugin may not work on this system.\n"
    printf "Continue anyway? [y/N]: "
    read -r CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        exit 1
    fi
fi

# --- Step 2: Detect Wireshark version ---
WS_VERSION=""

# Helper: extract version X.Y.Z from a dpkg Version: line
# Handles Debian epoch format like "4:4.6.3-1~deb13u1" -> "4.6.3"
extract_dpkg_version() {
    # Remove epoch (everything up to and including first colon)
    # Then extract first X.Y.Z pattern
    sed 's/^[0-9]*://' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

printf "\n${CYAN}Detecting Wireshark version...${NC}\n"

# Method 1: tshark (command-line, works without display)
if [ -z "$WS_VERSION" ] && command -v tshark >/dev/null 2>&1; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "  detected via tshark: %s\n" "$WS_VERSION"
    fi
fi

# Method 2: wireshark binary (may need display — try anyway)
if [ -z "$WS_VERSION" ] && command -v wireshark >/dev/null 2>&1; then
    WS_VERSION=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "  detected via wireshark: %s\n" "$WS_VERSION"
    fi
fi

# Method 3: dpkg (Debian/Ubuntu) — try all common package names
if [ -z "$WS_VERSION" ] && command -v dpkg-query >/dev/null 2>&1; then
    for pkg in wireshark-common wireshark wireshark-qt wireshark-gtk libwireshark-data libwireshark19 libwireshark18 libwireshark17; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            WS_VERSION=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | extract_dpkg_version)
            if [ -n "$WS_VERSION" ]; then
                printf "  detected via dpkg (%s): %s\n" "$pkg" "$WS_VERSION"
                break
            fi
        fi
    done
fi

# Method 4: apt-cache as fallback
if [ -z "$WS_VERSION" ] && command -v apt-cache >/dev/null 2>&1; then
    for pkg in wireshark-common wireshark; do
        WS_VERSION=$(apt-cache policy "$pkg" 2>/dev/null | grep 'Installed:' | grep -v '(none)' | extract_dpkg_version)
        if [ -n "$WS_VERSION" ]; then
            printf "  detected via apt-cache (%s): %s\n" "$pkg" "$WS_VERSION"
            break
        fi
    done
fi

# Method 5: rpm (Fedora/RHEL/SUSE)
if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    for pkg in wireshark wireshark-qt wireshark-cli; do
        WS_VERSION=$(rpm -q "$pkg" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ -n "$WS_VERSION" ]; then
            printf "  detected via rpm (%s): %s\n" "$pkg" "$WS_VERSION"
            break
        fi
    done
fi

# Method 6: pacman (Arch Linux)
if [ -z "$WS_VERSION" ] && command -v pacman >/dev/null 2>&1; then
    WS_VERSION=$(pacman -Q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "  detected via pacman: %s\n" "$WS_VERSION"
    fi
fi

# Method 7: detect from existing system plugin directories
if [ -z "$WS_VERSION" ]; then
    for dir in /usr/lib/x86_64-linux-gnu/wireshark/plugins/* \
               /usr/lib64/wireshark/plugins/* \
               /usr/lib/wireshark/plugins/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+\.[0-9]+$'; then
                DIR_MAJOR=$(printf "%s" "$DIRNAME" | cut -d. -f1)
                DIR_MINOR=$(printf "%s" "$DIRNAME" | cut -d. -f2)
                WS_VERSION="${DIR_MAJOR}.${DIR_MINOR}.0"
                printf "  detected from plugin directory: %s\n" "$dir"
                break
            fi
        fi
    done
fi

# Method 8: detect from libwireshark soname
if [ -z "$WS_VERSION" ]; then
    for lib in /usr/lib/x86_64-linux-gnu/libwireshark.so \
               /usr/lib64/libwireshark.so \
               /usr/lib/libwireshark.so; do
        if [ -L "$lib" ] || [ -f "$lib" ]; then
            SONAME=$(readlink -f "$lib" 2>/dev/null | grep -oE 'libwireshark\.so\.[0-9]+' | grep -oE '[0-9]+$')
            if [ -n "$SONAME" ]; then
                # Map soname to version: 17→4.2, 18→4.4, 19→4.6
                case "$SONAME" in
                    17) WS_VERSION="4.2.0"; printf "  detected from libwireshark.so.17: 4.2.x\n" ;;
                    18) WS_VERSION="4.4.0"; printf "  detected from libwireshark.so.18: 4.4.x\n" ;;
                    19) WS_VERSION="4.6.0"; printf "  detected from libwireshark.so.19: 4.6.x\n" ;;
                    *)  printf "  found libwireshark.so.%s (unknown mapping)\n" "$SONAME" ;;
                esac
                break
            fi
        fi
    done
fi

# If still not detected, ask user
if [ -z "$WS_VERSION" ]; then
    printf "\n"
    printf "${YELLOW}Could not automatically detect Wireshark version.${NC}\n"
    printf "\n"
    printf "  Diagnostic commands to try:\n"
    printf "    dpkg -l | grep wireshark\n"
    printf "    apt-cache policy wireshark-common\n"
    printf "    rpm -qa | grep wireshark\n"
    printf "    ls /usr/lib/x86_64-linux-gnu/wireshark/plugins/\n"
    printf "    tshark --version\n"
    printf "\n"
    printf "Enter Wireshark major.minor version (e.g., 4.4 or 4.6): "
    read -r WS_VERSION_INPUT
    WS_VERSION="${WS_VERSION_INPUT}.0"
fi

# Extract major.minor
WS_MAJOR=$(printf "%s" "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(printf "%s" "$WS_VERSION" | cut -d. -f2)

printf "\n${GREEN}✓${NC} Wireshark version: ${CYAN}%s${NC} (ABI: %s.%s)\n" "$WS_VERSION" "$WS_MAJOR" "$WS_MINOR"

# --- Step 3: Select the matching binary ---
SELECTED_BINARY=""
SELECTED_LABEL=""

case "$WS_MINOR" in
    2)
        SELECTED_BINARY="$BIN_DIR/packetcircle-ws42.so"
        SELECTED_LABEL="Wireshark 4.2.x (built against 4.2.14)"
        ;;
    4)
        SELECTED_BINARY="$BIN_DIR/packetcircle-ws44.so"
        SELECTED_LABEL="Wireshark 4.4.x (built against 4.4.7)"
        ;;
    6)
        SELECTED_BINARY="$BIN_DIR/packetcircle-ws46.so"
        SELECTED_LABEL="Wireshark 4.6.x (built against 4.6.3)"
        ;;
    *)
        printf "\n"
        printf "${RED}╔══════════════════════════════════════════════════════════╗${NC}\n"
        printf "${RED}║  UNSUPPORTED WIRESHARK VERSION                          ║${NC}\n"
        printf "${RED}╚══════════════════════════════════════════════════════════╝${NC}\n"
        printf "\n"
        printf "  Your Wireshark version:   ${YELLOW}%s${NC}\n" "$WS_VERSION"
        printf "  Supported versions:       ${GREEN}4.2.x, 4.4.x, 4.6.x${NC}\n"
        printf "\n"
        printf "  This installer does not include a binary for Wireshark %s.%s.\n" "$WS_MAJOR" "$WS_MINOR"
        printf "  Options:\n"
        printf "  1. Upgrade or downgrade to a supported version\n"
        printf "  2. Build from source (see src/BUILD.md)\n"
        printf "\n"

        # Offer to install the closest match
        printf "  Or choose a binary to install manually:\n"
        printf "    1) 4.2.x binary\n"
        printf "    2) 4.4.x binary\n"
        printf "    3) 4.6.x binary\n"
        printf "    q) Quit\n"
        printf "\n"
        printf "  Choice [q]: "
        read -r MANUAL_CHOICE
        case "$MANUAL_CHOICE" in
            1)
                SELECTED_BINARY="$BIN_DIR/packetcircle-ws42.so"
                SELECTED_LABEL="Wireshark 4.2.x (FORCED — may not work)"
                WS_MINOR=2
                ;;
            2)
                SELECTED_BINARY="$BIN_DIR/packetcircle-ws44.so"
                SELECTED_LABEL="Wireshark 4.4.x (FORCED — may not work)"
                WS_MINOR=4
                ;;
            3)
                SELECTED_BINARY="$BIN_DIR/packetcircle-ws46.so"
                SELECTED_LABEL="Wireshark 4.6.x (FORCED — may not work)"
                WS_MINOR=6
                ;;
            *)
                printf "Installation cancelled.\n"
                exit 1
                ;;
        esac
        printf "${YELLOW}Warning: Installing binary for a non-matching version. The plugin may not load.${NC}\n"
        ;;
esac

printf "${GREEN}✓${NC} Selected binary: %s\n" "$SELECTED_LABEL"

# --- Step 4: Determine plugin directory ---

# Look for existing version-like directories in system plugin paths
PLUGIN_PATH_ID=""
for dir in /usr/lib/x86_64-linux-gnu/wireshark/plugins/* \
           /usr/lib64/wireshark/plugins/* \
           /usr/lib/wireshark/plugins/* \
           /usr/local/lib/wireshark/plugins/* \
           /usr/local/lib64/wireshark/plugins/* \
           /snap/wireshark/current/usr/lib/x86_64-linux-gnu/wireshark/plugins/*; do
    if [ -d "$dir" ]; then
        DIRNAME=$(basename "$dir")
        if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+[-\.][0-9]+$'; then
            # Check if this dir matches the selected version
            DIR_MINOR=$(printf "%s" "$DIRNAME" | sed 's/[^0-9]/ /g' | awk '{print $2}')
            if [ "$DIR_MINOR" = "$WS_MINOR" ]; then
                PLUGIN_PATH_ID="$DIRNAME"
                break
            fi
        fi
    fi
done

# Check personal plugin directory
if [ -z "$PLUGIN_PATH_ID" ]; then
    for dir in "$HOME/.local/lib/wireshark/plugins"/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+[-\.][0-9]+$'; then
                DIR_MINOR=$(printf "%s" "$DIRNAME" | sed 's/[^0-9]/ /g' | awk '{print $2}')
                if [ "$DIR_MINOR" = "$WS_MINOR" ]; then
                    PLUGIN_PATH_ID="$DIRNAME"
                    break
                fi
            fi
        fi
    done
fi

# Fallback: construct from version (Linux uses dots: 4.2, 4.4, 4.6)
if [ -z "$PLUGIN_PATH_ID" ]; then
    PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"
fi

printf "${GREEN}✓${NC} Plugin API version: %s\n" "$PLUGIN_PATH_ID"

# --- Step 5: Install ---
INSTALL_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"

printf "\n"
printf "${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"

mkdir -p "$INSTALL_DIR"
cp "$SELECTED_BINARY" "$INSTALL_DIR/$PLUGIN_NAME"
chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"

# --- Step 6: Verify ---
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    FILESIZE=$(ls -lh "$INSTALL_DIR/$PLUGIN_NAME" | awk '{print $5}')
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Plugin:      %s\n" "$SELECTED_LABEL"
    printf "  Size:        %s\n" "$FILESIZE"
    printf "  Installed:   ${BLUE}%s/%s${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
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
    printf "  - Verify the path: Help > About Wireshark > Folders > Personal Plugins\n"
    printf "  - Check loading: wireshark -o log.level:debug 2>&1 | grep packetcircle\n"
    printf "  - 'DBus not running' warnings are harmless and can be ignored\n"
    printf "  - Make sure your Wireshark version matches (currently: %s)\n" "$WS_VERSION"
    printf "\n"
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
