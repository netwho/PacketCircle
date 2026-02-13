#!/bin/bash
# =============================================================================
# PacketCircle Installer for macOS (Universal Binary - Intel & Apple Silicon)
# =============================================================================
#
# This script installs the PacketCircle Wireshark plugin on macOS.
#
# What it does:
#   1. Detects your Wireshark installation and version
#   2. Determines the correct plugin API version directory (e.g., 4-6)
#   3. Creates the epan plugin directory if it doesn't exist
#   4. Copies the universal binary (packetcircle.so) to the plugin directory
#   5. Sets correct file permissions
#
# The universal binary works on both Intel (x86_64) and Apple Silicon (arm64)
# Macs without requiring Rosetta translation.
#
# Plugin directory locations (in order of preference):
#   - Personal:  ~/.local/lib/wireshark/plugins/<version>/epan/
#   - App bundle: /Applications/Wireshark.app/Contents/PlugIns/wireshark/<version>/epan/
#
# Requirements:
#   - Wireshark 4.6.x installed (via DMG or Homebrew)
#   - macOS 13.0 or later
#
# IMPORTANT: This binary is built against Wireshark 4.6.3 (plugin ABI 4-6).
# It will NOT work with older versions (4.4, 4.2, 4.0) or newer (4.8+).
# If you have a different version, build from source (see src/BUILD.md).
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
printf "${BLUE}║      PacketCircle Installer for macOS            ║${NC}\n"
printf "${BLUE}║      Universal Binary (Intel + Apple Silicon)    ║${NC}\n"
printf "${BLUE}╚══════════════════════════════════════════════════╝${NC}\n"
printf "\n"

# --- Step 1: Verify the plugin binary exists ---
if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: %s not found in %s${NC}\n" "$PLUGIN_NAME" "$SCRIPT_DIR"
    printf "Please ensure the plugin binary is in the same directory as this script.\n"
    exit 1
fi

printf "${GREEN}✓${NC} Found plugin binary: %s\n" "$PLUGIN_FILE"
printf "  Architecture: "
file "$PLUGIN_FILE" | grep -o "universal binary.*" || file "$PLUGIN_FILE" | grep -o "Mach-O.*"

# --- Step 2: Find Wireshark and determine version ---
WIRESHARK_APP=""
WS_VERSION=""

# Check for Wireshark.app
if [ -d "/Applications/Wireshark.app" ]; then
    WIRESHARK_APP="/Applications/Wireshark.app"
elif [ -d "$HOME/Applications/Wireshark.app" ]; then
    WIRESHARK_APP="$HOME/Applications/Wireshark.app"
fi

# Try to get version from the app bundle Info.plist
if [ -n "$WIRESHARK_APP" ]; then
    WS_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$WIRESHARK_APP/Contents/Info.plist" 2>/dev/null || true)
fi

# Fallback: try tshark
if [ -z "$WS_VERSION" ] && command -v tshark >/dev/null 2>&1; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Fallback: try Wireshark binary directly
if [ -z "$WS_VERSION" ] && [ -n "$WIRESHARK_APP" ]; then
    WS_VERSION=$("$WIRESHARK_APP/Contents/MacOS/Wireshark" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [ -z "$WS_VERSION" ]; then
    printf "${YELLOW}Warning: Could not detect Wireshark version.${NC}\n"
    printf "Please ensure Wireshark is installed.\n"
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
REQUIRED_MINOR=6

if [ "$WS_MAJOR" != "$REQUIRED_MAJOR" ] || [ "$WS_MINOR" != "$REQUIRED_MINOR" ]; then
    printf "\n"
    printf "${RED}╔══════════════════════════════════════════════════════════╗${NC}\n"
    printf "${RED}║  INCOMPATIBLE WIRESHARK VERSION                         ║${NC}\n"
    printf "${RED}╚══════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Your Wireshark version:   ${YELLOW}%s${NC}\n" "$WS_VERSION"
    printf "  Required version:         ${GREEN}4.6.x${NC}\n"
    printf "\n"
    printf "  This pre-built plugin binary was compiled against Wireshark\n"
    printf "  4.6.3 (plugin ABI 4-6) and is NOT compatible with %s.\n" "$WS_VERSION"
    printf "\n"
    printf "  Options:\n"
    printf "  1. Upgrade Wireshark to 4.6.x: ${BLUE}https://www.wireshark.org/download.html${NC}\n"
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

# First: look inside the Wireshark.app bundle for actual plugin version directories
PLUGIN_PATH_ID=""
if [ -n "$WIRESHARK_APP" ]; then
    for dir in "$WIRESHARK_APP/Contents/PlugIns/wireshark"/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            # Only match version-like directory names (e.g., "4-6", "4-4", "3-6")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+-[0-9]+$'; then
                PLUGIN_PATH_ID="$DIRNAME"
                break
            fi
        fi
    done
fi

# Second: look in personal plugin directory for version-like dirs
if [ -z "$PLUGIN_PATH_ID" ]; then
    for dir in "$HOME/.local/lib/wireshark/plugins"/*; do
        if [ -d "$dir" ]; then
            DIRNAME=$(basename "$dir")
            if printf "%s" "$DIRNAME" | grep -qE '^[0-9]+-[0-9]+$'; then
                PLUGIN_PATH_ID="$DIRNAME"
                break
            fi
        fi
    done
fi

# Fallback: construct from version
if [ -z "$PLUGIN_PATH_ID" ]; then
    PLUGIN_PATH_ID="${WS_MAJOR}-${WS_MINOR}"
fi

printf "${GREEN}✓${NC} Plugin API version: %s\n" "$PLUGIN_PATH_ID"

# --- Step 3: Determine installation directory ---
PERSONAL_PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"
SYSTEM_PLUGIN_DIR=""
if [ -n "$WIRESHARK_APP" ]; then
    SYSTEM_PLUGIN_DIR="$WIRESHARK_APP/Contents/PlugIns/wireshark/$PLUGIN_PATH_ID/epan"
fi

printf "\n"
printf "Where would you like to install the plugin?\n"
printf "\n"
printf "  1) Personal directory (recommended)\n"
printf "     %s\n" "$PERSONAL_PLUGIN_DIR"
if [ -n "$SYSTEM_PLUGIN_DIR" ]; then
    printf "\n"
    printf "  2) Application bundle (requires admin)\n"
    printf "     %s\n" "$SYSTEM_PLUGIN_DIR"
fi
printf "\n"
printf "Choice [1]: "
read -r CHOICE
CHOICE=${CHOICE:-1}

if [ "$CHOICE" = "2" ] && [ -n "$SYSTEM_PLUGIN_DIR" ]; then
    INSTALL_DIR="$SYSTEM_PLUGIN_DIR"
    NEED_SUDO=true
else
    INSTALL_DIR="$PERSONAL_PLUGIN_DIR"
    NEED_SUDO=false
fi

# --- Step 4: Create directory and install ---
printf "\n"
printf "${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"

if [ "$NEED_SUDO" = true ]; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
    sudo chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"
else
    mkdir -p "$INSTALL_DIR"
    cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
    chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"
fi

# --- Step 5: Verify installation ---
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
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
