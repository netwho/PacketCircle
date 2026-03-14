#!/bin/bash
# =============================================================================
# PacketCircle Installer for macOS (Universal Binary)
# =============================================================================
#
# Supports:
#   - Installing v.0.3.2 or v.0.4.3 (default: latest)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#
# The universal binary works on both Intel (x86_64) and Apple Silicon (arm64).
#
# Plugin directory:
#   Personal:  ~/.local/lib/wireshark/plugins/<version>/epan/
#   App bundle: /Applications/Wireshark.app/Contents/PlugIns/wireshark/<version>/epan/
#
# Usage:
#   chmod +x install.sh && ./install.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="packetcircle.so"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║   PacketCircle Installer for macOS               ║${NC}\n"
printf "${BLUE}║   Universal Binary (Intel + Apple Silicon)       ║${NC}\n"
printf "${BLUE}║   Available: v.0.3.2, v.0.4.3 (latest)           ║${NC}\n"
printf "${BLUE}╚══════════════════════════════════════════════════╝${NC}\n"
printf "\n"

# --- Detect Wireshark ---
WIRESHARK_APP=""
WS_VERSION=""

if [ -d "/Applications/Wireshark.app" ]; then
    WIRESHARK_APP="/Applications/Wireshark.app"
elif [ -d "$HOME/Applications/Wireshark.app" ]; then
    WIRESHARK_APP="$HOME/Applications/Wireshark.app"
fi

if [ -n "$WIRESHARK_APP" ]; then
    WS_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
        "$WIRESHARK_APP/Contents/Info.plist" 2>/dev/null || true)
fi

if [ -z "$WS_VERSION" ] && command -v tshark >/dev/null 2>&1; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

if [ -z "$WS_VERSION" ] && [ -n "$WIRESHARK_APP" ]; then
    WS_VERSION=$("$WIRESHARK_APP/Contents/MacOS/Wireshark" --version 2>/dev/null \
        | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
fi

if [ -z "$WS_VERSION" ]; then
    printf "${YELLOW}Warning: Could not detect Wireshark version.${NC}\n"
    printf "Enter Wireshark major.minor version (e.g., 4.6): "
    read -r WS_VERSION_INPUT
    WS_VERSION="${WS_VERSION_INPUT}.0"
fi

WS_MAJOR=$(printf "%s" "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(printf "%s" "$WS_VERSION" | cut -d. -f2)
printf "${GREEN}✓${NC} Wireshark version: ${CYAN}%s${NC}\n" "$WS_VERSION"

# --- Determine plugin directory ---
# Wireshark uses either "4.6" or "4-6" as the version directory name depending on
# the build. We discover the correct format rather than hardcoding it.
PLUGIN_PATH_ID=""

# Step 1: look inside Wireshark.app — most authoritative, tells us the exact name
#         the build uses (e.g. "4-6" for the official .dmg installer)
if [ -n "$WIRESHARK_APP" ]; then
    for dir in "$WIRESHARK_APP/Contents/PlugIns/wireshark"/*/; do
        b=$(basename "$dir" 2>/dev/null) || continue
        if printf "%s" "$b" | grep -qE "^${WS_MAJOR}[.-]${WS_MINOR}$"; then
            PLUGIN_PATH_ID="$b"
            printf "  Plugin path ID from app bundle: ${CYAN}%s${NC}\n" "$PLUGIN_PATH_ID"
            break
        fi
    done
fi

# Step 2: scan known personal plugin locations for an existing matching version dir
if [ -z "$PLUGIN_PATH_ID" ]; then
    for base in \
        "$HOME/.local/lib/wireshark/plugins" \
        "$HOME/Library/Application Support/Wireshark/plugins" \
        "$HOME/Library/Wireshark/plugins"; do
        [ -d "$base" ] || continue
        for dir in "$base"/*/; do
            b=$(basename "$dir" 2>/dev/null) || continue
            if printf "%s" "$b" | grep -qE "^${WS_MAJOR}[.-]${WS_MINOR}$"; then
                PLUGIN_PATH_ID="$b"
                printf "  Plugin path ID from personal dir: ${CYAN}%s${NC}\n" "$PLUGIN_PATH_ID"
                break 2
            fi
        done
    done
fi

# Step 3: infer separator convention from any existing version dir in the app bundle
#         (e.g. if "3-4" exists, then "4-6" is also dash-separated)
if [ -z "$PLUGIN_PATH_ID" ] && [ -n "$WIRESHARK_APP" ]; then
    for dir in "$WIRESHARK_APP/Contents/PlugIns/wireshark"/*/; do
        b=$(basename "$dir" 2>/dev/null) || continue
        if printf "%s" "$b" | grep -qE '^[0-9]+-[0-9]+$'; then
            PLUGIN_PATH_ID="${WS_MAJOR}-${WS_MINOR}"
            printf "  Inferred dash format from app bundle: ${CYAN}%s${NC}\n" "$PLUGIN_PATH_ID"
            break
        elif printf "%s" "$b" | grep -qE '^[0-9]+\.[0-9]+$'; then
            PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"
            printf "  Inferred dot format from app bundle: ${CYAN}%s${NC}\n" "$PLUGIN_PATH_ID"
            break
        fi
    done
fi

# Step 4: fallback — use dot format (XDG/Linux convention, also valid on macOS)
if [ -z "$PLUGIN_PATH_ID" ]; then
    PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"
    printf "  ${YELLOW}Warning: Could not detect plugin path format. Defaulting to: %s${NC}\n" "$PLUGIN_PATH_ID"
    printf "  If the plugin does not load, check Help > About Wireshark > Folders > Personal Plugins\n"
fi

PERSONAL_PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"
SYSTEM_PLUGIN_DIR=""
[ -n "$WIRESHARK_APP" ] && SYSTEM_PLUGIN_DIR="$WIRESHARK_APP/Contents/PlugIns/wireshark/$PLUGIN_PATH_ID/epan"

# --- Detect currently installed version ---
# Check all known personal plugin locations in addition to the derived path,
# in case Wireshark was previously installed with a different path convention.
INSTALLED_VERSION=""
INSTALLED_PATH=""
EXTRA_PERSONAL_DIRS=""
for base in \
    "$HOME/.local/lib/wireshark/plugins" \
    "$HOME/Library/Application Support/Wireshark/plugins" \
    "$HOME/Library/Wireshark/plugins"; do
    [ -d "$base" ] || continue
    EXTRA_PERSONAL_DIRS="$EXTRA_PERSONAL_DIRS $base/$PLUGIN_PATH_ID/epan"
done

for dir in "$PERSONAL_PLUGIN_DIR" $EXTRA_PERSONAL_DIRS "$SYSTEM_PLUGIN_DIR"; do
    [ -n "$dir" ] || continue
    [ -f "$dir/$PLUGIN_NAME" ] || continue
    INSTALLED_VERSION=$(strings "$dir/$PLUGIN_NAME" 2>/dev/null \
        | grep -oE 'PacketCircle v\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    INSTALLED_PATH="$dir/$PLUGIN_NAME"
    break
done

if [ -n "$INSTALLED_VERSION" ]; then
    printf "${GREEN}✓${NC} Currently installed: ${CYAN}v.%s${NC}\n" "$INSTALLED_VERSION"
    printf "  Location: %s\n" "$INSTALLED_PATH"
else
    printf "  No existing installation found.\n"
fi

# --- Main menu ---
printf "\n"
printf "What would you like to do?\n"
printf "\n"
printf "  ${GREEN}i${NC}) Install / upgrade / downgrade\n"
printf "  ${RED}u${NC}) Uninstall\n"
printf "  ${YELLOW}q${NC}) Quit\n"
printf "\n"
printf "Choice [i]: "
read -r ACTION
ACTION=${ACTION:-i}

case "$ACTION" in
    u|U)
        if [ -z "$INSTALLED_PATH" ]; then
            printf "\n${YELLOW}PacketCircle is not currently installed.${NC}\n\n"
            exit 0
        fi
        printf "\nRemove: ${CYAN}%s${NC}\n" "$INSTALLED_PATH"
        printf "Confirm uninstall? [y/N]: "
        read -r CONFIRM
        if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
            rm "$INSTALLED_PATH"
            printf "\n${GREEN}✓ PacketCircle v.%s uninstalled successfully.${NC}\n\n" "$INSTALLED_VERSION"
        else
            printf "Uninstall cancelled.\n"
        fi
        exit 0
        ;;
    q|Q) printf "Bye.\n"; exit 0 ;;
    i|I|"") ;;
    *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
esac

# --- Version selection (context-aware) ---
printf "\n"
printf "Select version to install:\n"
printf "\n"

if [ "$INSTALLED_VERSION" = "0.4.3" ]; then
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — already installed, reinstall\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — downgrade (legacy)\n"
elif [ "$INSTALLED_VERSION" = "0.3.2" ]; then
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — upgrade (recommended)\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — already installed, reinstall\n"
else
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — universal binary, Wireshark 4.0 API compat fixes\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — TCP stream stats, Select Results, theme-aware UI\n"
fi

printf "\n"
printf "Choice [1]: "
read -r VER_CHOICE
VER_CHOICE=${VER_CHOICE:-1}

case "$VER_CHOICE" in
    1) SELECTED_VERSION="0.4.3" ;;
    2) SELECTED_VERSION="0.3.2" ;;
    *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
esac

PLUGIN_FILE="$SCRIPT_DIR/v.${SELECTED_VERSION}/$PLUGIN_NAME"

if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: Binary not found: %s${NC}\n" "$PLUGIN_FILE"
    exit 1
fi

printf "\n${GREEN}✓${NC} Selected: PacketCircle v.%s\n" "$SELECTED_VERSION"
printf "  Binary: %s\n" "$PLUGIN_FILE"
printf "  Architecture: "
file "$PLUGIN_FILE" | grep -o "universal binary.*" || file "$PLUGIN_FILE" | grep -o "Mach-O.*"

# --- Version compatibility check ---
# v.0.4.3 is built against Wireshark 4.6.x; v.0.3.2 is also 4.6.x.
# Warn if the installed Wireshark is not 4.6.x.
if [ "$WS_MAJOR" != "4" ] || [ "$WS_MINOR" != "6" ]; then
    printf "\n${YELLOW}Warning: This installer contains binaries built against Wireshark 4.6.x.${NC}\n"
    printf "  Your version: ${YELLOW}%s${NC}  — plugin may not load.\n" "$WS_VERSION"
    printf "  Install anyway? [y/N]: "
    read -r FORCE
    if [ "$FORCE" != "y" ] && [ "$FORCE" != "Y" ]; then
        printf "Installation cancelled.\n"; exit 1
    fi
fi

# --- Choose install location ---
printf "\n"
printf "Where would you like to install?\n"
printf "\n"
printf "  ${GREEN}1${NC}) Personal directory (recommended)\n"
printf "     %s\n" "$PERSONAL_PLUGIN_DIR"
if [ -n "$SYSTEM_PLUGIN_DIR" ]; then
    printf "\n"
    printf "  ${YELLOW}2${NC}) Application bundle (requires admin)\n"
    printf "     %s\n" "$SYSTEM_PLUGIN_DIR"
fi
printf "\n"
printf "Choice [1]: "
read -r LOC_CHOICE
LOC_CHOICE=${LOC_CHOICE:-1}

if [ "$LOC_CHOICE" = "2" ] && [ -n "$SYSTEM_PLUGIN_DIR" ]; then
    INSTALL_DIR="$SYSTEM_PLUGIN_DIR"
    NEED_SUDO=true
else
    INSTALL_DIR="$PERSONAL_PLUGIN_DIR"
    NEED_SUDO=false
fi

# --- Install ---
printf "\n${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"

if [ "$NEED_SUDO" = true ]; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
    sudo chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"
else
    mkdir -p "$INSTALL_DIR"
    cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
    chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"
fi

# --- Verify ---
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Installed:  PacketCircle ${CYAN}v.%s${NC}\n" "$SELECTED_VERSION"
    printf "  Location:   ${BLUE}%s/%s${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
    printf "\n"
    printf "  Next steps:\n"
    printf "  1. Restart Wireshark (if running)\n"
    printf "  2. Open a capture or start a live capture\n"
    printf "  3. Look for PacketCircle in the Tools menu\n"
    printf "\n"
    printf "  To uninstall, run this script again and choose 'u'.\n"
    printf "\n"
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
