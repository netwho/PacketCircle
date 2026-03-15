#!/bin/bash
# =============================================================================
# PacketCircle Installer for Linux (x86_64)
# =============================================================================
#
# Supports:
#   - Installing v.0.3.2 or v.0.4.3 (default: latest)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#   - Auto-detecting Wireshark version (4.0.x, 4.2.x, 4.4.x, 4.6.x)
#
# Plugin directory:
#   ~/.local/lib/wireshark/plugins/<version>/epan/
#
# Usage:
#   chmod +x install.sh && ./install.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
PLUGIN_NAME="packetcircle.so"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║   PacketCircle Installer for Linux               ║${NC}\n"
printf "${BLUE}║   x86_64 (64-bit Intel/AMD)                      ║${NC}\n"
printf "${BLUE}║   Supports Wireshark 4.0.x, 4.2.x, 4.4.x, 4.6.x  ║${NC}\n"
printf "${BLUE}║   Available: v.0.3.2, v.0.4.3 (latest)           ║${NC}\n"
printf "${BLUE}╚══════════════════════════════════════════════════╝${NC}\n"
printf "\n"

# --- Architecture check ---
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    printf "${YELLOW}Warning: These binaries are built for x86_64 but you are running %s.${NC}\n" "$ARCH"
    printf "Continue anyway? [y/N]: "
    read -r CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then exit 1; fi
fi

# --- Verify binaries exist ---
# v.0.3.2 has ws42/ws44/ws46 only; v.0.4.3 adds ws40
for ws in ws42 ws44 ws46; do
    if [ ! -f "$BIN_DIR/v.0.3.2/packetcircle-${ws}.so" ]; then
        printf "${RED}Error: Missing binary: bin/v.0.3.2/packetcircle-%s.so${NC}\n" "$ws"
        exit 1
    fi
done
for ws in ws40 ws42 ws44 ws46; do
    if [ ! -f "$BIN_DIR/v.0.4.3/packetcircle-${ws}.so" ]; then
        printf "${RED}Error: Missing binary: bin/v.0.4.3/packetcircle-%s.so${NC}\n" "$ws"
        exit 1
    fi
done
printf "${GREEN}✓${NC} All plugin binaries present.\n"

# --- Detect Wireshark version ---
extract_dpkg_version() {
    sed 's/^[0-9]*://' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

WS_VERSION=""
printf "\n${CYAN}Detecting Wireshark version...${NC}\n"

if [ -z "$WS_VERSION" ] && command -v tshark >/dev/null 2>&1; then
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$WS_VERSION" ] && printf "  Detected via tshark: %s\n" "$WS_VERSION"
fi

if [ -z "$WS_VERSION" ] && command -v wireshark >/dev/null 2>&1; then
    WS_VERSION=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$WS_VERSION" ] && printf "  Detected via wireshark: %s\n" "$WS_VERSION"
fi

if [ -z "$WS_VERSION" ] && command -v dpkg-query >/dev/null 2>&1; then
    for pkg in wireshark-common wireshark wireshark-qt libwireshark-data; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            WS_VERSION=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | extract_dpkg_version)
            [ -n "$WS_VERSION" ] && printf "  Detected via dpkg (%s): %s\n" "$pkg" "$WS_VERSION" && break
        fi
    done
fi

if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    for pkg in wireshark wireshark-qt wireshark-cli; do
        WS_VERSION=$(rpm -q "$pkg" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ -n "$WS_VERSION" ] && printf "  Detected via rpm (%s): %s\n" "$pkg" "$WS_VERSION" && break
    done
fi

if [ -z "$WS_VERSION" ] && command -v pacman >/dev/null 2>&1; then
    WS_VERSION=$(pacman -Q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$WS_VERSION" ] && printf "  Detected via pacman: %s\n" "$WS_VERSION"
fi

if [ -z "$WS_VERSION" ]; then
    for lib in /usr/lib/x86_64-linux-gnu/libwireshark.so /usr/lib64/libwireshark.so /usr/lib/libwireshark.so; do
        if [ -L "$lib" ] || [ -f "$lib" ]; then
            SONAME=$(readlink -f "$lib" 2>/dev/null | grep -oE 'libwireshark\.so\.[0-9]+' | grep -oE '[0-9]+$')
            case "$SONAME" in
                16) WS_VERSION="4.0.0"; printf "  Detected from libwireshark.so.16: 4.0.x\n" ;;
                17) WS_VERSION="4.2.0"; printf "  Detected from libwireshark.so.17: 4.2.x\n" ;;
                18) WS_VERSION="4.4.0"; printf "  Detected from libwireshark.so.18: 4.4.x\n" ;;
                19) WS_VERSION="4.6.0"; printf "  Detected from libwireshark.so.19: 4.6.x\n" ;;
            esac
            [ -n "$WS_VERSION" ] && break
        fi
    done
fi

if [ -z "$WS_VERSION" ]; then
    printf "\n${YELLOW}Could not automatically detect Wireshark version.${NC}\n"
    printf "Enter Wireshark major.minor version (e.g., 4.0, 4.2, 4.6): "
    read -r WS_VERSION_INPUT
    WS_VERSION="${WS_VERSION_INPUT}.0"
fi

WS_MAJOR=$(printf "%s" "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(printf "%s" "$WS_VERSION" | cut -d. -f2)
printf "${GREEN}✓${NC} Wireshark version: ${CYAN}%s${NC} (ABI: %s.%s)\n" "$WS_VERSION" "$WS_MAJOR" "$WS_MINOR"

# --- Select binary for Wireshark version ---
case "$WS_MINOR" in
    0) SELECTED_WS_TAG="ws40"; SELECTED_WS_LABEL="Wireshark 4.0.x (built against 4.0.17)" ;;
    2) SELECTED_WS_TAG="ws42"; SELECTED_WS_LABEL="Wireshark 4.2.x (built against 4.2.14)" ;;
    4) SELECTED_WS_TAG="ws44"; SELECTED_WS_LABEL="Wireshark 4.4.x (built against 4.4.7)"  ;;
    6) SELECTED_WS_TAG="ws46"; SELECTED_WS_LABEL="Wireshark 4.6.x (built against 4.6.3)"  ;;
    *)
        printf "\n${RED}Unsupported Wireshark version: %s.%s${NC}\n" "$WS_MAJOR" "$WS_MINOR"
        printf "Supported: 4.0.x, 4.2.x, 4.4.x, 4.6.x\n\n"
        printf "Force-install a binary anyway?\n"
        printf "  1) 4.0.x binary\n  2) 4.2.x binary\n  3) 4.4.x binary\n  4) 4.6.x binary\n  q) Quit\n"
        printf "Choice [q]: "
        read -r MANUAL_CHOICE
        case "$MANUAL_CHOICE" in
            1) SELECTED_WS_TAG="ws40"; SELECTED_WS_LABEL="Wireshark 4.0.x (FORCED)"; WS_MINOR=0 ;;
            2) SELECTED_WS_TAG="ws42"; SELECTED_WS_LABEL="Wireshark 4.2.x (FORCED)"; WS_MINOR=2 ;;
            3) SELECTED_WS_TAG="ws44"; SELECTED_WS_LABEL="Wireshark 4.4.x (FORCED)"; WS_MINOR=4 ;;
            4) SELECTED_WS_TAG="ws46"; SELECTED_WS_LABEL="Wireshark 4.6.x (FORCED)"; WS_MINOR=6 ;;
            *) printf "Installation cancelled.\n"; exit 1 ;;
        esac
        printf "${YELLOW}Warning: Installing binary for a non-matching version.${NC}\n"
        ;;
esac

# Note for Wireshark 4.0.x users: only v.0.4.3 is available (first release with 4.0 support)
if [ "$SELECTED_WS_TAG" = "ws40" ]; then
    printf "${YELLOW}Note: Only PacketCircle v.0.4.3 is available for Wireshark 4.0.x.${NC}\n"
fi

# --- Determine plugin directory ---
PLUGIN_PATH_ID=""
for dir in /usr/lib/x86_64-linux-gnu/wireshark/plugins/* \
           /usr/lib64/wireshark/plugins/* \
           /usr/lib/wireshark/plugins/* \
           "$HOME/.local/lib/wireshark/plugins"/*; do
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
[ -z "$PLUGIN_PATH_ID" ] && PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"

INSTALL_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"

# --- Detect currently installed version ---
INSTALLED_VERSION=""
INSTALLED_PATH=""
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    INSTALLED_VERSION=$(strings "$INSTALL_DIR/$PLUGIN_NAME" 2>/dev/null \
        | grep -oE 'PacketCircle v\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    INSTALLED_PATH="$INSTALL_DIR/$PLUGIN_NAME"
fi

printf "${GREEN}✓${NC} Plugin API version: %s\n" "$PLUGIN_PATH_ID"
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

# --- Version selection ---
# Note: ws40 support was added in v.0.4.3; v.0.3.2 only supports 4.2+
printf "\n"
printf "Select version to install:\n"
printf "\n"
if [ "$SELECTED_WS_TAG" = "ws40" ]; then
    printf "  ${GREEN}1${NC}) v.0.4.3             — only version available for Wireshark 4.0.x\n"
elif [ "$INSTALLED_VERSION" = "0.4.3" ]; then
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — already installed, reinstall\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — downgrade (legacy)\n"
elif [ "$INSTALLED_VERSION" = "0.3.2" ]; then
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — upgrade (recommended)\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — already installed, reinstall\n"
else
    printf "  ${GREEN}1${NC}) v.0.4.3 (latest)   — Wireshark 4.0 support, API compat fixes\n"
    printf "  ${YELLOW}2${NC}) v.0.3.2             — TCP stream stats, Select Results, theme-aware UI\n"
fi
printf "\n"
printf "Choice [1]: "
read -r VER_CHOICE
VER_CHOICE=${VER_CHOICE:-1}
if [ "$SELECTED_WS_TAG" = "ws40" ]; then
    case "$VER_CHOICE" in
        1) SELECTED_VERSION="0.4.3" ;;
        *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
    esac
else
    case "$VER_CHOICE" in
        1) SELECTED_VERSION="0.4.3" ;;
        2) SELECTED_VERSION="0.3.2" ;;
        *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
    esac
fi

PLUGIN_FILE="$BIN_DIR/v.${SELECTED_VERSION}/packetcircle-${SELECTED_WS_TAG}.so"

if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: Binary not found: %s${NC}\n" "$PLUGIN_FILE"
    exit 1
fi

printf "\n${GREEN}✓${NC} Selected: PacketCircle v.%s for %s\n" "$SELECTED_VERSION" "$SELECTED_WS_LABEL"

# --- Qt6 runtime check ---
# PacketCircle is built against Qt6. Wireshark 4.0.x and 4.2.x ship Qt5 on most
# distros, so Qt6 runtime libraries may not be present. Check and offer to install.
QT6_OK=0
for libdir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
    if [ -f "$libdir/libQt6Widgets.so.6" ] || [ -f "$libdir/libQt6Core.so.6" ]; then
        QT6_OK=1
        break
    fi
done

if [ "$QT6_OK" = "0" ]; then
    printf "\n${YELLOW}⚠ Qt6 runtime libraries not found.${NC}\n"
    printf "  PacketCircle requires Qt6 (libQt6Widgets, libQt6Gui, libQt6Core).\n"
    printf "  Wireshark %s.%s ships with Qt5; Qt6 must be installed separately.\n" "$WS_MAJOR" "$WS_MINOR"
    printf "\n"
    if command -v apt-get >/dev/null 2>&1; then
        printf "  Install Qt6 runtime now? (requires sudo)\n"
        printf "  Command: sudo apt-get install -y libqt6widgets6\n"
        printf "  Proceed? [Y/n]: "
        read -r QT6_INSTALL
        QT6_INSTALL=${QT6_INSTALL:-Y}
        if [ "$QT6_INSTALL" = "y" ] || [ "$QT6_INSTALL" = "Y" ]; then
            sudo apt-get install -y libqt6widgets6
            printf "${GREEN}✓${NC} Qt6 runtime installed.\n"
        else
            printf "${YELLOW}Skipped. The plugin may fail to load without Qt6 runtime.${NC}\n"
        fi
    else
        printf "  ${YELLOW}apt not available. Install Qt6 runtime manually for your distro:${NC}\n"
        printf "    Fedora/RHEL: sudo dnf install qt6-qtbase\n"
        printf "    Arch:        sudo pacman -S qt6-base\n"
        printf "    openSUSE:    sudo zypper install libQt6Widgets6\n"
    fi
fi

# --- Install ---
printf "\n${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"

# --- Verify ---
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    FILESIZE=$(ls -lh "$INSTALL_DIR/$PLUGIN_NAME" | awk '{print $5}')
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Installed:  PacketCircle ${CYAN}v.%s${NC} (%s)\n" "$SELECTED_VERSION" "$SELECTED_WS_LABEL"
    printf "  Size:       %s\n" "$FILESIZE"
    printf "  Location:   ${BLUE}%s/%s${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
    printf "\n"
    printf "  Next steps:\n"
    printf "  1. Restart Wireshark (if running)\n"
    printf "  2. Open a capture or start a live capture\n"
    printf "  3. Look for PacketCircle in the Tools menu\n"
    printf "\n"
    printf "  To uninstall, run this script again and choose 'u'.\n"
    printf "\n"
    printf "  ${YELLOW}Troubleshooting:${NC}\n"
    printf "  - Verify path: Help > About Wireshark > Folders > Personal Plugins\n"
    printf "  - Check loading: wireshark -o log.level:debug 2>&1 | grep packetcircle\n"
    printf "\n"
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
