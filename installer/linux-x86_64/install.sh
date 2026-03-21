#!/bin/bash
# =============================================================================
# PacketCircle Installer for Linux (x86_64)
# =============================================================================
#
# Supports:
#   - Installing v.0.4.6 (latest) or v.0.3.2 (legacy)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#   - Auto-detecting Wireshark version (4.0.x, 4.2.x, 4.4.x, 4.6.x)
#
# Plugin directory:
#   ~/.local/lib/wireshark/plugins/<version>/epan/
#
# Binaries are in version subdirectories next to this script:
#   v.0.4.6/packetcircle-wsNN.so   (ws40, ws42, ws44, ws46)
#   v.0.3.2/packetcircle-wsNN.so   (ws42, ws44, ws46)
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
GRAY='\033[0;90m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║   PacketCircle Installer for Linux               ║${NC}\n"
printf "${BLUE}║   x86_64 (64-bit Intel/AMD)                      ║${NC}\n"
printf "${BLUE}║   Supports Wireshark 4.0.x, 4.2.x, 4.4.x, 4.6.x  ║${NC}\n"
printf "${BLUE}║   Available: v.0.4.6 (latest), v.0.3.2 (legacy)  ║${NC}\n"
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

# =============================================================================
# PREREQUISITES CHECK
# =============================================================================
printf "Checking prerequisites...\n\n"

# --- Verify which plugin binaries are present ---
# v.0.3.2 supports ws42/ws44/ws46; v.0.4.6 adds ws40.
# v.0.4.6 Linux binaries may not be built yet — report availability without failing.
printf "  Plugin binaries in this installer:\n"

V046_OK=1
for ws in ws40 ws42 ws44 ws46; do
    f="$SCRIPT_DIR/v.0.4.6/packetcircle-${ws}.so"
    if [ -f "$f" ]; then
        sz=$(ls -lh "$f" | awk '{print $5}')
        printf "    ${GREEN}[FOUND]${NC}   v.0.4.6/packetcircle-%s.so  (%s)\n" "$ws" "$sz"
    else
        printf "    ${GRAY}[missing]${NC} v.0.4.6/packetcircle-%s.so\n" "$ws"
        V046_OK=0
    fi
done

printf "\n"
V032_OK=1
for ws in ws42 ws44 ws46; do
    f="$SCRIPT_DIR/v.0.3.2/packetcircle-${ws}.so"
    if [ -f "$f" ]; then
        sz=$(ls -lh "$f" | awk '{print $5}')
        printf "    ${GREEN}[FOUND]${NC}   v.0.3.2/packetcircle-%s.so  (%s)\n" "$ws" "$sz"
    else
        printf "    ${RED}[MISSING]${NC} v.0.3.2/packetcircle-%s.so\n" "$ws"
        V032_OK=0
    fi
done

if [ "$V046_OK" = "0" ] && [ "$V032_OK" = "0" ]; then
    printf "\n${RED}Error: No usable plugin binaries found in this installer package.${NC}\n"
    exit 1
fi

if [ "$V046_OK" = "0" ]; then
    printf "\n  ${YELLOW}Note: v.0.4.6 Linux binaries are not yet included in this release.${NC}\n"
    printf "  ${YELLOW}      v.0.3.2 will be installed. Update when v.0.4.6 binaries are available.${NC}\n"
fi

# --- Detect Wireshark version ---
extract_dpkg_version() {
    sed 's/^[0-9]*://' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

WS_VERSION=""
printf "\n  Searching for Wireshark:\n"

if command -v tshark >/dev/null 2>&1; then
    TSHARK_PATH=$(command -v tshark)
    WS_VERSION=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "    ${GREEN}[FOUND]${NC}   tshark at %s  →  version %s\n" "$TSHARK_PATH" "$WS_VERSION"
    else
        printf "    ${YELLOW}[found]${NC}   tshark at %s  (could not parse version)\n" "$TSHARK_PATH"
    fi
else
    printf "    ${GRAY}[not found]${NC} tshark not on PATH\n"
fi

if [ -z "$WS_VERSION" ] && command -v wireshark >/dev/null 2>&1; then
    WS_PATH=$(command -v wireshark)
    WS_VERSION=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "    ${GREEN}[FOUND]${NC}   wireshark at %s  →  version %s\n" "$WS_PATH" "$WS_VERSION"
    else
        printf "    ${YELLOW}[found]${NC}   wireshark at %s  (could not parse version)\n" "$WS_PATH"
    fi
else
    [ -z "$WS_VERSION" ] && printf "    ${GRAY}[not found]${NC} wireshark not on PATH\n"
fi

if [ -z "$WS_VERSION" ] && command -v dpkg-query >/dev/null 2>&1; then
    printf "    Trying dpkg-query...\n"
    for pkg in wireshark-common wireshark wireshark-qt libwireshark-data; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            WS_VERSION=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | extract_dpkg_version)
            if [ -n "$WS_VERSION" ]; then
                printf "    ${GREEN}[FOUND]${NC}   dpkg package %-22s  →  version %s\n" "$pkg" "$WS_VERSION"
                break
            fi
        else
            printf "    ${GRAY}[not installed]${NC} dpkg: %s\n" "$pkg"
        fi
    done
fi

if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    printf "    Trying rpm...\n"
    for pkg in wireshark wireshark-qt wireshark-cli; do
        WS_VERSION=$(rpm -q "$pkg" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ -n "$WS_VERSION" ]; then
            printf "    ${GREEN}[FOUND]${NC}   rpm package %-24s  →  version %s\n" "$pkg" "$WS_VERSION"
            break
        else
            printf "    ${GRAY}[not installed]${NC} rpm: %s\n" "$pkg"
        fi
    done
fi

if [ -z "$WS_VERSION" ] && command -v pacman >/dev/null 2>&1; then
    WS_VERSION=$(pacman -Q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "    ${GREEN}[FOUND]${NC}   pacman: wireshark-qt  →  version %s\n" "$WS_VERSION"
    else
        printf "    ${GRAY}[not installed]${NC} pacman: wireshark-qt\n"
    fi
fi

if [ -z "$WS_VERSION" ]; then
    printf "    Trying libwireshark.so soname...\n"
    for lib in /usr/lib/x86_64-linux-gnu/libwireshark.so \
               /usr/lib64/libwireshark.so \
               /usr/lib/libwireshark.so; do
        if [ -L "$lib" ] || [ -f "$lib" ]; then
            SONAME=$(readlink -f "$lib" 2>/dev/null | grep -oE 'libwireshark\.so\.[0-9]+' | grep -oE '[0-9]+$')
            case "$SONAME" in
                16) WS_VERSION="4.0.0"; label="4.0.x" ;;
                17) WS_VERSION="4.2.0"; label="4.2.x" ;;
                18) WS_VERSION="4.4.0"; label="4.4.x" ;;
                19) WS_VERSION="4.6.0"; label="4.6.x" ;;
            esac
            if [ -n "$WS_VERSION" ]; then
                printf "    ${GREEN}[FOUND]${NC}   %s (soname .%s)  →  %s\n" "$lib" "$SONAME" "$label"
                break
            else
                printf "    ${GRAY}[found]${NC}   %s  (unrecognised soname .%s)\n" "$lib" "$SONAME"
            fi
        else
            printf "    ${GRAY}[not found]${NC} %s\n" "$lib"
        fi
    done
fi

if [ -z "$WS_VERSION" ]; then
    printf "\n  ${YELLOW}[WARN] Could not detect Wireshark version automatically.${NC}\n"
    printf "  Enter Wireshark major.minor version (e.g., 4.0, 4.2, 4.6): "
    read -r WS_VERSION_INPUT
    WS_VERSION="${WS_VERSION_INPUT}.0"
fi

WS_MAJOR=$(printf "%s" "$WS_VERSION" | cut -d. -f1)
WS_MINOR=$(printf "%s" "$WS_VERSION" | cut -d. -f2)

# --- Select binary tag for Wireshark version ---
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

# --- Determine plugin directory ---
printf "\n  Searching for plugin directory:\n"
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
                printf "    ${GREEN}[MATCH]${NC}   %s\n" "$dir"
                PLUGIN_PATH_ID="$DIRNAME"
                break
            else
                printf "    ${GRAY}[skip]${NC}    %s\n" "$dir"
            fi
        fi
    fi
done
if [ -z "$PLUGIN_PATH_ID" ]; then
    PLUGIN_PATH_ID="${WS_MAJOR}.${WS_MINOR}"
    printf "    ${YELLOW}No existing plugin dir found; will create: %s${NC}\n" "$PLUGIN_PATH_ID"
    printf "    ${YELLOW}If the plugin does not load: Help > About Wireshark > Folders > Personal Plugins${NC}\n"
fi

INSTALL_DIR="$HOME/.local/lib/wireshark/plugins/$PLUGIN_PATH_ID/epan"

# --- Detect currently installed version ---
printf "\n  Checking for existing PacketCircle installation:\n"
INSTALLED_VERSION=""
INSTALLED_PATH=""
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    INSTALLED_VERSION=$(strings "$INSTALL_DIR/$PLUGIN_NAME" 2>/dev/null \
        | grep -oE 'PacketCircle v\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    INSTALLED_PATH="$INSTALL_DIR/$PLUGIN_NAME"
    if [ -n "$INSTALLED_VERSION" ]; then
        printf "    ${GREEN}[FOUND]${NC}   %s\n" "$INSTALLED_PATH"
        printf "    Embedded version string: ${CYAN}v.%s${NC}\n" "$INSTALLED_VERSION"
    else
        printf "    ${YELLOW}[found]${NC}   %s  (no version string in binary)\n" "$INSTALLED_PATH"
    fi
else
    printf "    ${GRAY}[none]${NC}    %s  (not installed)\n" "$INSTALL_DIR/$PLUGIN_NAME"
fi

# --- Prerequisites summary ---
printf "\n-----------------------------------------------------------\n"
printf "  Prerequisites Summary\n"
printf "-----------------------------------------------------------\n"
printf "  Wireshark       : %s.%s  (plugin API dir: %s)\n" "$WS_MAJOR" "$WS_MINOR" "$PLUGIN_PATH_ID"
printf "  Binary tag      : %s  — %s\n" "$SELECTED_WS_TAG" "$SELECTED_WS_LABEL"
printf "  v.0.4.6 binaries: "
if [ "$V046_OK" = "1" ]; then printf "${GREEN}all present${NC}\n"; else printf "${YELLOW}not yet built for Linux${NC}\n"; fi
printf "  v.0.3.2 binaries: "
if [ "$V032_OK" = "1" ]; then printf "${GREEN}all present${NC}\n"; else printf "${RED}missing${NC}\n"; fi
printf "  Install dir     : %s\n" "$INSTALL_DIR"
printf "  Installed now   : "
if [ -n "$INSTALLED_VERSION" ]; then
    printf "${CYAN}v.%s${NC}\n" "$INSTALLED_VERSION"
else
    printf "${GRAY}none${NC}\n"
fi
printf "-----------------------------------------------------------\n"

# --- Qt6 runtime check ---
QT6_OK=0
for libdir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
    if [ -f "$libdir/libQt6Widgets.so.6" ] || [ -f "$libdir/libQt6Core.so.6" ]; then
        QT6_OK=1; break
    fi
done
if [ "$QT6_OK" = "1" ]; then
    printf "  Qt6 runtime     : ${GREEN}found${NC}\n"
else
    printf "  Qt6 runtime     : ${YELLOW}not found${NC}  (PacketCircle requires Qt6)\n"
fi
printf "-----------------------------------------------------------\n"

# --- Main menu ---
printf "\n"
printf "What would you like to do?\n\n"
printf "  ${GREEN}i${NC}) Install / upgrade / downgrade\n"
printf "  ${RED}u${NC}) Uninstall\n"
printf "  ${YELLOW}q${NC}) Quit\n\n"
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
printf "\nSelect version to install:\n\n"

# ws40 only exists in v.0.4.6
if [ "$SELECTED_WS_TAG" = "ws40" ]; then
    if [ "$V046_OK" = "1" ]; then
        printf "  ${GREEN}1${NC}) v.0.4.6 (latest)  — the only version with Wireshark 4.0.x support\n"
        printf "\nChoice [1]: "
        read -r VER_CHOICE
        VER_CHOICE=${VER_CHOICE:-1}
        case "$VER_CHOICE" in
            1) SELECTED_VERSION="0.4.6" ;;
            *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
        esac
    else
        printf "  ${RED}v.0.4.6 is not yet available for Linux and is required for Wireshark 4.0.x.${NC}\n"
        printf "  ${YELLOW}Please check back once v.0.4.6 Linux binaries are released.${NC}\n\n"
        exit 1
    fi
else
    # v.0.4.6 is strongly recommended; v.0.3.2 is legacy
    printf "  ${GREEN}★ RECOMMENDED: use v.0.4.6 unless you have a specific reason to stay on v.0.3.2${NC}\n\n"

    if [ "$V046_OK" = "1" ]; then
        if [ "$INSTALLED_VERSION" = "0.4.6" ]; then
            printf "  ${GREEN}1${NC}) v.0.4.6 (latest)   — already installed, reinstall\n"
        elif [ "$INSTALLED_VERSION" = "0.3.2" ]; then
            printf "  ${GREEN}1${NC}) v.0.4.6 (latest)   — upgrade (recommended)\n"
        else
            printf "  ${GREEN}1${NC}) v.0.4.6 (latest)   — protocol info dialogs, ntopng & Malcolm/Arkime integrations, settings menu\n"
        fi
    else
        printf "  ${YELLOW}1${NC}) v.0.4.6             — ${YELLOW}not yet available for Linux (binaries pending build)${NC}\n"
    fi

    if [ "$INSTALLED_VERSION" = "0.3.2" ]; then
        printf "  ${YELLOW}2${NC}) v.0.3.2 (legacy)    — already installed, reinstall\n"
    elif [ "$INSTALLED_VERSION" = "0.4.6" ]; then
        printf "  ${YELLOW}2${NC}) v.0.3.2 (legacy)    — downgrade; only if you have a specific compatibility reason\n"
    else
        printf "  ${YELLOW}2${NC}) v.0.3.2 (legacy)    — TCP stream stats, Select Results, theme-aware UI\n"
        printf "                       (only choose this if you need v.0.3.2 specifically)\n"
    fi

    printf "\nChoice [1]: "
    read -r VER_CHOICE
    VER_CHOICE=${VER_CHOICE:-1}

    case "$VER_CHOICE" in
        1)
            if [ "$V046_OK" = "0" ]; then
                printf "\n${RED}v.0.4.6 Linux binaries are not yet available in this installer.${NC}\n"
                printf "${YELLOW}Please download the latest installer once v.0.4.6 binaries are released,${NC}\n"
                printf "${YELLOW}or install v.0.3.2 in the meantime.${NC}\n\n"
                exit 1
            fi
            SELECTED_VERSION="0.4.6"
            ;;
        2)
            if [ "$V032_OK" = "0" ]; then
                printf "\n${RED}v.0.3.2 binaries are missing.${NC}\n"; exit 1
            fi
            SELECTED_VERSION="0.3.2"
            if [ "$VER_CHOICE" = "2" ] && [ "$INSTALLED_VERSION" != "0.3.2" ]; then
                printf "\n  ${YELLOW}You chose v.0.3.2. This is a legacy release.${NC}\n"
                printf "  ${YELLOW}Use v.0.4.6 unless you specifically need v.0.3.2 compatibility.${NC}\n"
                printf "  Continue with v.0.3.2? [y/N]: "
                read -r CONFIRM_LEGACY
                if [ "$CONFIRM_LEGACY" != "y" ] && [ "$CONFIRM_LEGACY" != "Y" ]; then
                    printf "Installation cancelled.\n"; exit 0
                fi
            fi
            ;;
        *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
    esac
fi

PLUGIN_FILE="$SCRIPT_DIR/v.${SELECTED_VERSION}/packetcircle-${SELECTED_WS_TAG}.so"

if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: Binary not found: %s${NC}\n" "$PLUGIN_FILE"
    exit 1
fi

FILESIZE=$(ls -lh "$PLUGIN_FILE" | awk '{print $5}')
printf "\n${GREEN}✓${NC} Selected: PacketCircle v.%s  |  %s  |  %s\n" \
    "$SELECTED_VERSION" "$SELECTED_WS_LABEL" "$FILESIZE"

# --- Qt6 warning (if not found, remind before install) ---
if [ "$QT6_OK" = "0" ]; then
    printf "\n${YELLOW}⚠ Qt6 runtime libraries not found.${NC}\n"
    printf "  PacketCircle requires Qt6 (libQt6Widgets, libQt6Gui, libQt6Core).\n"
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
        printf "  Install Qt6 runtime manually for your distro:\n"
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
    INSTALLED_SIZE=$(ls -lh "$INSTALL_DIR/$PLUGIN_NAME" | awk '{print $5}')
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Installed:  PacketCircle ${CYAN}v.%s${NC} (%s)\n" "$SELECTED_VERSION" "$SELECTED_WS_LABEL"
    printf "  Size:       %s\n" "$INSTALLED_SIZE"
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
