#!/bin/bash
# =============================================================================
# PacketCircle Installer for Linux (x86_64)
# =============================================================================
#
# Supports:
#   - Installing v.0.5.3 (latest) or v.0.4.7 (stable legacy)
#   - Two flavors: Standard (default) or Experimental (enables Graph View)
#   - Detecting an already-installed version
#   - Upgrading, downgrading, and uninstalling
#   - Auto-detecting Wireshark version (4.0.x, 4.2.x, 4.4.x, 4.6.x)
#
# Plugin directory:
#   ~/.local/lib/wireshark/plugins/<version>/epan/
#
# Binaries are in version subdirectories next to this script:
#   v.0.5.3/packetcircle-wsNN.so   (ws40, ws42, ws44, ws46)
#   v.0.4.7/packetcircle-wsNN.so   (ws40, ws42, ws44, ws46)
#
# Usage:
#   chmod +x install.sh && ./install.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_NAME="packetcircle.so"
LATEST_VERSION="0.5.3"
LEGACY_VERSION="0.4.7"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
GRAY='\033[0;90m'
NC='\033[0m'

printf "\n"
printf "${BLUE}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BLUE}║   PacketCircle Installer for Linux               ║${NC}\n"
printf "${BLUE}║   x86_64 (64-bit Intel/AMD)                      ║${NC}\n"
printf "${BLUE}║   Supports Wireshark 4.0.x, 4.2.x, 4.4.x, 4.6.x  ║${NC}\n"
printf "${BLUE}║   Available: v.0.5.3 (latest), v.0.4.7            ║${NC}\n"
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
printf "  Plugin binaries in this installer:\n"

VLATEST_OK=1
for ws in ws40 ws42 ws44 ws46; do
    f="$SCRIPT_DIR/v.${LATEST_VERSION}/packetcircle-${ws}.so"
    if [ -f "$f" ]; then
        sz=$(ls -lh "$f" | awk '{print $5}')
        printf "    ${GREEN}[FOUND]${NC}   v.%s/packetcircle-%s.so  (%s)\n" "$LATEST_VERSION" "$ws" "$sz"
    else
        printf "    ${GRAY}[missing]${NC} v.%s/packetcircle-%s.so\n" "$LATEST_VERSION" "$ws"
        VLATEST_OK=0
    fi
done

printf "\n"
V047_OK=1
for ws in ws40 ws42 ws44 ws46; do
    f="$SCRIPT_DIR/v.0.4.7/packetcircle-${ws}.so"
    if [ -f "$f" ]; then
        sz=$(ls -lh "$f" | awk '{print $5}')
        printf "    ${GREEN}[FOUND]${NC}   v.0.4.7/packetcircle-%s.so  (%s)\n" "$ws" "$sz"
    else
        printf "    ${GRAY}[missing]${NC} v.0.4.7/packetcircle-%s.so\n" "$ws"
        V047_OK=0
    fi
done

if [ "$VLATEST_OK" = "0" ] && [ "$V047_OK" = "0" ]; then
    printf "\n${YELLOW}Warning: No installer binaries found — uninstall still available.${NC}\n"
    INSTALL_ONLY_WARN=1
else
    INSTALL_ONLY_WARN=0
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
    fi
fi

if [ -z "$WS_VERSION" ] && command -v dpkg-query >/dev/null 2>&1; then
    for pkg in wireshark-common wireshark wireshark-qt libwireshark-data; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            WS_VERSION=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | extract_dpkg_version)
            if [ -n "$WS_VERSION" ]; then
                printf "    ${GREEN}[FOUND]${NC}   dpkg package %-22s  →  version %s\n" "$pkg" "$WS_VERSION"
                break
            fi
        fi
    done
fi

if [ -z "$WS_VERSION" ] && command -v rpm >/dev/null 2>&1; then
    for pkg in wireshark wireshark-qt wireshark-cli; do
        WS_VERSION=$(rpm -q "$pkg" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ -n "$WS_VERSION" ]; then
            printf "    ${GREEN}[FOUND]${NC}   rpm package %-24s  →  version %s\n" "$pkg" "$WS_VERSION"
            break
        fi
    done
fi

if [ -z "$WS_VERSION" ] && command -v pacman >/dev/null 2>&1; then
    WS_VERSION=$(pacman -Q wireshark-qt 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$WS_VERSION" ]; then
        printf "    ${GREEN}[FOUND]${NC}   pacman: wireshark-qt  →  version %s\n" "$WS_VERSION"
    fi
fi

if [ -z "$WS_VERSION" ]; then
    for lib in /usr/lib/x86_64-linux-gnu/libwireshark.so \
               /usr/lib64/libwireshark.so \
               /usr/lib/libwireshark.so; do
        if [ -L "$lib" ] || [ -f "$lib" ]; then
            SONAME=$(readlink -f "$lib" 2>/dev/null | grep -oE 'libwireshark\.so\.[0-9]+' | grep -oE '[0-9]+$')
            case "$SONAME" in
                16) WS_VERSION="4.0.0" ;;
                17) WS_VERSION="4.2.0" ;;
                18) WS_VERSION="4.4.0" ;;
                19) WS_VERSION="4.6.0" ;;
            esac
            if [ -n "$WS_VERSION" ]; then
                printf "    ${GREEN}[FOUND]${NC}   %s (soname .%s)  →  %s\n" "$lib" "$SONAME" "$WS_VERSION"
                break
            fi
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
    4) SELECTED_WS_TAG="ws44"; SELECTED_WS_LABEL="Wireshark 4.4.x (built against 4.4.14)"  ;;
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
        printf "    ${GREEN}[FOUND]${NC}   v.%s at %s\n" "$INSTALLED_VERSION" "$INSTALLED_PATH"
    else
        printf "    ${YELLOW}[found]${NC}   %s  (no version string in binary)\n" "$INSTALLED_PATH"
    fi
else
    printf "    ${GRAY}[none]${NC}    %s  (not installed)\n" "$INSTALL_DIR/$PLUGIN_NAME"
fi

# --- Qt6 runtime check ---
QT6_OK=0
for libdir in /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
    if [ -f "$libdir/libQt6Widgets.so.6" ] || [ -f "$libdir/libQt6Core.so.6" ]; then
        QT6_OK=1; break
    fi
done

# --- Prerequisites summary ---
SEP="-----------------------------------------------------------"
printf "\n%s\n" "$SEP"
printf "  Prerequisites Summary\n"
printf "%s\n" "$SEP"
printf "  Wireshark       : %s.%s  (plugin API dir: %s)\n" "$WS_MAJOR" "$WS_MINOR" "$PLUGIN_PATH_ID"
printf "  Binary tag      : %s  (%s)\n" "$SELECTED_WS_TAG" "$SELECTED_WS_LABEL"
printf "  v.%s binaries: " "$LATEST_VERSION"
if [ "$VLATEST_OK" = "1" ]; then printf "${GREEN}all present${NC}\n"; else printf "${YELLOW}some missing${NC}\n"; fi
printf "  v.%s binaries: " "$LEGACY_VERSION"
if [ "$V047_OK" = "1" ]; then printf "${GREEN}all present${NC}\n"; else printf "${YELLOW}some missing${NC}\n"; fi
printf "  Install dir     : %s\n" "$INSTALL_DIR"
printf "  Installed now   : "
if [ -n "$INSTALLED_VERSION" ]; then
    printf "${CYAN}v.%s${NC}\n" "$INSTALLED_VERSION"
else
    printf "${GRAY}none${NC}\n"
fi
printf "  Qt6 runtime     : "
if [ "$QT6_OK" = "1" ]; then printf "${GREEN}found${NC}\n"; else printf "${YELLOW}not found${NC}  (PacketCircle requires Qt6)\n"; fi
printf "%s\n" "$SEP"
printf "\n  Press Enter to continue..."
read -r _

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
            printf "\n${YELLOW}PacketCircle is not currently installed at:%s${NC}\n" "$INSTALL_DIR"
            printf "If you installed manually, remove the file:\n"
            printf "  find ~/.local/lib/wireshark -name 'packetcircle.so' 2>/dev/null\n\n"
            exit 0
        fi
        printf "\nRemove: ${CYAN}%s${NC}\n" "$INSTALLED_PATH"
        printf "Confirm uninstall? [y/N]: "
        read -r CONFIRM
        if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
            rm -f "$INSTALLED_PATH"
            printf "\n${GREEN}✓ PacketCircle%s uninstalled successfully.${NC}\n\n" \
                "${INSTALLED_VERSION:+ v.$INSTALLED_VERSION}"
        else
            printf "Uninstall cancelled.\n"
        fi
        exit 0
        ;;
    q|Q) printf "Bye.\n"; exit 0 ;;
    i|I|"")
        if [ "$INSTALL_ONLY_WARN" = "1" ]; then
            printf "\n${RED}Error: No installer binaries found — cannot install.${NC}\n"
            printf "Download the full installer package from GitHub.\n\n"
            exit 1
        fi
        ;;
    *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
esac

# --- Version selection ---
printf "\nSelect version to install:\n\n"

# ws40 only exists in v.0.4.7+; handle gracefully
if [ "$SELECTED_WS_TAG" = "ws40" ] && [ "$V052_OK" = "0" ] && [ "$V047_OK" = "0" ]; then
    printf "  ${RED}No binaries available for Wireshark 4.0.x in this installer.${NC}\n\n"
    exit 1
fi

if [ "$INSTALLED_VERSION" = "$LATEST_VERSION" ]; then
    printf "  ${GREEN}1${NC}) v.%s ${BOLD}(latest)${NC}   — already installed, reinstall\n" "$LATEST_VERSION"
    printf "  ${YELLOW}2${NC}) v.%s             — downgrade to stable legacy\n" "$LEGACY_VERSION"
elif [ "$INSTALLED_VERSION" = "$LEGACY_VERSION" ]; then
    printf "  ${GREEN}1${NC}) v.%s ${BOLD}(latest)${NC}   — upgrade (recommended)\n" "$LATEST_VERSION"
    printf "  ${YELLOW}2${NC}) v.%s             — already installed, reinstall\n" "$LEGACY_VERSION"
else
    printf "  ${GREEN}1${NC}) v.%s ${BOLD}(latest)${NC}   — 3-page PDF reports, graph view (opt-in), TCP Window analysis\n" "$LATEST_VERSION"
    printf "  ${YELLOW}2${NC}) v.%s             — stable legacy: table view, protocol info dialogs, Wi-Fi mode\n" "$LEGACY_VERSION"
fi

printf "\nChoice [1]: "
read -r VER_CHOICE
VER_CHOICE=${VER_CHOICE:-1}

case "$VER_CHOICE" in
    1)
        if [ "$VLATEST_OK" = "0" ] || [ ! -f "$SCRIPT_DIR/v.${LATEST_VERSION}/packetcircle-${SELECTED_WS_TAG}.so" ]; then
            printf "\n${RED}v.%s binary for %s is not available in this installer.${NC}\n" "$LATEST_VERSION" "$SELECTED_WS_TAG"
            exit 1
        fi
        SELECTED_VERSION="$LATEST_VERSION"
        ;;
    2)
        if [ "$V047_OK" = "0" ] || [ ! -f "$SCRIPT_DIR/v.0.4.7/packetcircle-${SELECTED_WS_TAG}.so" ]; then
            printf "\n${RED}v.0.4.7 binary for %s is not available in this installer.${NC}\n" "$SELECTED_WS_TAG"
            exit 1
        fi
        SELECTED_VERSION="$LEGACY_VERSION"
        if [ "$INSTALLED_VERSION" != "$LEGACY_VERSION" ]; then
            printf "\n  ${YELLOW}You chose v.0.4.7. This is the legacy release.${NC}\n"
            printf "  Continue with v.0.4.7? [y/N]: "
            read -r CONFIRM_LEGACY
            if [ "$CONFIRM_LEGACY" != "y" ] && [ "$CONFIRM_LEGACY" != "Y" ]; then
                printf "Installation cancelled.\n"; exit 0
            fi
        fi
        ;;
    *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
esac

PLUGIN_FILE="$SCRIPT_DIR/v.${SELECTED_VERSION}/packetcircle-${SELECTED_WS_TAG}.so"

if [ ! -f "$PLUGIN_FILE" ]; then
    printf "${RED}Error: Binary not found: %s${NC}\n" "$PLUGIN_FILE"
    exit 1
fi

FILESIZE=$(ls -lh "$PLUGIN_FILE" | awk '{print $5}')
printf "\n${GREEN}✓${NC} Selected: PacketCircle v.%s  |  %s  |  %s\n" \
    "$SELECTED_VERSION" "$SELECTED_WS_LABEL" "$FILESIZE"

# --- Feature set selection (latest version only) ---
ENABLE_EXPERIMENTAL=false
if [ "$SELECTED_VERSION" = "$LATEST_VERSION" ]; then
    printf "\n"
    printf "Feature set:\n"
    printf "\n"
    printf "  ${GREEN}1${NC}) ${BOLD}Standard${NC} (recommended)\n"
    printf "     Circle view, Table view, Wi-Fi mode, 20+ protocol info dialogs,\n"
    printf "     PDF reports, ntopng/Malcolm integration — stable, fully tested\n"
    printf "\n"
    printf "  ${CYAN}2${NC}) ${BOLD}Experimental${NC} — enables Graph View (beta)\n"
    printf "     Everything in Standard, plus an interactive node-link topology\n"
    printf "     diagram with 8 layouts, TCP Health / Anomaly Score / High Risk\n"
    printf "     edge colors, and score breakdowns. Beta quality — may have rough edges.\n"
    printf "\n"
    printf "Choice [1]: "
    read -r FEAT_CHOICE
    FEAT_CHOICE=${FEAT_CHOICE:-1}
    case "$FEAT_CHOICE" in
        2) ENABLE_EXPERIMENTAL=true ;;
        1|"") ENABLE_EXPERIMENTAL=false ;;
        *) printf "Invalid choice. Exiting.\n"; exit 1 ;;
    esac
fi

# --- Qt6 warning ---
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

# --- Install binary ---
printf "\n${BLUE}Installing to: %s${NC}\n" "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp "$PLUGIN_FILE" "$INSTALL_DIR/$PLUGIN_NAME"
chmod 644 "$INSTALL_DIR/$PLUGIN_NAME"

# --- Write experimental settings if requested ---
SETTINGS_FILE="$HOME/.PacketCircle/settings.ini"
if [ "$ENABLE_EXPERIMENTAL" = true ]; then
    mkdir -p "$HOME/.PacketCircle"
    if [ -f "$SETTINGS_FILE" ]; then
        grep -v '^\[Beta\]' "$SETTINGS_FILE" | grep -v '^EnableGraphView' > "${SETTINGS_FILE}.tmp" || true
        mv "${SETTINGS_FILE}.tmp" "$SETTINGS_FILE"
    fi
    printf "\n[Beta]\nEnableGraphView=true\n" >> "$SETTINGS_FILE"
    printf "${CYAN}✓${NC} Experimental Graph View enabled in %s\n" "$SETTINGS_FILE"
fi

# --- Verify ---
if [ -f "$INSTALL_DIR/$PLUGIN_NAME" ]; then
    INSTALLED_SIZE=$(ls -lh "$INSTALL_DIR/$PLUGIN_NAME" | awk '{print $5}')
    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║      Installation successful!                    ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  Installed:  PacketCircle ${CYAN}v.%s${NC} (%s)" "$SELECTED_VERSION" "$SELECTED_WS_LABEL"
    if [ "$ENABLE_EXPERIMENTAL" = true ]; then
        printf " ${CYAN}[Experimental]${NC}"
    fi
    printf "\n"
    printf "  Size:       %s\n" "$INSTALLED_SIZE"
    printf "  Location:   ${BLUE}%s/%s${NC}\n" "$INSTALL_DIR" "$PLUGIN_NAME"
    printf "\n"
    printf "  Next steps:\n"
    printf "  1. Restart Wireshark (if running)\n"
    printf "  2. Open a capture or start a live capture\n"
    printf "  3. Look for PacketCircle in the Tools menu\n"
    if [ "$ENABLE_EXPERIMENTAL" = true ]; then
        printf "  4. The Graph button appears in the PacketCircle toolbar\n"
    fi
    printf "\n"
    printf "  To uninstall, run this script again and choose 'u'.\n"
    if [ "$ENABLE_EXPERIMENTAL" = true ]; then
        printf "\n"
        printf "  ${YELLOW}⚠ Graph View (Experimental) — QA on Linux has been basic only.${NC}\n"
        printf "  ${YELLOW}  If you encounter issues, run the installer again and choose Standard${NC}\n"
        printf "  ${YELLOW}  to disable it (removes EnableGraphView from settings.ini).${NC}\n"
    fi
    printf "\n"
    printf "  ${YELLOW}Troubleshooting:${NC}\n"
    printf "  - Verify path: Help > About Wireshark > Folders > Personal Plugins\n"
    printf "  - Check loading: wireshark -o log.level:debug 2>&1 | grep packetcircle\n"
    printf "\n"
else
    printf "${RED}Error: Installation failed.${NC}\n"
    exit 1
fi
