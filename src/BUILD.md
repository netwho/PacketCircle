# Building PacketCircle from Source

> **Important**: You must build against the **same Wireshark minor version** you have installed. For example, if you have Wireshark 4.6.3, build against the `v4.6.3` source tag. The pre-built binaries are compiled for Wireshark 4.6.x only.

## Prerequisites

- **Wireshark source code** (matching your installed Wireshark version, e.g., `v4.6.3` tag)
- **CMake** 3.10 or higher
- **Qt6** (Core, Widgets, Gui modules)
- **GLib** 2.54+
- **C/C++ compiler** (Clang on macOS, GCC on Linux)
- **Ninja** (recommended) or Make

### macOS Dependencies (Homebrew)

```bash
brew install cmake qt@6 glib libgcrypt c-ares pcre2 libxml2 ninja
```

## Standard Build (Single Architecture)

1. **Get Wireshark source (use the tag matching your installed version):**
   ```bash
   git clone --depth 1 --branch v4.6.3 https://gitlab.com/wireshark/wireshark.git wireshark-source
   cd wireshark-source
   ```
   Replace `v4.6.3` with your version tag (e.g., `v4.4.2`, `v4.2.8`).

2. **Copy plugin source files:**
   ```bash
   mkdir -p plugins/epan/packetcircle
   cp /path/to/PacketCircle/src/* plugins/epan/packetcircle/
   ```

3. **Configure with CMake:**
   ```bash
   mkdir build && cd build
   cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle \
         -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt \
         -G Ninja ..
   ```

4. **Build the plugin:**
   ```bash
   ninja packetcircle
   ```

5. **Find the built plugin:**
   ```
   build/run/Wireshark.app/Contents/PlugIns/wireshark/4-6/epan/packetcircle.so
   ```
   The version directory (e.g., `4-6`) matches your Wireshark source version.

## Universal Binary Build (macOS arm64 + x86_64)

To create a plugin that works on both Intel and Apple Silicon Macs:

### Step 1: Build for arm64 (Apple Silicon)

Follow the standard build above on an Apple Silicon Mac using `/opt/homebrew` dependencies. This produces the arm64 binary.

### Step 2: Install x86_64 Dependencies

Install a separate x86_64 Homebrew and dependencies:

```bash
# Install x86_64 Homebrew at /usr/local
arch -x86_64 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install x86_64 dependencies
arch -x86_64 /usr/local/bin/brew install cmake qt@6 glib libgcrypt c-ares pcre2 \
    libxml2 ninja xxhash gnutls lz4 zstd brotli snappy nghttp2 libnghttp3 \
    speexdsp minizip zlib flex gettext
```

### Step 3: Build for x86_64

```bash
mkdir build-x86_64 && cd build-x86_64

# Configure with x86_64 library paths
arch -x86_64 /usr/local/bin/cmake \
    -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle \
    -DCMAKE_OSX_ARCHITECTURES=x86_64 \
    -DCMAKE_PREFIX_PATH="/usr/local/opt/qt;/usr/local/opt/libxml2;/usr/local/opt/zlib" \
    -DCMAKE_MAKE_PROGRAM=/usr/local/bin/ninja \
    -DENABLE_WERROR=OFF \
    -DUSE_qt6=ON \
    -G Ninja ..

# Build
arch -x86_64 /usr/local/bin/ninja packetcircle
```

### Step 4: Merge with lipo

```bash
lipo -create \
    build/run/Wireshark.app/Contents/PlugIns/wireshark/4-6/epan/packetcircle.so \
    build-x86_64/run/Wireshark.app/Contents/PlugIns/wireshark/4-6/epan/packetcircle.so \
    -output packetcircle-universal.so

# Verify
file packetcircle-universal.so
# Expected: Mach-O universal binary with 2 architectures: [x86_64] [arm64]
```

## Verification

```bash
# Check architecture
file packetcircle.so

# Check dependencies
otool -L packetcircle.so
```

## Installation After Build

Replace `4-6` below with the version directory matching your Wireshark build (e.g., `4-4` for Wireshark 4.4.x):

```bash
mkdir -p ~/.local/lib/wireshark/plugins/4-6/epan/
cp packetcircle.so ~/.local/lib/wireshark/plugins/4-6/epan/
chmod 644 ~/.local/lib/wireshark/plugins/4-6/epan/packetcircle.so
```

Restart Wireshark to load the plugin.

> **Tip**: Check your plugin version directory by looking under Help -> About Wireshark -> Folders -> Personal Plugins.
