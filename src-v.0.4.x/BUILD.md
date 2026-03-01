# Building PacketCircle from Source

> **Important**: You must build against the **same Wireshark minor version** you have installed. For example, if you have Wireshark 4.6.3, build against the `v4.6.3` source tag. The pre-built binaries are compiled for Wireshark 4.6.x only.

## Prerequisites

- **Wireshark source code** (matching your installed Wireshark version, e.g., `v4.6.3` tag)
- **CMake** 3.10 or higher
- **Qt6** (Core, Widgets, Gui) — **must match the exact Qt version bundled by Wireshark** (see below)
- **GLib** 2.54+
- **C/C++ compiler** (Clang on macOS, GCC on Linux)
- **Ninja** (recommended) or Make

### Critical: Qt Version Must Match Wireshark

> **You MUST build against the exact same Qt version that your installed Wireshark uses.**
> Homebrew's `qt@6` is often newer than what Wireshark bundles, and even a minor Qt version
> mismatch (e.g., Qt 6.10 vs 6.9) causes ABI-incompatible symbols like
> `QObject::doSetProperty` that prevent the plugin from loading at runtime.

**How to find Wireshark's Qt version:**

```bash
# macOS — check the bundled QtCore framework
otool -L /Applications/Wireshark.app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore | head -3
# Look for "current version X.Y.Z" — e.g., 6.9.3

# Windows — open Wireshark → Help → About Wireshark → look for "with Qt X.Y.Z"

# Linux
ldd $(which wireshark) | grep Qt6Core
```

**How to install the matching Qt version (using `aqtinstall`):**

```bash
pip3 install aqtinstall

# Example: install Qt 6.9.3 for macOS
aqt install-qt mac desktop 6.9.3 -O ~/Qt

# Example: install Qt 6.9.3 for Linux
aqt install-qt linux desktop 6.9.3 -O ~/Qt
```

Then point CMake to it:

```bash
cmake -DCMAKE_PREFIX_PATH="$HOME/Qt/6.9.3/macos" \
      -DQt6_DIR="$HOME/Qt/6.9.3/macos/lib/cmake/Qt6" \
      ...
```

> **Do NOT use `brew install qt@6`** for building this plugin unless you have verified
> that Homebrew's Qt version exactly matches Wireshark's. As of early 2026, Homebrew
> ships Qt 6.10.x while Wireshark 4.6.x bundles Qt 6.9.3.

### macOS Dependencies (Homebrew)

```bash
# Non-Qt dependencies only — Qt must be installed separately via aqtinstall (see above)
brew install cmake glib libgcrypt c-ares pcre2 libxml2 ninja xxhash gnutls lz4 zstd
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
   # Replace ~/Qt/6.9.3/macos with the path matching YOUR Wireshark's Qt version
   cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle \
         -DCMAKE_PREFIX_PATH="$HOME/Qt/6.9.3/macos" \
         -DQt6_DIR="$HOME/Qt/6.9.3/macos/lib/cmake/Qt6" \
         -DUSE_qt6=ON \
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
# IMPORTANT: Use the SAME Qt version from aqtinstall (not Homebrew's qt@6)
arch -x86_64 /usr/local/bin/cmake \
    -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/packetcircle \
    -DCMAKE_OSX_ARCHITECTURES=x86_64 \
    -DCMAKE_PREFIX_PATH="$HOME/Qt/6.9.3/macos;/usr/local" \
    -DQt6_DIR="$HOME/Qt/6.9.3/macos/lib/cmake/Qt6" \
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

### Step 5: Fix Dynamic Library References

After `lipo`, fix any absolute library paths to use `@rpath` so Wireshark's bundled libraries are found at runtime. Check what needs fixing with `otool -L`:

```bash
otool -L packetcircle-universal.so | grep -v "@rpath\|/System\|/usr/lib"
```

Fix any absolute paths to match Wireshark's bundled library names:

```bash
# Example: fix xxhash and glib references
# Check exact filenames: ls /Applications/Wireshark.app/Contents/Frameworks/libxxhash*
install_name_tool -change "/opt/homebrew/opt/xxhash/lib/libxxhash.0.dylib" \
    "@rpath/libxxhash.0.8.3.dylib" packetcircle-universal.so

install_name_tool -change "/opt/homebrew/opt/glib/lib/libglib-2.0.0.dylib" \
    "@rpath/libglib-2.0.0.dylib" packetcircle-universal.so
```

> **Tip**: Always verify the exact filenames inside `/Applications/Wireshark.app/Contents/Frameworks/`
> since versioned filenames (e.g., `libxxhash.0.8.3.dylib` vs `libxxhash.0.dylib`) must match precisely.

## Verification

```bash
# Check architecture
file packetcircle.so

# Check dependencies — all non-system libs should use @rpath
otool -L packetcircle.so

# Verify Qt version matches Wireshark's (critical!)
otool -L packetcircle.so | grep QtCore
# Should show the same version as: otool -L /Applications/Wireshark.app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore
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

---

*AI-Assisted: yes (Claude) — build system documentation, cross-platform compatibility, Qt version matching guidance*
