# PacketCircle v.0.5.3 — Release Notes

**Released:** 2026-05-21  
**Status:** Public Beta  
**Requires:** Wireshark 4.0.x – 4.6.x

---

## What's New

### Graph View improvements

- **Star layout is now the default** — When you open the Graph view for the first time, it starts in Star layout with the busiest host anchored at the centre. Previously it opened in Force-directed. All 8 layouts remain fully selectable.
- **Toolbar settings are persisted** — The three Graph toolbar selectors (Edge color, Node color, Layout) are now saved to `~/.PacketCircle/settings.ini` under `[Graph]` and restored on the next launch. Your preferred view survives restarts.
- **Improved legend readability** — Hint text updated from the generic "click row to filter" to context-accurate labels: "Click Protocol to select" (node legend) and "Click Edge to filter" (edge legend). Legend font size increased from 6 pt to 9 pt.

---

## Bug Fixes

### macOS: crash report on Wireshark exit — fixed

Earlier releases (v.0.5.2 and below) could trigger a crash report for Wireshark after a normal exit on macOS. The root cause: Wireshark's `epan_cleanup()` called `g_module_close()` on the plugin — unmapping its code — before `QApplication::~QApplication()` had finished cleaning up Qt's accessibility cache. The cache then called into unmapped vtable memory, producing a `SIGSEGV` in `QAccessibleCache::~QAccessibleCache()`.

**Fix:** The plugin now calls `dlopen(..., RTLD_NODELETE)` on itself at registration time. This prevents the dynamic linker from unmapping the plugin DSO when `dlclose()` is called, keeping the mapping valid through the full Qt teardown. No workaround is needed with v.0.5.3.

### Linux installer: uninstall no longer blocked by missing binaries

The prerequisite check in the Linux installer ran before the action menu was shown. If only `install.sh` was present (no binary subdirectories), the installer exited early — making it impossible to uninstall a previously installed plugin using just the script. Fixed: the binary check is now skipped for uninstall actions.

---

## Download & Install

### macOS (Universal Binary — Intel + Apple Silicon)

```bash
cd installer/macos-universal
chmod +x install.sh
./install.sh
```

### Linux (x86_64 — WS 4.0 / 4.2 / 4.4 / 4.6)

```bash
cd installer/linux-x86_64
chmod +x install.sh
./install.sh
```

### Windows (x86_64)

```
cd installer\windows-x86_64
install.bat
```

Or [download installer.zip](https://github.com/netwho/PacketCircle/raw/main/installer.zip) for macOS and Windows.

---

## Supported Platforms

| Wireshark | macOS Universal | Windows x86_64 | Linux x86_64 |
|---|---|---|---|
| 4.6.x | ✓ | ✓ | ✓ |
| 4.4.x | — | — | ✓ |
| 4.2.x | — | — | ✓ |
| 4.0.x | — | — | ✓ |

---

## Upgrading from v.0.5.2

Run the installer and press Enter — it detects your current version and upgrades in place. No manual file removal needed.

---

[Full changelog](CHANGELOG.md) · [Installation guide](INSTALLATION.md) · [GitHub](https://github.com/netwho/PacketCircle)

---

*AI-Assisted: yes (Claude by Anthropic) — default layout, settings persistence, legend text, macOS crash fix, Linux uninstall fix, version bump, documentation.*
