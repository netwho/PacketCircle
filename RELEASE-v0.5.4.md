# PacketCircle v.0.5.4 — Release Notes

**Released:** 2026-06-06  
**Status:** Public Beta  
**Requires:** Wireshark 4.0.x – 4.6.x

---

## What's New

v0.5.4 is a **UI refresh**. PacketCircle's chrome now matches its Wireshark host and reads as one cohesive app. There are no changes to packet analysis or detection — this release is purely visual (plus one display-bug fix).

### Wireshark-native look

- **Accent colour comes from Wireshark** — Every accent (selected toolbar segment, active states, focus rings, menu and legend selection) now uses the host palette's highlight colour, read at runtime. PacketCircle automatically matches whatever blue Wireshark uses, on any theme or platform — no hardcoded colour.
- **Toolbar segmented controls are now pill tracks** — The Top / Metric / View / Mode groups render as recessed tracks with borderless chip buttons. The ⚙ and ? buttons are round ghost buttons with an accent ring on hover.
- **Context menus restyled** — All right-click menus share one themed look: rounded card, inset accent-pill selection, sectioned with hairline separators. A light-theme menu style was added (menus previously fell back to the native look in light mode).
- **Graph-view legends are now cards** — Both the node and edge legends sit on rounded dark cards with a styled header (accent dot + title + hairline). The node legend previously had no background (text overlapped the graph) and no title — it now has both.

### Action bar & graph controls

- **Row 2 (actions + filter)** — Filter / Clear / Reload / PDF / Send to NTOP / Send to Malcolm gained outline icons, grouped with thin dividers (filter · data · integrations). The filter input is a rounded search field with a leading magnifier. **Clear** now also empties the search field and reloads, returning to the full unfiltered view.
- **Row 3 (graph controls)** — Edge / Node / Layout are rounded "field chips" with dark, theme-matched dropdowns that widen to fit the longest entry (no more truncated "Service / Port"). Re-layout gained a ↻ icon; Zoom is now a recessed pill.

All toolbar icons are drawn in-process (QPainter) — no new library dependency; the binaries stay dependency-clean (`@rpath` on macOS).

---

## Bug Fixes

### Anomaly Score breakdown: "packets/port" factor

The scan-rate factor in the Anomaly Score breakdown displayed the literal text `%.1f packets/port — rapid scan rate` instead of the computed value. The cause was a C `printf` specifier used inside Qt's `QString::arg()` (which only understands `%1` placeholders). Fixed — it now shows the real ratio, e.g. "2.0 packets/port — rapid scan rate".

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

## Upgrading from v.0.5.3

Run the installer and press Enter — it detects your current version and upgrades in place. No manual file removal needed.

---

[Full changelog](CHANGELOG.md) · [Installation guide](INSTALLATION.md) · [GitHub](https://github.com/netwho/PacketCircle)

---

*AI-Assisted: yes (Claude by Anthropic) — full UI restyle, anomaly-score label fix, version bump, installer + documentation updates.*
