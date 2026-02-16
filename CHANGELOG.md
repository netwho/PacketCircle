# Changelog

All notable changes to PacketCircle will be documented in this file.

## [0.3.2] - 2026-02-16

### Added
- **TCP Stream Statistics** - Connection popup context menu now includes TCP Throughput Graph and TCP Round-Trip Time Graph, launching Wireshark's built-in TCP stream analysis tools
- **Select Search Results** - New "Select Results" button that selects only the communication pairs matching the current search, deselecting all others
- **Theme-Aware UI** - Plugin automatically adapts to light and dark themes based on Wireshark/OS settings
- **Port Search** - Search bar supports TCP/UDP port queries (e.g., `TCP 443`, `UDP 53`) to highlight matching communication pairs
- **Name Truncation** - Long resolved hostnames in the pair list are truncated with "..." when space is limited

### Changed
- Help button enlarged (30x30) and right-aligned in the toolbar for better visibility
- Help dialog version corrected and updated with all new features
- Version bumped to 0.3.2

### Fixed
- IP fragment protocol classification no longer misidentifies fragments as ICMP or TCP
- Bidirectional filter generation uses `ip.addr` / `eth.addr` for correct two-way matching

## [0.3.1] - 2026-02-15

### Added
- **User Preferences Persistence** - Window size, position, splitter layout, display mode (IP/MAC), metric (Packets/Bytes), Top N, view (Circle/Table), and line thickness are saved to `~/.PacketCircle/settings.ini` and restored on next launch
- **Connection Popup** - Click a line in the circle to see a port-level connection summary with protocol, destination port, service name, and packet counts
- **Context Menu Filtering** - Right-click a row in the connection popup to apply a Wireshark display filter or follow a TCP stream
- **Search Blinking in Pair List** - Search results blink red/yellow in both the circle and the pair list simultaneously
- **Name Resolution** - Circle nodes and pair list display resolved names matching Wireshark's global name resolution settings
- **Modern Controls UI** - Redesigned toolbar with segmented button groups and icon-style action buttons
- **Responsive Layout** - Window scales from 640x480 to Full HD+; circle and node fonts resize proportionally
- **Version in Title Bar** - Plugin window title now shows the current version
- **Windows 10 Guidance** - Windows installer detects Windows 10 and provides targeted advice for common VC++ runtime and DLL loading issues

### Changed
- Minimum window size reduced to 640x480 for older displays
- Default window size set to 1280x780

### Fixed
- Search bar visibility on Windows (text was black on black background)
- Splitter handle now easier to grab on Windows

## [0.2.2] - 2026-02-13

### Added
- **Adaptive MAC Display** - MAC addresses in the pair list show abbreviated form when the panel is narrow and full address when the panel is wide enough
- **Multi-Version Linux Support** - Unified installer with pre-built binaries for Wireshark 4.2.x, 4.4.x, and 4.6.x
- **Smart Installer** - Linux installer auto-detects Wireshark version and installs the correct binary
- Source code uses conditional compilation to support Wireshark 4.2.x–4.6.x APIs
- AI-Assisted: yes (Claude) — build automation, installer scripting, cross-platform compatibility, documentation

### Changed
- Reduced font size on Windows for better cross-platform consistency

### Fixed
- Fixed protocol color mapping documentation to match actual implementation

## [0.2.1] - 2026-02-11

### Added
- **Universal Binary** - macOS plugin now runs natively on both Intel (x86_64) and Apple Silicon (arm64)
- **Linux x86_64 Binary** - Pre-built plugin for Linux (Ubuntu 24.04 / Debian-based)
- **Wireshark 4.6.x Compatibility** - Built against Wireshark 4.6.3 for broad 4.6.x support
- **PDF Report Export** - Generate a professional one-page PDF report with circle visualization, IP pair table, and summary
- **Clear Filter Button** - Quickly reset the Wireshark display filter and show all connections
- **Node Tooltips** - Hover over circle nodes to see destination ports, service names, and packet counts
- **Protocol Filtering** - Interactive checkboxes to filter the visualization by specific protocols
- **Mixed Protocol Visualization** - Dotted lines with alternating TCP/UDP colors for mixed-protocol connections
- **Search Filter** - Search box to quickly find IP addresses in the pair list
- **Directional Filtering** - Display filters now correctly match a single direction (A->B) instead of both directions
- **Resizable Splitter** - Drag the divider between the circle and pair list to resize panels
- **Help Dialog** - In-app help documenting all features and controls

### Changed
- Increased default window size to prevent button text clipping
- Circle visualization only shows selected pairs (non-selected pairs are completely hidden)
- PDF circle uses white background with high-contrast labels for print readability
- Improved control bar spacing and layout

### Fixed
- Fixed issue where selecting a single pair showed multiple lines on the circle
- Fixed bidirectional filter generation (was showing both A->B and B->A instead of just the selected direction)
- Fixed splitter between circle and pair list (was visible but non-functional)
- Fixed PDF table column widths to prevent "Bytes" label clipping
- Fixed installer script compatibility (POSIX printf, Wireshark version detection, plugin path discovery)
- Installer now checks Wireshark version and warns if not 4.6.x (prevents installing incompatible binary)

## [0.1.0] - 2025-12-01

### Initial Release
- Circle visualization of network communication pairs
- Protocol color coding (HTTP, HTTPS, SMB, DNS, MSSQL, SSH, FTP, TCP, UDP)
- Line weight proportional to traffic volume
- Top 10/25/50 conversation limits
- Packets and Bytes metric switching
- Circle and Table view modes
- MAC and IP address pair modes
- Wireshark display filter integration
- Select All / Select None bulk operations
- Protocol legend with color indicators
