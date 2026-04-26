# HyperSwitch

HyperSwitch is a Windows desktop utility for checking and toggling Hyper-V, VBS, Driver Signature Enforcement, CPU virtualization state, and a small set of related troubleshooting controls from one place.

## Version 2.0

HyperSwitch `2.0` is now in alpha and continuing forward after the initial alpha tag.

Current development version: `2.0.0-alpha.2`

- Roadmap: `docs/ROADMAP-2.0.md`
- Current foundation work now includes release polish, metadata/version cleanup, UI copy refinement, dedicated feature modules for Hyper-V, DSE, and VBS, plus separate platform and mitigation modules for the broader read-only security surface.

## What It Does

- Shows current virtualization and security state in a single desktop app
- Offers safer Basic mode for common troubleshooting
- Includes Advanced mode for deeper system changes
- Exports an in-app support bundle with debug output, current state, recent activity, and recovery artifacts
- Includes a Recovery Center with grouped restore sets, recent rollback backups, support exports, restore commands, and direct backup import actions
- Can check GitHub Releases, cache release state for support, verify downloaded packages, and self-apply a newer portable build when one is available
- Lets operators quickly copy a machine summary or open the rollback backup folder
- Persists recent operator activity and remembered mode selection through an in-app Activity Center
- Supports a debugger build that writes `debugger.txt` for issue reports
- Packages into a portable Windows `.exe`

## Requirements

- Windows
- Administrator privileges
- Python 3.11+ for local builds

## Run From Source

```powershell
python hyperv_switch.py
```

## Build The Executable

```powershell
.\build.ps1
```

This creates:

- `dist\HyperSwitch.exe`
- `dist\HyperSwitchDBG.exe`
- `out\HyperSwitch-v<version>-portable.zip`

## Usage Notes

- Run the executable as Administrator
- Many changes only fully apply after a restart
- Basic mode is the safer default for one-off troubleshooting
- Advanced mode exposes additional controls and should be used carefully

## Debugger Build

`HyperSwitchDBG.exe` launches the diagnostic flow and writes `debugger.txt` next to the executable. Use that report when filing bugs or reporting machine-specific behavior.

## GitHub Releases

The repo includes a GitHub Actions workflow at `.github/workflows/release.yml`.

- Pushing a tag like `v1.0.2` builds `HyperSwitch.exe`, `HyperSwitchDBG.exe`, and a portable zip bundle
- The portable zip keeps `HyperSwitch.exe` at the top level and tucks docs, source files, assets, and debug tools into subfolders
- The workflow uploads the build outputs as workflow artifacts
- Tagged builds are published to GitHub Releases automatically

## License

MIT
