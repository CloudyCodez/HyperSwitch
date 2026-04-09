# HyperSwitch

HyperSwitch is a Windows desktop utility for checking and toggling Hyper-V, VBS, Driver Signature Enforcement, CPU virtualization state, and a small set of related troubleshooting controls from one place.

## What It Does

- Shows current virtualization and security state in a single desktop app
- Offers safer Basic mode for common troubleshooting
- Includes Advanced mode for deeper system changes
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

## Usage Notes

- Run the executable as Administrator
- Many changes only fully apply after a restart
- Basic mode is the safer default for one-off troubleshooting
- Advanced mode exposes additional controls and should be used carefully

## Debugger Build

`HyperSwitchDBG.exe` launches the diagnostic flow and writes `debugger.txt` next to the executable. Use that report when filing bugs or reporting machine-specific behavior.

## GitHub Releases

The repo includes a GitHub Actions workflow at `.github/workflows/release.yml`.

- Pushing a tag like `v1.0.0` builds `HyperSwitch.exe`
- The workflow uploads the executable as a workflow artifact
- Tagged builds are published to GitHub Releases automatically

## License

MIT
