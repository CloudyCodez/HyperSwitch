$ErrorActionPreference = "Stop"

$pythonCandidates = @(
    "C:\Users\conno\AppData\Local\Python\bin\python.exe",
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    (Get-Command py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
) | Where-Object { $_ }

$python = $pythonCandidates | Select-Object -First 1

if (-not $python) {
    throw "Python was not found. Install Python 3 and ensure python or py is available."
}

& $python -m pip install -r requirements.txt
& $python generate_icon.py

& $python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --add-data "hyperswitch.ico;." `
    --add-data "hyperswitch.png;." `
    --icon hyperswitch.ico `
    --name HyperSwitch `
    hyperv_switch.py

& $python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --add-data "hyperswitch.ico;." `
    --add-data "hyperswitch.png;." `
    --icon hyperswitch.ico `
    --name HyperSwitchDBG `
    hyperv_switch.py

Write-Host ""
Write-Host "Build complete:"
Write-Host "  dist\\HyperSwitch.exe"
Write-Host "  dist\\HyperSwitchDBG.exe"
