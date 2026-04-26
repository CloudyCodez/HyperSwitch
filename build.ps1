param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

function Invoke-PythonStep {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )

    & $python @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $($Args -join ' ')"
    }
}

$pythonCandidates = @(
    "C:\Users\conno\AppData\Local\Python\bin\python.exe",
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    (Get-Command py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
) | Where-Object { $_ }

$python = $pythonCandidates | Select-Object -First 1

if (-not $python) {
    throw "Python was not found. Install Python 3 and ensure python or py is available."
}

if (-not $Version) {
    $Version = (& $python -c "from hyperswitch.metadata import APP_VERSION; print(APP_VERSION)").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read APP_VERSION from hyperswitch.metadata"
    }
}

$packageVersion = if ($Version -like "v*") { $Version } else { "v$Version" }

Invoke-PythonStep -m pip install -r requirements.txt
Invoke-PythonStep generate_icon.py

Invoke-PythonStep -m PyInstaller --noconfirm --clean --onefile --windowed `
    --add-data "hyperswitch.ico;." `
    --add-data "hyperswitch.png;." `
    --add-data "chibi-cloud-watermark.png;." `
    --icon hyperswitch.ico `
    --name HyperSwitch `
    hyperv_switch.py

Invoke-PythonStep -m PyInstaller --noconfirm --clean --onefile --windowed `
    --add-data "hyperswitch.ico;." `
    --add-data "hyperswitch.png;." `
    --add-data "chibi-cloud-watermark.png;." `
    --icon hyperswitch.ico `
    --name HyperSwitchDBG `
    hyperv_switch.py

Write-Host ""
Write-Host "Build complete:"
Write-Host "  dist\\HyperSwitch.exe"
Write-Host "  dist\\HyperSwitchDBG.exe"

Invoke-PythonStep scripts\package_release.py --version $packageVersion

Write-Host "  out\\HyperSwitch-$packageVersion-portable.zip"
