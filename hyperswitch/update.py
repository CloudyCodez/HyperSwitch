import json
import os
import re
import subprocess
import tempfile
import textwrap
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .metadata import APP_NAME, DEBUG_APP_NAME

REPO_OWNER = "CloudyCodez"
REPO_NAME = "HyperSwitch"
RELEASES_API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases?per_page=20"
RELEASES_PAGE_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases"
USER_AGENT = f"{APP_NAME}-Updater"

_VERSION_RE = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?\s*$")


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    download_url: str
    size: int


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    tag_name: str
    title: str
    html_url: str
    published_at: str
    prerelease: bool
    asset: ReleaseAsset


@dataclass(frozen=True)
class UpdateProbe:
    status: str
    current_version: str
    latest_version: str | None
    detail: str
    release: ReleaseInfo | None = None


@dataclass(frozen=True)
class _VersionKey:
    major: int
    minor: int
    patch: int
    prerelease: tuple[tuple[int, int | str], ...]

    def __lt__(self, other: "_VersionKey") -> bool:
        left_core = (self.major, self.minor, self.patch)
        right_core = (other.major, other.minor, other.patch)
        if left_core != right_core:
            return left_core < right_core

        if not self.prerelease and other.prerelease:
            return False
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and not other.prerelease:
            return False

        for left_token, right_token in zip(self.prerelease, other.prerelease):
            if left_token == right_token:
                continue
            if left_token[0] != right_token[0]:
                return left_token[0] < right_token[0]
            return left_token[1] < right_token[1]
        return len(self.prerelease) < len(other.prerelease)


def normalize_version(value: str) -> str:
    return value.strip().lstrip("vV")


def release_page_url() -> str:
    return RELEASES_PAGE_URL


def check_for_updates(current_version: str) -> UpdateProbe:
    releases = _fetch_releases()
    if not releases:
        return UpdateProbe(
            status="unavailable",
            current_version=normalize_version(current_version),
            latest_version=None,
            detail="No compatible GitHub release packages were found.",
        )

    latest = releases[0]
    comparison = compare_versions(current_version, latest.version)
    current_clean = normalize_version(current_version)
    if comparison < 0:
        return UpdateProbe(
            status="available",
            current_version=current_clean,
            latest_version=latest.version,
            detail=f"GitHub release {latest.version} is newer than {current_clean}.",
            release=latest,
        )
    if comparison > 0:
        return UpdateProbe(
            status="ahead",
            current_version=current_clean,
            latest_version=latest.version,
            detail=f"Current build {current_clean} is newer than GitHub release {latest.version}.",
            release=latest,
        )
    return UpdateProbe(
        status="current",
        current_version=current_clean,
        latest_version=latest.version,
        detail=f"Current build {current_clean} matches the latest GitHub release.",
        release=latest,
    )


def compare_versions(left: str, right: str) -> int:
    left_key = _parse_version_key(left)
    right_key = _parse_version_key(right)
    if left_key and right_key:
        if left_key < right_key:
            return -1
        if right_key < left_key:
            return 1
        return 0

    left_clean = normalize_version(left)
    right_clean = normalize_version(right)
    if left_clean < right_clean:
        return -1
    if left_clean > right_clean:
        return 1
    return 0


def install_target_for_executable(executable_path: str) -> tuple[str, str]:
    exe_path = Path(executable_path).resolve()
    if exe_path.parent.name.lower() == "debug" and exe_path.name.lower() == f"{DEBUG_APP_NAME.lower()}.exe":
        return str(exe_path.parent.parent), os.path.join("debug", exe_path.name)
    return str(exe_path.parent), exe_path.name


def download_release_package(release: ReleaseInfo, destination_root: str | None = None) -> str:
    root = Path(destination_root) if destination_root else Path(tempfile.mkdtemp(prefix="hyperswitch-update-"))
    root.mkdir(parents=True, exist_ok=True)
    target = root / release.asset.name

    request = urllib.request.Request(
        release.asset.download_url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response, open(target, "wb") as handle:
        while True:
            chunk = response.read(1024 * 64)
            if not chunk:
                break
            handle.write(chunk)
    return str(target)


def launch_update_installer(zip_path: str, install_dir: str, restart_relative_path: str, wait_pid: int) -> None:
    job_root = Path(zip_path).resolve().parent
    script_path = job_root / "apply-update.ps1"
    script_path.write_text(_installer_script(), encoding="utf-8")

    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-ZipPath",
            str(Path(zip_path).resolve()),
            "-InstallDir",
            str(Path(install_dir).resolve()),
            "-RestartRelativePath",
            restart_relative_path,
            "-WaitPid",
            str(wait_pid),
        ],
        cwd=str(job_root),
        creationflags=flags,
        close_fds=True,
    )


def _fetch_releases() -> list[ReleaseInfo]:
    request = urllib.request.Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)

    candidates: list[tuple[_VersionKey, str, ReleaseInfo]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if item.get("draft"):
            continue

        tag_name = str(item.get("tag_name", "")).strip()
        version = normalize_version(tag_name)
        version_key = _parse_version_key(version)
        if not version_key:
            continue

        asset = _portable_asset(item.get("assets", []))
        if not asset:
            continue

        release = ReleaseInfo(
            version=version,
            tag_name=tag_name or f"v{version}",
            title=str(item.get("name") or tag_name or version),
            html_url=str(item.get("html_url", "")).strip(),
            published_at=str(item.get("published_at", "")).strip(),
            prerelease=bool(item.get("prerelease")),
            asset=asset,
        )
        candidates.append((version_key, release.published_at, release))

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [release for _, _, release in candidates]


def _portable_asset(assets: object) -> ReleaseAsset | None:
    if not isinstance(assets, list):
        return None

    preferred: ReleaseAsset | None = None
    for item in assets:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        url = str(item.get("browser_download_url", "")).strip()
        if not name or not url:
            continue
        lower_name = name.lower()
        if lower_name.startswith(f"{APP_NAME.lower()}-v") and lower_name.endswith("-portable.zip"):
            return ReleaseAsset(name=name, download_url=url, size=int(item.get("size") or 0))
        if lower_name.endswith(".zip") and preferred is None:
            preferred = ReleaseAsset(name=name, download_url=url, size=int(item.get("size") or 0))
    return preferred


def _parse_version_key(value: str) -> _VersionKey | None:
    match = _VERSION_RE.match(value)
    if not match:
        return None

    prerelease_text = match.group(4) or ""
    prerelease: list[tuple[int, int | str]] = []
    if prerelease_text:
        for token in prerelease_text.split("."):
            token = token.strip()
            if not token:
                continue
            if token.isdigit():
                prerelease.append((0, int(token)))
            else:
                prerelease.append((1, token.lower()))

    return _VersionKey(
        major=int(match.group(1)),
        minor=int(match.group(2)),
        patch=int(match.group(3)),
        prerelease=tuple(prerelease),
    )


def _installer_script() -> str:
    return textwrap.dedent(
        """
        param(
            [Parameter(Mandatory = $true)][string]$ZipPath,
            [Parameter(Mandatory = $true)][string]$InstallDir,
            [Parameter(Mandatory = $true)][string]$RestartRelativePath,
            [Parameter(Mandatory = $true)][int]$WaitPid
        )

        $ErrorActionPreference = 'Stop'

        function Remove-IfPresent([string]$Path) {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Recurse -Force
            }
        }

        $jobRoot = Split-Path -Parent $ZipPath
        $extractRoot = Join-Path $jobRoot 'expanded'
        $scriptPath = $MyInvocation.MyCommand.Path

        while (Get-Process -Id $WaitPid -ErrorAction SilentlyContinue) {
            Start-Sleep -Milliseconds 500
        }

        Remove-IfPresent $extractRoot
        New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $extractRoot -Force

        $bundleRoot = Get-ChildItem -LiteralPath $extractRoot -Directory | Select-Object -First 1
        if (-not $bundleRoot) {
            throw 'The update package did not contain a release folder.'
        }

        foreach ($name in @('assets', 'debug', 'docs', 'source')) {
            Remove-IfPresent (Join-Path $InstallDir $name)
        }

        Get-ChildItem -LiteralPath $bundleRoot.FullName -Force | ForEach-Object {
            $destination = Join-Path $InstallDir $_.Name
            if ($_.PSIsContainer) {
                Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force
            } else {
                Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
            }
        }

        $restartPath = Join-Path $InstallDir $RestartRelativePath
        if (Test-Path -LiteralPath $restartPath) {
            Start-Process -FilePath $restartPath
        }

        Start-Sleep -Seconds 2
        Remove-IfPresent $extractRoot
        Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
        """
    ).strip() + "\n"
