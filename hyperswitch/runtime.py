import os
import sys
from pathlib import Path

from .metadata import APP_NAME, DEBUG_APP_NAME


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_base_dir() -> Path:
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
    return Path(__file__).resolve().parent.parent


def resource_path(name: str) -> str:
    return str(resource_base_dir() / name)


def app_storage_dir() -> str:
    root = os.environ.get("ProgramData") or os.environ.get("LOCALAPPDATA") or os.getcwd()
    folder = os.path.join(root, APP_NAME)
    os.makedirs(folder, exist_ok=True)
    return folder


def state_file_path() -> str:
    return os.path.join(app_storage_dir(), "state.json")


def backup_dir() -> str:
    folder = os.path.join(app_storage_dir(), "backups")
    os.makedirs(folder, exist_ok=True)
    return folder


def debug_report_path() -> str:
    if is_frozen():
        return os.path.join(os.path.dirname(sys.executable), "debugger.txt")
    return os.path.join(str(Path(__file__).resolve().parent.parent), "debugger.txt")


def is_debug_mode(argv: list[str] | None = None) -> bool:
    args = argv if argv is not None else sys.argv
    exe = os.path.basename(sys.executable).lower() if is_frozen() else ""
    return ("--debug-report" in args) or exe.startswith(DEBUG_APP_NAME.lower())
