import subprocess
from datetime import datetime


_BCD_CACHE: dict[str, tuple[bool, str]] = {}
_BCD_ALLOWED_VALUES: dict[str, tuple[str, ...]] = {
    "hypervisorlaunchtype": ("auto", "off"),
    "testsigning": ("yes", "no"),
    "nointegritychecks": ("yes", "no"),
    "vsmlaunchtype": ("auto", "off"),
}


def clear_bcd_cache() -> None:
    _BCD_CACHE.clear()


def run_bcdedit(*args: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["bcdedit", *args],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
    except FileNotFoundError:
        return False, "bcdedit not found -- is this a Windows system?"
    except OSError as exc:
        return False, str(exc)


def bcdedit_cached(cache_key: str, *args: str) -> tuple[bool, str]:
    if cache_key in _BCD_CACHE:
        return _BCD_CACHE[cache_key]
    ok, out = run_bcdedit(*args)
    _BCD_CACHE[cache_key] = (ok, out)
    return ok, out


def current_entry() -> tuple[bool, str, str]:
    ok, out = bcdedit_cached("bcd_current", "/enum", "{current}")
    if ok and out:
        return True, out, "{current}"
    return False, "", "{current}"


def read_value(key: str) -> str | None:
    ok, output, _ = current_entry()
    if not ok:
        return None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(key.lower()):
            parts = stripped.split(None, 1)
            return parts[1].strip().lower() if len(parts) == 2 else ""
    return None


def read_key_value(output: str, key: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(key.lower()):
            parts = stripped.split(None, 1)
            return parts[1].strip().lower() if len(parts) == 2 else ""
    return None


def all_entries() -> str:
    parts = []
    for args in (["{current}"], ["all"]):
        cache_key = "bcd_current" if args == ["{current}"] else "bcd_all"
        ok, out = bcdedit_cached(cache_key, "/enum", *args)
        if ok and out:
            parts.append(out)
    return "\n".join(parts)


def set_boot_value(key: str, value: str, pending_reasons: list[str]) -> tuple[bool, str]:
    key_norm = (key or "").strip().lower()
    value_norm = (value or "").strip().lower()

    allowed = _BCD_ALLOWED_VALUES.get(key_norm)
    if not allowed:
        return False, f"Refusing to set unsupported BCD key: {key}"
    if value_norm not in allowed:
        return False, f"Refusing to set unsupported value for {key_norm}: {value}"

    if pending_reasons:
        return False, (
            "Refusing to change boot configuration while Windows has a pending reboot state: "
            + ", ".join(pending_reasons)
        )

    ok_entry, _, token = current_entry()
    if not ok_entry:
        return False, "Could not resolve the current boot entry in the BCD store."

    return run_bcdedit("/set", token, key_norm, value_norm)


def format_bcdedit_failure(
    setting: str,
    value: str,
    raw_output: str,
    secure_boot_enabled: bool | None,
) -> str:
    detail = (raw_output or "").strip() or "Unknown bcdedit error."
    low = detail.lower()
    blocked_by_secure_boot = "secure boot" in low
    missing_entry = False

    if not blocked_by_secure_boot:
        if "access is denied" in low or "cannot be modified" in low or "protected" in low:
            blocked_by_secure_boot = secure_boot_enabled is True

    if (
        "entry specified" in low
        or "element not found" in low
        or "cannot find the file specified" in low
        or "arquivo especificado" in low
        or "entrada especificada" in low
    ):
        missing_entry = True

    if blocked_by_secure_boot:
        return (
            f"{setting}={value} failed.\n\n"
            "Secure Boot is blocking this boot setting from being changed.\n"
            "Disable Secure Boot in BIOS/UEFI, then run HyperSwitch again.\n\n"
            f"bcdedit: {detail}"
        )

    if missing_entry:
        return (
            f"{setting}={value} failed.\n\n"
            "Windows could not resolve the target boot entry in the BCD store.\n"
            "This usually means the machine is using a different loader alias than the default one.\n\n"
            f"bcdedit: {detail}"
        )

    return f"{setting}={value} failed.\n\nbcdedit: {detail}"


def split_status_detail(message: str) -> tuple[str, str]:
    if "\n\n" not in message:
        return message, ""
    summary, detail = message.split("\n\n", 1)
    return summary.strip(), detail.strip()


def status_error_title(message: str, fallback: str) -> str:
    if "Secure Boot is blocking this boot setting" in message:
        return "Secure Boot blocked boot configuration change"
    if "could not resolve the target boot entry" in message:
        return "Boot configuration entry not found"
    return fallback


def export_backup(tag: str, backup_root: str) -> tuple[bool, str]:
    path = f"{backup_root}\\{datetime.now().strftime('%Y%m%d-%H%M%S')}-{tag}.bcd"
    try:
        proc = subprocess.run(
            ["bcdedit", "/export", path],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        out = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0:
            return True, path
        return False, out or f"bcdedit /export failed for {path}"
    except OSError as exc:
        return False, str(exc)
