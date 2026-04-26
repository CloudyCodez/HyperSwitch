import subprocess

from .queries import get_cpu_vendor, powershell_bool, read_registry_dword


SPEC_REG_PATH = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
SPEC_OVERRIDE = "FeatureSettingsOverride"
SPEC_MASK = "FeatureSettingsOverrideMask"


def _spec_read_override_mask() -> tuple[int | None, int | None]:
    override = read_registry_dword(None, SPEC_REG_PATH, SPEC_OVERRIDE)
    mask = read_registry_dword(None, SPEC_REG_PATH, SPEC_MASK)
    return override, mask


def _spec_bit_disabled(bit: int, override: int | None, mask: int | None) -> bool:
    if override is None or mask is None:
        return False
    return bool((override & mask & bit) != 0)


def spec_ps_query(property_name: str) -> bool | None:
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"try {{ Import-Module SpeculationControl -EA Stop; "
                f"(Get-SpeculationControlSettings).{property_name} }} "
                f"catch {{ 'UNAVAILABLE' }}",
            ],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        value = proc.stdout.strip().splitlines()[0].lower() if proc.stdout.strip() else ""
        if value == "true":
            return True
        if value == "false":
            return False
        return None
    except Exception:
        return None


def meltdown_is_protected() -> bool | None:
    vendor = get_cpu_vendor()
    if vendor == "amd":
        return True

    override, mask = _spec_read_override_mask()
    if override is None and mask is None:
        return True

    if _spec_bit_disabled(0x02, override, mask):
        return False

    for property_name in ("KVAShadowWindowsSupportEnabled", "KVAShadowWindowsSupportPresent"):
        result = spec_ps_query(property_name)
        if result is not None:
            return result

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            SPEC_REG_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        override_value, _ = winreg.QueryValueEx(key, SPEC_OVERRIDE)
        mask_value, _ = winreg.QueryValueEx(key, SPEC_MASK)
        winreg.CloseKey(key)
        if isinstance(override_value, int) and isinstance(mask_value, int):
            if (override_value & mask_value & 0x02) != 0:
                return False
    except Exception:
        pass

    return True


def spectre_is_protected() -> bool | None:
    override, mask = _spec_read_override_mask()
    vendor = get_cpu_vendor()

    if override is None and mask is None:
        return True

    v2_disabled = _spec_bit_disabled(0x001, override, mask)
    v4_disabled = _spec_bit_disabled(0x100, override, mask)
    if v2_disabled or v4_disabled:
        return False

    if vendor == "intel":
        if _spec_bit_disabled(0x008, override, mask):
            return False
        if _spec_bit_disabled(0x010, override, mask):
            return False

    for property_name in (
        "BTIWindowsSupportEnabled",
        "SSBDWindowsSupportEnabled",
        "BTIWindowsSupportPresent",
    ):
        result = spec_ps_query(property_name)
        if result is not None:
            if not result:
                return False
            break

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            SPEC_REG_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        override_value, _ = winreg.QueryValueEx(key, SPEC_OVERRIDE)
        mask_value, _ = winreg.QueryValueEx(key, SPEC_MASK)
        winreg.CloseKey(key)
        if isinstance(override_value, int) and isinstance(mask_value, int):
            bits = 0x101 if vendor == "amd" else 0x11B
            if (override_value & mask_value & bits) != 0:
                return False
    except Exception:
        pass

    return True
