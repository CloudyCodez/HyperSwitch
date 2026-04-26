import ctypes
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import tkinter as tk
import zipfile
from tkinter import messagebox

from hyperswitch.bcd import (
    all_entries as _bcdedit_all_entries,
    clear_bcd_cache,
    current_entry as _bcdedit_current_entry,
    read_key_value as _bcd_key_value,
    read_value as _read_bcd_value,
    run_bcdedit as _bcdedit,
    status_error_title as _status_error_title,
)
from hyperswitch.features import (
    HELLO_CSP_ROOT as _HELLO_CSP_ROOT,
    HELLO_GPO_PATH as _HELLO_GPO_PATH,
    HELLO_GPO_VALUE as _HELLO_GPO_VALUE,
    HYPERV_PLATFORM_FEATURES as _HYPERV_PLATFORM_FEATURES,
    KSHADOW_PATH as _KSHADOW_PATH,
    VBS_POLICY_PATH as _VBS_POLICY_PATH,
    VBS_REG_PATH as _VBS_REG_PATH,
    VBS_REG_VALUE as _VBS_REG_VALUE,
    VBS_STATUS_PATH as _VBS_STATUS_PATH,
    VBS_STATUS_VALUE as _VBS_STATUS_VALUE,
    dse_is_enforced,
    dse_partial_enforcement as _dse_partial_enforcement,
    dse_set_enforced as _dse_set_enforced_raw,
    hyperv_driver_kind,
    hyperv_feature_enabled,
    hyperv_set as _hyperv_set_raw,
    hyperv_status,
    vbs_is_active,
    vbs_set as _vbs_set_raw,
)
from hyperswitch.metadata import APP_NAME, APP_VERSION, DEBUG_APP_NAME, ROADMAP_TARGET
from hyperswitch.mitigations import (
    SPEC_MASK as _SPEC_MASK,
    SPEC_OVERRIDE as _SPEC_OVERRIDE,
    SPEC_REG_PATH as _SPEC_REG_PATH,
    meltdown_is_protected,
    spec_ps_query as _spec_ps_query,
    spectre_is_protected,
)
from hyperswitch.platform import (
    DMA_POLICY_GPO_PATH as _DMA_POLICY_GPO_PATH,
    DMA_POLICY_PATH as _DMA_POLICY_PATH,
    DMA_POLICY_VALUE as _DMA_POLICY_VALUE,
    HVCI_PATH as _HVCI_PATH,
    HVCI_PATH_LEGACY as _HVCI_PATH_LEGACY,
    HVCI_POLICY_PATH as _HVCI_POLICY_PATH,
    HVCI_POLICY_VALUE as _HVCI_POLICY_VALUE,
    credential_guard_capability_reasons as _credential_guard_capability_reasons,
    cpu_virt_status,
    dep_available as _dep_available,
    dma_status,
    dma_support_available,
    edition_supports_credential_guard as _edition_supports_credential_guard,
    edition_supports_hyperv as _edition_supports_hyperv,
    hvci_status,
    hyperv_capability_reasons as _hyperv_capability_reasons,
    os_edition as _os_edition,
    pending_reboot_reasons as _pending_reboot_reasons,
    pending_reboot_text as _pending_reboot_text,
    processor_bool_property as _processor_bool_property,
    reg_subkey_has_entries as _reg_subkey_has_entries,
    secure_boot_enabled as _secure_boot_enabled,
    tpm_2_ready as _tpm_2_ready,
    uefi_firmware_present as _uefi_firmware_present,
    vbs_capability_reasons as _vbs_capability_reasons,
)
from hyperswitch.queries import (
    bitlocker_protection_on as _bitlocker_protection_on,
    clear_query_caches,
    credential_guard_configured as _credential_guard_configured_raw,
    credential_guard_status as _credential_guard_status,
    dism_feature_state as _dism_feature_state,
    get_cpu_vendor as _get_cpu_vendor,
    hello_csp_state as _hello_csp_state_raw,
    powershell_value as _powershell_value,
    prime_device_guard_cache as _prime_device_guard_cache,
    prime_platform_cache as _prime_platform_cache,
    prime_processor_cache as _prime_processor_cache,
    query_cpu_registry_value as _query_cpu_registry_value,
    query_kernel_ci_options as _query_kernel_ci_options,
    query_processor_value as _query_processor_value,
    query_wmi_device_guard as _query_wmi_device_guard,
    query_wmi_device_guard_list as _query_wmi_device_guard_list,
    read_registry_dword as _read_registry_dword,
    service_is_running as _service_is_running,
    windows_hello_present as _windows_hello_present,
    windows_hello_status as _windows_hello_status,
    wmic_property_value as _wmic_property_value,
)
from hyperswitch.runtime import (
    app_storage_dir as _app_storage_dir,
    backup_dir as _backup_dir,
    debug_report_path as _debug_report_path,
    is_debug_mode as _is_debug_mode,
    resource_path as _resource_path,
    state_file_path as _state_file_path,
)
from hyperswitch.ui import (
    ACCENT,
    AMBER,
    BG,
    BLUE,
    BORDER,
    CARD_EDGE,
    DIM,
    GRID,
    GREEN,
    MONO_HDR,
    MONO_LG,
    MONO_SM,
    MUTED,
    PANEL,
    PANEL_ALT,
    RED,
    ROSE,
    ToggleRow as _ToggleRow,
    WHITE,
    apply_window_icon as _apply_window_icon,
)


MASCOT_PATH = _resource_path("chibi-cloud-watermark.png")


def _handle_cli_flags() -> None:
    if "--version" in sys.argv:
        print(f"{APP_NAME} {APP_VERSION}")
        raise SystemExit(0)


# ---------------------------------------------------------------------------
# Privilege handling
# ---------------------------------------------------------------------------

def _running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _is_system() -> bool:
    try:
        import ctypes.wintypes
        TOKEN_QUERY      = 0x0008
        TokenUser        = 1
        WinLocalSystemSid = 22

        token = ctypes.wintypes.HANDLE()
        if not ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_QUERY, ctypes.byref(token)
        ):
            return False

        size = ctypes.wintypes.DWORD(0)
        ctypes.windll.advapi32.GetTokenInformation(
            token, TokenUser, None, 0, ctypes.byref(size)
        )
        buf = (ctypes.c_byte * size.value)()
        if not ctypes.windll.advapi32.GetTokenInformation(
            token, TokenUser, buf, size, ctypes.byref(size)
        ):
            ctypes.windll.kernel32.CloseHandle(token)
            return False

        ctypes.windll.kernel32.CloseHandle(token)

        system_sid = ctypes.c_void_p()
        if not ctypes.windll.advapi32.CreateWellKnownSid(
            WinLocalSystemSid, None, ctypes.byref(system_sid),
            ctypes.byref(ctypes.wintypes.DWORD(256))
        ):
            return False

        token_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return bool(ctypes.windll.advapi32.EqualSid(
            ctypes.c_void_p(token_sid), system_sid
        ))
    except Exception:
        return False


def _enable_debug_privileges() -> bool:
    try:
        import ctypes.wintypes

        SE_DEBUG_NAME          = "SeDebugPrivilege"
        SE_TCB_NAME            = "SeTcbPrivilege"
        SE_ASSIGNPRIMARYTOKEN  = "SeAssignPrimaryTokenPrivilege"
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY             = 0x0008
        SE_PRIVILEGE_ENABLED    = 0x00000002

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                        ("HighPart", ctypes.wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", ctypes.wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                        ("Privileges",     LUID_AND_ATTRIBUTES * 1)]

        token = ctypes.wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        )

        granted = False
        for priv_name in (SE_DEBUG_NAME, SE_TCB_NAME, SE_ASSIGNPRIMARYTOKEN):
            luid = LUID()
            if not ctypes.windll.advapi32.LookupPrivilegeValueW(
                None, priv_name, ctypes.byref(luid)
            ):
                continue
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount        = 1
            tp.Privileges[0].Luid   = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            ok = ctypes.windll.advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp),
                ctypes.sizeof(tp), None, None,
            )
            if ok and priv_name == SE_DEBUG_NAME:
                granted = True

        ctypes.windll.kernel32.CloseHandle(token)
        return granted
    except Exception:
        return False


def _relaunch_as_system() -> bool:
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
        else:
            exe = f'"{sys.executable}" "{os.path.abspath(__file__)}"'

        task = "HyperSwitch_Elevate"
        create = subprocess.run(
            [
                "schtasks", "/create", "/f",
                "/tn", task,
                "/sc", "once",
                "/st", "00:00",
                "/ru", "SYSTEM",
                "/tr", exe,
            ],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if create.returncode != 0:
            return False

        run = subprocess.run(
            ["schtasks", "/run", "/tn", task],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        subprocess.run(
            ["schtasks", "/delete", "/f", "/tn", task],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        return run.returncode == 0
    except Exception:
        return False


def _relaunch_elevated() -> None:
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = ""
    else:
        target = sys.executable
        params = os.path.abspath(__file__)

    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", target, params, None, 1
    )
    if ret > 32:
        sys.exit(0)

    if _running_as_admin():
        if _relaunch_as_system():
            sys.exit(0)

    _enable_debug_privileges()

    try:
        import tkinter as tk
        from tkinter import messagebox
        _root = tk.Tk()
        _root.withdraw()
        messagebox.showwarning(
            "Elevation Warning",
            "HyperSwitch could not obtain full administrator privileges.\n\n"
            "Some operations (bcdedit, registry writes) may fail.\n"
            "Try right-clicking the exe and selecting 'Run as administrator'.",
        )
        _root.destroy()
    except Exception:
        pass
_handle_cli_flags()

if not _running_as_admin():
    _relaunch_elevated()


# ---------------------------------------------------------------------------
# bcdedit interface
# ---------------------------------------------------------------------------

def _timestamp_slug() -> str:
    import datetime
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _export_bcd_backup(tag: str) -> tuple[bool, str]:
    path = os.path.join(_backup_dir(), f"{_timestamp_slug()}-{tag}.bcd")
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


def _export_registry_backup(tag: str, paths: tuple[str, ...]) -> tuple[list[str], list[str]]:
    exported: list[str] = []
    failures: list[str] = []
    stamp = _timestamp_slug()
    for index, path in enumerate(paths, start=1):
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", path)
        out_path = os.path.join(_backup_dir(), f"{stamp}-{tag}-{index:02d}-{safe_name}.reg")
        try:
            proc = subprocess.run(
                ["reg", "export", f"HKLM\\{path}", out_path, "/y"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if proc.returncode == 0:
                exported.append(out_path)
            else:
                failures.append(f"{path}: {(proc.stdout + proc.stderr).strip()}")
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    return exported, failures


def _load_tool_state() -> dict:
    path = _state_file_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _save_tool_state(data: dict) -> None:
    path = _state_file_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def _state_history_entries(data: dict) -> list[dict[str, str]]:
    history = data.get("history", [])
    if not isinstance(history, list):
        return []

    entries: list[dict[str, str]] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        when = str(item.get("when", "")).strip()
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        entries.append({"when": when, "text": text})
    return entries


# ---------------------------------------------------------------------------
# Feature state queries and setters
# ---------------------------------------------------------------------------

def _clear_caches() -> None:
    clear_query_caches()
    clear_bcd_cache()


def _collect_basic_snapshot() -> dict:
    _prime_platform_cache()
    _prime_device_guard_cache()
    _prime_processor_cache()
    dse = dse_is_enforced()
    return {
        "hyperv": hyperv_status(),
        "hyperv_feature": hyperv_feature_enabled(),
        "dse": dse,
        "dse_partial": _dse_partial_enforcement() if dse is False else [],
        "vbs": vbs_is_active(),
        "cpuvirt": cpu_virt_status(),
    }


def _collect_advanced_snapshot() -> dict:
    _prime_platform_cache()
    _prime_device_guard_cache()
    _prime_processor_cache()
    vendor = _get_cpu_vendor()
    return {
        "vendor": vendor,
        "credguard": credential_guard_status(),
        "bitlocker": _bitlocker_protection_on(),
        "secureboot": _secure_boot_enabled(),
        "hello": windows_hello_status(),
        "meltdown": None if vendor == "amd" else meltdown_is_protected(),
        "spectre": spectre_is_protected(),
    }


def hyperv_set(active: bool) -> tuple[bool, str]:
    return _hyperv_set_raw(active, _pending_reboot_reasons(), _secure_boot_enabled())


def dse_set_enforced(enforced: bool) -> tuple[bool, str]:
    return _dse_set_enforced_raw(enforced, _pending_reboot_reasons(), _secure_boot_enabled())


def vbs_set(active: bool) -> tuple[bool, str]:
    return _vbs_set_raw(active, _pending_reboot_reasons(), _secure_boot_enabled())


def _credential_guard_configured() -> bool | None:
    return _credential_guard_configured_raw(_VBS_POLICY_PATH)


def credential_guard_status() -> tuple[bool | None, bool | None]:
    return _credential_guard_status(_VBS_POLICY_PATH)


def _hello_csp_state() -> tuple[bool | None, str]:
    return _hello_csp_state_raw(_HELLO_CSP_ROOT)


def windows_hello_status() -> tuple[bool | None, str]:
    return _windows_hello_status(_HELLO_GPO_PATH, _HELLO_GPO_VALUE, _HELLO_CSP_ROOT)


def _first_reason(reasons: list[str]) -> str:
    return reasons[0] if reasons else ""


def _bcd_has_flag(output: str, flag: str) -> bool:
    for line in output.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith(flag.lower()):
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[1].strip() == "yes":
                return True
    return False


def _bcd_loadoptions_has(output: str, tokens: tuple[str, ...]) -> bool:
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("loadoptions"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        options = parts[1].strip().lower()
        for token in tokens:
            if token in options:
                return True
    return False


def _wmi_ci_enforced() -> bool | None:
    value = _query_wmi_device_guard("CodeIntegrityPolicyEnforcementStatus")
    if value is not None:
        return value >= 1
    return None


# ---------------------------------------------------------------------------
# Debug report
# ---------------------------------------------------------------------------
def _debug_bool(val: bool | None) -> str:
    if val is None:
        return "UNKNOWN"
    return "TRUE" if val else "FALSE"


def _bool_text(val: bool | None) -> str:
    if val is None:
        return "UNKNOWN"
    return "ON" if val else "OFF"


def _write_debug_report() -> None:
    _clear_caches()
    lines: list[str] = []

    lines.append(f"{APP_NAME} Debugger Report")
    lines.append("=" * 38)
    lines.append(f"Version: {APP_VERSION}")
    lines.append(f"Python: {sys.version}")
    lines.append(f"Executable: {sys.executable}")
    lines.append("")

    # Hyper-V
    runtime, configured = hyperv_status()
    lines.append("[HYPER-V]")
    lines.append(f"runtime_active: {_debug_bool(runtime)}")
    lines.append(f"configured_enabled: {_debug_bool(configured)}")
    lines.append(f"feature_installed: {_debug_bool(hyperv_feature_enabled())}")
    ok, bcd_cur, bcd_token = _bcdedit_current_entry()
    lines.append(f"bcd_current.entry: {bcd_token if ok else 'READ_FAIL'}")
    lines.append(f"bcd_current.hypervisorlaunchtype: {_bcd_key_value(bcd_cur, 'hypervisorlaunchtype') if ok else 'READ_FAIL'}")
    lines.append(f"wmi.SecurityServicesRunning: {_query_wmi_device_guard_list('SecurityServicesRunning')}")
    lines.append(f"wmi.SecurityServicesConfigured: {_query_wmi_device_guard_list('SecurityServicesConfigured')}")
    lines.append(f"reg.HypervisorRunning: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Status', 'HypervisorRunning')}")
    lines.append(f"reg.HypervisorPresent: {_read_registry_dword(None, r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization', 'HypervisorPresent')}")
    lines.append(f"cim.HypervisorPresent: {_powershell_value('(Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).HypervisorPresent')}")
    for feat in _HYPERV_PLATFORM_FEATURES:
        lines.append(f"feature.{feat}: {_dism_feature_state(feat)}")
    for svc in ("HvHost", "vmms", "HvSocket"):
        lines.append(f"svc.{svc}: {_debug_bool(_service_is_running(svc))}")
    lines.append("")

    # DSE
    lines.append("[DSE]")
    ci_opts = _query_kernel_ci_options()
    lines.append(f"kernel.CiOptions: {ci_opts}")
    ok, bcd_cur, _ = _bcdedit_current_entry()
    lines.append(f"bcd_current.testsigning: {_bcd_has_flag(bcd_cur, 'testsigning') if ok else 'READ_FAIL'}")
    lines.append(f"bcd_current.nointegritychecks: {_bcd_has_flag(bcd_cur, 'nointegritychecks') if ok else 'READ_FAIL'}")
    lines.append(f"bcd_current.loadoptions_has_disable: {_bcd_loadoptions_has(bcd_cur, ('testsigning','nointegritychecks','disable_integrity_checks','disableintegritychecks','ddisable_integrity_checks','ddisableintegritychecks')) if ok else 'READ_FAIL'}")
    lines.append(f"reg.CI\\Config.DisableIntegrityChecks: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\CI\\Config', 'DisableIntegrityChecks')}")
    lines.append(f"reg.CI\\Protected.DisableIntegrityChecks: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\CI\\Protected', 'DisableIntegrityChecks')}")
    lines.append(f"reg.CI.DisableIntegrityChecks: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\CI', 'DisableIntegrityChecks')}")
    lines.append(f"wmi.CodeIntegrityPolicyEnforcementStatus: {_wmi_ci_enforced()}")
    lines.append(f"computed.dse_is_enforced: {_debug_bool(dse_is_enforced())}")
    lines.append("")

    # VBS
    lines.append("[VBS]")
    lines.append(f"wmi.VirtualizationBasedSecurityStatus: {_query_wmi_device_guard('VirtualizationBasedSecurityStatus')}")
    lines.append(f"wmi.SecurityServicesRunning: {_query_wmi_device_guard_list('SecurityServicesRunning')}")
    lines.append(f"wmi.SecurityServicesConfigured: {_query_wmi_device_guard_list('SecurityServicesConfigured')}")
    lines.append(f"reg.DeviceGuard.EnableVBS: {_read_registry_dword(None, _VBS_REG_PATH, _VBS_REG_VALUE)}")
    lines.append(f"reg.DeviceGuard.WasEnabledBy: {_read_registry_dword(None, _VBS_REG_PATH, 'WasEnabledBy')}")
    lines.append(f"reg.DeviceGuard.Status.VBS: {_read_registry_dword(None, _VBS_STATUS_PATH, _VBS_STATUS_VALUE)}")
    lines.append(f"bcd_current.vsmlaunchtype: {_read_bcd_value('vsmlaunchtype')}")
    lines.append(f"Get-ComputerInfo.DeviceGuardVBS: {_powershell_value('[int](Get-ComputerInfo -EA SilentlyContinue).DeviceGuardVirtualizationBasedSecurityStatus')}")
    lines.append(f"policy.EnableVBS: {_read_registry_dword(None, _VBS_POLICY_PATH, 'EnableVirtualizationBasedSecurity')}")
    lines.append(f"policy.LsaCfgFlags: {_read_registry_dword(None, _VBS_POLICY_PATH, 'LsaCfgFlags')}")
    lines.append(f"reg.KernelShadowStacks.Enabled: {_read_registry_dword(None, _KSHADOW_PATH, 'Enabled')}")
    lines.append(f"reg.KernelShadowStacks.AuditModeEnabled: {_read_registry_dword(None, _KSHADOW_PATH, 'AuditModeEnabled')}")
    lines.append(f"computed.vbs_is_active: {_debug_bool(vbs_is_active())}")
    lines.append("")

    # HVCI
    lines.append("[HVCI]")
    rt, cfg = hvci_status()
    lines.append(f"runtime_active: {_debug_bool(rt)}")
    lines.append(f"configured_enabled: {_debug_bool(cfg)}")
    lines.append(f"kernel.CiOptions: {_query_kernel_ci_options()}")
    lines.append(f"wmi.SecurityServicesRunning: {_query_wmi_device_guard_list('SecurityServicesRunning')}")
    lines.append(f"wmi.SecurityServicesConfigured: {_query_wmi_device_guard_list('SecurityServicesConfigured')}")
    lines.append(f"wmi.HyperVisorEnforcedCodeIntegrityStatus: {_query_wmi_device_guard('HyperVisorEnforcedCodeIntegrityStatus')}")
    lines.append(f"reg.Status.HvciStatus: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Status', 'HvciStatus')}")
    for path, name in (
        (_HVCI_PATH, "Enabled"),
        (_HVCI_PATH, "WasEnabledBy"),
        (_HVCI_PATH_LEGACY, "Enabled"),
        (_HVCI_PATH_LEGACY, "WasEnabledBy"),
        (r'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HyperGuard\\Status', 'Enabled'),
        (r'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Status', 'Enabled'),
        (r'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks', 'Enabled'),
    ):
        lines.append(f"reg.{path}.{name}: {_read_registry_dword(None, path, name)}")
    lines.append(f"policy.HVCI: {_read_registry_dword(None, r'SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard', 'HypervisorEnforcedCodeIntegrity')}")
    lines.append("")

    # DMA
    lines.append("[DMA]")
    rt, pol = dma_status()
    lines.append(f"runtime_active: {_debug_bool(rt)}")
    lines.append(f"policy_enabled: {_debug_bool(pol)}")
    lines.append(f"support_available: {_debug_bool(dma_support_available())}")
    lines.append(f"wmi.KernelDmaProtectionEnabled: {_query_wmi_device_guard('KernelDmaProtectionEnabled')}")
    lines.append(f"wmi.AvailableSecurityProperties: {_query_wmi_device_guard_list('AvailableSecurityProperties')}")
    lines.append(f"wmi.RequiredSecurityProperties: {_query_wmi_device_guard_list('RequiredSecurityProperties')}")
    lines.append(f"reg.Default.HSTI: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\Default\\VerifiedBuses\\HSTI')}")
    lines.append(f"reg.Root.HSTI: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\VerifiedBuses\\HSTI')}")
    lines.append(f"reg.Default.AllowedBuses: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\Default\\AllowedBuses')}")
    lines.append(f"reg.Default.UnallowedBuses: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\Default\\UnallowedBuses')}")
    lines.append(f"reg.Root.AllowedBuses: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\AllowedBuses')}")
    lines.append(f"reg.Root.UnallowedBuses: {_reg_subkey_has_entries(r'SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\UnallowedBuses')}")
    lines.append(f"policy.System.DeviceEnumerationPolicy: {_read_registry_dword(None, _DMA_POLICY_PATH, _DMA_POLICY_VALUE)}")
    lines.append(f"policy.GPO.DeviceEnumerationPolicy: {_read_registry_dword(None, _DMA_POLICY_GPO_PATH, _DMA_POLICY_VALUE)}")
    lines.append("")

    # CPU
    lines.append("[CPU]")
    lines.append(f"cpu.detected_vendor: {_get_cpu_vendor()}")
    lines.append(f"cim.Manufacturer: {_query_processor_value('Manufacturer')}")
    lines.append(f"cim.Name: {_query_processor_value('Name')}")
    lines.append(f"cim.ProcessorId: {_query_processor_value('ProcessorId')}")
    lines.append(f"cim.Caption: {_query_processor_value('Caption')}")
    lines.append(f"cim.Description: {_query_processor_value('Description')}")
    lines.append(f"reg.VendorIdentifier: {_query_cpu_registry_value('VendorIdentifier')}")
    lines.append(f"reg.ProcessorNameString: {_query_cpu_registry_value('ProcessorNameString')}")
    lines.append(f"reg.Identifier: {_query_cpu_registry_value('Identifier')}")
    lines.append(f"cpu.is_amd_fx: {_debug_bool(_is_amd_fx_cpu())}")
    lines.append(f"os.EditionID: {_os_edition()}")
    lines.append("")

    # CPU Virtualization
    lines.append("[CPU VIRTUALIZATION]")
    lines.append(f"wmic.VirtualizationFirmwareEnabled: {_wmic_property_value('cpu', 'VirtualizationFirmwareEnabled')}")
    lines.append(f"cim.VirtualizationFirmwareEnabled: {_query_processor_value('VirtualizationFirmwareEnabled')}")
    lines.append(f"wmi.VirtualizationFirmwareEnabled: {_powershell_value('(Get-WmiObject Win32_Processor -EA SilentlyContinue).VirtualizationFirmwareEnabled')}")
    lines.append(f"cim.VMMonitorModeExtensions: {_query_processor_value('VMMonitorModeExtensions')}")
    lines.append(f"cim.SecondLevelAddressTranslationExtensions: {_query_processor_value('SecondLevelAddressTranslationExtensions')}")
    lines.append(f"computed.dep_available: {_debug_bool(_dep_available())}")
    lines.append(f"computerinfo.HyperVRequirementVirtualizationFirmwareEnabled: {_powershell_value('(Get-ComputerInfo -Property HyperVRequirementVirtualizationFirmwareEnabled -EA SilentlyContinue).HyperVRequirementVirtualizationFirmwareEnabled')}")
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            winreg.KEY_READ,
        )
        fs, _ = winreg.QueryValueEx(key, "FeatureSet")
        winreg.CloseKey(key)
    except Exception:
        fs = None
    lines.append(f"reg.FeatureSet: {fs}")
    try:
        pf = ctypes.windll.kernel32.IsProcessorFeaturePresent(ctypes.c_uint(21))
        lines.append(f"api.PF_VIRT_FIRMWARE_ENABLED(21): {pf}")
    except Exception:
        lines.append("api.PF_VIRT_FIRMWARE_ENABLED(21): ERROR")
    cpuvirt_state, cpuvirt_source = cpu_virt_status()
    lines.append(f"computed.cpu_virt_is_enabled: {_debug_bool(cpuvirt_state)}")
    lines.append(f"computed.cpu_virt_source: {cpuvirt_source}")
    lines.append("")

    lines.append("[COMPATIBILITY]")
    lines.append(f"uefi_present: {_debug_bool(_uefi_firmware_present())}")
    lines.append(f"secure_boot_enabled: {_debug_bool(_secure_boot_enabled())}")
    lines.append(f"tpm_2_ready: {_debug_bool(_tpm_2_ready())}")
    lines.append(f"edition_supports_hyperv: {_debug_bool(_edition_supports_hyperv())}")
    lines.append(f"edition_supports_credential_guard: {_debug_bool(_edition_supports_credential_guard())}")
    lines.append(f"pending_reboot_reasons: {', '.join(_pending_reboot_reasons()) or '(none)'}")
    lines.append(f"hyperv_compatibility_reasons: {', '.join(_hyperv_capability_reasons()) or '(none)'}")
    lines.append(f"vbs_compatibility_reasons: {', '.join(_vbs_capability_reasons()) or '(none)'}")
    lines.append(f"credential_guard_compatibility_reasons: {', '.join(_credential_guard_capability_reasons()) or '(none)'}")
    lines.append("")

    # Spectre/Meltdown
    lines.append("[SPECTRE/MELTDOWN]")
    lines.append(f"cpu.vendor: {_get_cpu_vendor()}")
    lines.append(f"spec.FeatureSettingsOverride: {_read_registry_dword(None, _SPEC_REG_PATH, _SPEC_OVERRIDE)}")
    lines.append(f"spec.FeatureSettingsOverrideMask: {_read_registry_dword(None, _SPEC_REG_PATH, _SPEC_MASK)}")
    lines.append(f"spec.Control.IBRS: {_spec_ps_query('BTIHardwarePresent')}")
    lines.append(f"spec.Control.IBPB: {_spec_ps_query('BTIWindowsSupportEnabled')}")
    lines.append(f"spec.Control.SSBD: {_spec_ps_query('SSBDWindowsSupportEnabled')}")
    lines.append("")

    # Credential Guard
    lines.append("[CREDENTIAL GUARD]")
    cg_runtime, cg_config = credential_guard_status()
    lines.append(f"runtime_active: {_debug_bool(cg_runtime)}")
    lines.append(f"configured_enabled: {_debug_bool(cg_config)}")
    lines.append(f"policy.LsaCfgFlags: {_read_registry_dword(None, _VBS_POLICY_PATH, 'LsaCfgFlags')}")
    lines.append(f"reg.Lsa.LsaCfgFlags: {_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LsaCfgFlags')}")
    lines.append(f"wmi.SecurityServicesRunning: {_query_wmi_device_guard_list('SecurityServicesRunning')}")
    lines.append(f"wmi.SecurityServicesConfigured: {_query_wmi_device_guard_list('SecurityServicesConfigured')}")
    lines.append(
        "cim.CredentialGuardRunning: "
        + _powershell_value(
            "try { "
            "$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA Stop; "
            "if ($null -eq $dg) { '' } else { [string]($dg.SecurityServicesRunning -contains 1) } "
            "} catch { '' }"
        )
    )
    lines.append("")

    # BitLocker
    lines.append("[BITLOCKER]")
    lines.append(f"protection_on: {_debug_bool(_bitlocker_protection_on())}")
    lines.append(
        "powershell.GetBitLockerVolume.ProtectionStatus: "
        + _powershell_value(
            "try { "
            "$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop; "
            "if ($null -eq $v) { '' } else { [string]$v.ProtectionStatus } "
            "} catch { '' }"
        )
    )
    lines.append(
        "cim.Win32_EncryptableVolume.ProtectionStatus: "
        + _powershell_value(
            "try { "
            "$vol = Get-CimInstance -Namespace 'Root/CIMV2/Security/MicrosoftVolumeEncryption' "
            "-ClassName Win32_EncryptableVolume -EA Stop | "
            "Where-Object { $_.DriveLetter -eq $env:SystemDrive } | Select-Object -First 1; "
            "if ($null -eq $vol) { '' } else { "
            "$r = Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus -EA Stop; "
            "[string]$r.ProtectionStatus } "
            "} catch { '' }"
        )
    )
    lines.append("")

    # Secure Boot
    lines.append("[SECURE BOOT]")
    lines.append(f"enabled: {_debug_bool(_secure_boot_enabled())}")
    lines.append(
        "reg.UEFISecureBootEnabled: "
        + str(_read_registry_dword(None, r'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 'UEFISecureBootEnabled'))
    )
    lines.append(
        "powershell.ConfirmSecureBootUEFI: "
        + _powershell_value("try { [string](Confirm-SecureBootUEFI) } catch { '' }")
    )
    lines.append("")

    # Windows Hello
    lines.append("[WINDOWS HELLO]")
    hello_allowed, hello_source = windows_hello_status()
    lines.append(f"provisioning_allowed: {_debug_bool(hello_allowed)}")
    lines.append(f"status_source: {hello_source}")
    lines.append(f"gpo.PassportForWork.Enabled: {_read_registry_dword(None, _HELLO_GPO_PATH, _HELLO_GPO_VALUE)}")
    lines.append(f"gpo.DisablePostLogonProvisioning: {_read_registry_dword(None, _HELLO_GPO_PATH, 'DisablePostLogonProvisioning')}")
    hello_csp_state, hello_csp_source = _hello_csp_state()
    lines.append(f"csp.UsePassportForWork: {_debug_bool(hello_csp_state)}")
    lines.append(f"csp.source: {hello_csp_source}")
    lines.append(f"signal.windows_hello_present: {_debug_bool(_windows_hello_present())}")
    lines.append("")

    # Raw command snapshots
    lines.append("[RAW COMMANDS]")
    lines.append(_debug_cmd("bcdedit /enum {current}", ["bcdedit", "/enum", "{current}"]))
    lines.append(_debug_cmd("bcdedit /enum {default}", ["bcdedit", "/enum", "{default}"]))
    lines.append(_debug_cmd("bcdedit /enum all", ["bcdedit", "/enum", "all"]))
    lines.append(_debug_cmd("systeminfo", ["systeminfo"]))
    lines.append(_debug_cmd("wmic cpu get Manufacturer,Name,VirtualizationFirmwareEnabled /value",
                            ["wmic", "cpu", "get", "Manufacturer,Name,VirtualizationFirmwareEnabled", "/value"]))
    lines.append(_debug_cmd(r"reg query HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                            ["reg", "query", r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0"]))
    lines.append(_debug_cmd("powershell Get-CimInstance Win32_Processor | fl Name,Manufacturer,ProcessorId,VirtualizationFirmwareEnabled,VMMonitorModeExtensions,SecondLevelAddressTranslationExtensions",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-CimInstance Win32_Processor -EA SilentlyContinue | Format-List Name,Manufacturer,ProcessorId,VirtualizationFirmwareEnabled,VMMonitorModeExtensions,SecondLevelAddressTranslationExtensions"]))
    lines.append(_debug_cmd("powershell Get-ComputerInfo | fl WindowsEditionId,BiosFirmwareType,HyperVRequirementVirtualizationFirmwareEnabled,HyperVRequirementSecondLevelAddressTranslation,HyperVRequirementDataExecutionPreventionAvailable",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-ComputerInfo -EA SilentlyContinue | Format-List WindowsEditionId,BiosFirmwareType,HyperVRequirementVirtualizationFirmwareEnabled,HyperVRequirementSecondLevelAddressTranslation,HyperVRequirementDataExecutionPreventionAvailable"]))
    lines.append(_debug_cmd("wmic computersystem get HypervisorPresent /value",
                            ["wmic", "computersystem", "get", "HypervisorPresent", "/value"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard /s",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard", "/s"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity /s",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\DmaSecurity", "/s"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI /s",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\CI", "/s"]))
    lines.append(_debug_cmd("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /s",
                            ["reg", "query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "/s"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                             "/v", "LsaCfgFlags"]))
    lines.append(_debug_cmd("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork /s",
                            ["reg", "query", r"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "/s"]))
    lines.append(_debug_cmd("reg query HKLM\\SOFTWARE\\Microsoft\\Policies\\PassportForWork /s",
                            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Policies\PassportForWork", "/s"]))
    lines.append(_debug_cmd("powershell Get-CimInstance Win32_DeviceGuard | fl *",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -EA SilentlyContinue | Format-List *"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State /v UEFISecureBootEnabled",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                             "/v", "UEFISecureBootEnabled"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management /v FeatureSettingsOverride",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                             "/v", "FeatureSettingsOverride"]))
    lines.append(_debug_cmd("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management /v FeatureSettingsOverrideMask",
                            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                             "/v", "FeatureSettingsOverrideMask"]))
    lines.append(_debug_cmd("powershell Get-BitLockerVolume -MountPoint $env:SystemDrive | fl *",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "Get-BitLockerVolume -MountPoint $env:SystemDrive -EA SilentlyContinue | Format-List *"]))
    lines.append(_debug_cmd("manage-bde -status %SystemDrive%",
                            ["manage-bde", "-status", os.getenv("SystemDrive", "C:")]))
    lines.append(_debug_cmd("powershell Confirm-SecureBootUEFI",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "try { Confirm-SecureBootUEFI } catch { $_ }"]))
    lines.append(_debug_cmd("powershell Get-Tpm",
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             "try { Get-Tpm | Format-List * } catch { $_ }"]))
    lines.append("")

    # msinfo32 snapshot (filtered)
    msinfo = _msinfo_summary()
    lines.append("[MSINFO32 SUMMARY]")
    lines.extend(msinfo.splitlines() if msinfo else ["(msinfo32 report unavailable)"])
    lines.append("")

    path = _debug_report_path()
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def _debug_cmd(label: str, cmd: list[str], timeout_ms: int = 20000) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=timeout_ms / 1000,
        )
        out = (proc.stdout + proc.stderr).strip()
        return f"{label}\n{out if out else '(no output)'}\n"
    except Exception as exc:
        return f"{label}\nERROR: {exc}\n"


def _msinfo_summary() -> str:
    try:
        tmp = os.path.join(os.getenv("TEMP", "."), "hyperswitch_msinfo.txt")
        proc = subprocess.run(
            ["msinfo32", "/report", tmp],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=60,
        )
        if proc.returncode != 0 or not os.path.exists(tmp):
            return ""
        with open(tmp, "r", encoding="utf-16", errors="replace") as f:
            raw = f.read()
        keys = (
            "Kernel DMA Protection",
            "Virtualization-based Security",
            "Device Guard",
            "Hyper-V",
            "Hypervisor",
        )
        lines = []
        for line in raw.splitlines():
            if any(k in line for k in keys):
                lines.append(line.strip())
        return "\n".join(lines)
    except Exception:
        return ""


def _run_debug_gui() -> None:
    try:
        root = tk.Tk()
        root.title(DEBUG_APP_NAME)
        _apply_window_icon(root)
        root.configure(bg=BG)
        root.resizable(False, False)
        status = tk.StringVar(value="Starting debug scan...")

        tk.Label(
            root,
            text=f"{APP_NAME} Debugger",
            font=MONO_HDR,
            fg=WHITE,
            bg=BG,
        ).pack(padx=16, pady=(14, 6))

        tk.Label(
            root,
            textvariable=status,
            font=MONO_SM,
            fg=MUTED,
            bg=BG,
        ).pack(padx=16, pady=(0, 14))

        root.update_idletasks()

        def step(msg: str) -> None:
            status.set(msg)
            root.update_idletasks()
            root.update()

        step("Collecting system data...")
        _write_debug_report()
        step("Writing debugger.txt...")
        messagebox.showinfo(
            "Debugger Complete",
            f"Report saved to:\n{_debug_report_path()}",
            parent=root,
        )
        root.destroy()
    except Exception:
        _write_debug_report()


def _support_bundle_dir() -> str:
    folder = os.path.join(_app_storage_dir(), "support")
    os.makedirs(folder, exist_ok=True)
    return folder


def _recent_backup_paths(limit: int = 12) -> list[str]:
    try:
        root = _backup_dir()
        entries = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            entries.append((os.path.getmtime(path), path))
        entries.sort(reverse=True)
        return [path for _, path in entries[:limit]]
    except Exception:
        return []


def _recent_support_bundle_paths(limit: int = 12) -> list[str]:
    try:
        root = _support_bundle_dir()
        entries = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            entries.append((os.path.getmtime(path), path))
        entries.sort(reverse=True)
        return [path for _, path in entries[:limit]]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Reboot helper
# ---------------------------------------------------------------------------

def schedule_reboot(delay_seconds: int = 5) -> None:
    subprocess.run(
        [
            "shutdown", "/r",
            "/t", str(delay_seconds),
            "/c", f"{APP_NAME}: restarting in {delay_seconds} seconds",
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    BASE_W = 860
    BASE_H = 880

    def __init__(self) -> None:
        super().__init__()

        self._tool_state = _load_tool_state()
        self.title(f"{APP_NAME} {APP_VERSION}")
        _apply_window_icon(self)
        self.configure(bg=BG)
        self.option_add("*Menu.background", PANEL_ALT)
        self.option_add("*Menu.foreground", WHITE)
        self.option_add("*Menu.activeBackground", "#1b2633")
        self.option_add("*Menu.activeForeground", WHITE)

        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()

        max_w = int(screen_w * 0.90)
        max_h = int(screen_h * 0.90)

        win_w = min(self.BASE_W, max_w)
        win_h = min(self.BASE_H, max_h)

        self.resizable(True, True)
        self.minsize(760, 560)

        saved_mode = self._tool_state.get("preferred_mode", "Basic")
        if saved_mode not in ("Basic", "Advanced"):
            saved_mode = "Basic"

        self._mode_var = tk.StringVar(value=saved_mode)
        self._last_mode = saved_mode
        self._mascot_photo = None
        self._build_ui()
        self._center(win_w, win_h)
        self._refresh_worker = None
        self._refresh_pending = False
        self._advanced_refresh_worker = None
        self._advanced_refresh_pending = False
        self._last_vbs = None
        self._last_hyperv_feature = None
        self._last_dse_partial = []
        self._basic_change_pending = False
        self._history_cache = _state_history_entries(self._tool_state)
        self._record_activity("Session started.")
        self._append_log("[SESSION] Ready.")
        self._refresh_all_async()

    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------

    def _ask_two_option_dialog(
        self,
        title: str,
        message: str,
        confirm_text: str,
        cancel_text: str,
    ) -> bool:
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        choice = {"value": False}

        def close_with(value: bool) -> None:
            choice["value"] = value
            dialog.destroy()

        body = tk.Frame(dialog, bg=BG, padx=20, pady=18)
        body.pack(fill="both", expand=True)

        tk.Label(
            body,
            text=message,
            justify="left",
            anchor="w",
            font=MONO_SM,
            fg=WHITE,
            bg=BG,
            wraplength=420,
        ).pack(fill="x")

        button_row = tk.Frame(body, bg=BG)
        button_row.pack(fill="x", pady=(16, 0))

        tk.Button(
            button_row,
            text=confirm_text,
            command=lambda: close_with(True),
            font=("Consolas", 10, "bold"),
            fg=WHITE,
            bg="#1b2633",
            activeforeground=WHITE,
            activebackground="#243246",
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="right")

        tk.Button(
            button_row,
            text=cancel_text,
            command=lambda: close_with(False),
            font=("Consolas", 10, "bold"),
            fg=WHITE,
            bg=PANEL_ALT,
            activeforeground=WHITE,
            activebackground="#1b2633",
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            cursor="hand2",
        ).pack(side="right", padx=(0, 10))

        dialog.protocol("WM_DELETE_WINDOW", lambda: close_with(False))
        dialog.bind("<Escape>", lambda _event: close_with(False))
        dialog.bind("<Return>", lambda _event: close_with(True))

        dialog.update_idletasks()
        width = dialog.winfo_reqwidth()
        height = dialog.winfo_reqheight()
        x = self.winfo_rootx() + max((self.winfo_width() - width) // 2, 0)
        y = self.winfo_rooty() + max((self.winfo_height() - height) // 2, 0)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        self.wait_window(dialog)
        return choice["value"]

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x", side="top")
        tk.Frame(self, bg=GRID, height=18).pack(fill="x", side="top")
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=20, pady=(10, 0))

        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left", fill="x", expand=True)

        brand_top = tk.Frame(brand, bg=BG)
        brand_top.pack(anchor="w")

        tk.Label(
            brand_top, text="HYPERSWITCH",
            font=MONO_HDR, fg=WHITE, bg=BG,
        ).pack(side="left")

        tk.Label(
            brand_top,
            text=f"  {APP_VERSION.upper()}",
            font=("Consolas", 8, "bold"),
            fg=ACCENT,
            bg="#0f2024",
            padx=7,
            pady=2,
            highlightthickness=1,
            highlightbackground="#24545a",
        ).pack(side="left", padx=(10, 0), pady=(3, 0))

        tk.Label(
            brand,
            text="operator console for Hyper-V, DSE, and VBS   |   BCD-first safety mode",
            font=MONO_SM, fg=MUTED, bg=BG,
        ).pack(anchor="w", pady=(4, 0))

        header_right = tk.Frame(header, bg=BG)
        header_right.pack(side="right")

        mode_wrap = tk.Frame(header_right, bg=BG)
        mode_wrap.pack(side="right")

        tk.Label(
            mode_wrap,
            text="VIEW",
            font=MONO_SM,
            fg=MUTED,
            bg=BG,
        ).pack(side="left", padx=(0, 8), pady=(5, 0))

        self._mode_menu = tk.OptionMenu(
            mode_wrap,
            self._mode_var,
            "Basic",
            "Advanced",
            command=self._on_mode_changed,
        )
        self._mode_menu.config(
            font=("Consolas", 9, "bold"),
            fg=WHITE,
            bg=PANEL_ALT,
            activeforeground=WHITE,
            activebackground="#1b2633",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=CARD_EDGE,
            width=9,
        )
        self._mode_menu["menu"].config(
            font=MONO_SM,
            fg=WHITE,
            bg=PANEL_ALT,
            activeforeground=WHITE,
            activebackground="#1b2633",
            bd=0,
        )
        self._mode_menu.pack(side="left")

        if os.path.exists(MASCOT_PATH):
            try:
                mascot = tk.PhotoImage(file=MASCOT_PATH)
                factor = max(1, int(max(mascot.width() / 86, mascot.height() / 72)))
                self._mascot_photo = mascot.subsample(factor, factor)
            except Exception:
                self._mascot_photo = None

        if self._mascot_photo is not None:
            mascot_frame = tk.Frame(
                header_right,
                bg=PANEL_ALT,
                highlightthickness=1,
                highlightbackground=CARD_EDGE,
                padx=8,
                pady=6,
            )
            mascot_frame.pack(side="right", padx=(0, 14))
            tk.Label(
                mascot_frame,
                image=self._mascot_photo,
                bg=PANEL_ALT,
            ).pack()

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(12, 8))

        self._mode_hint = tk.Label(
            self,
            text="",
            font=MONO_SM,
            fg=AMBER,
            bg=PANEL_ALT,
            anchor="w",
            justify="left",
            wraplength=780,
            padx=10,
            pady=8,
            highlightthickness=1,
            highlightbackground="#4a3b0f",
        )
        self._mode_hint.pack(fill="x", padx=20, pady=(0, 6))

        footer = tk.Frame(self, bg=BG)
        footer.pack(side="bottom", fill="x", padx=20, pady=(6, 12))

        footer_left = tk.Frame(footer, bg=BG)
        footer_left.pack(side="left", fill="x", expand=True)

        footer_right = tk.Frame(footer, bg=BG)
        footer_right.pack(side="right")

        tk.Label(
            footer_left,
            text="BCD changes land on the next restart   |   F1 help   |   F2 product notes",
            font=MONO_SM, fg=MUTED, bg=BG,
        ).pack(side="left", padx=(8, 0))

        sig = tk.Frame(footer_right, bg=BG)
        sig.pack(side="right")

        tk.Label(
            footer_right,
            text=f"ROADMAP {ROADMAP_TARGET}",
            font=("Consolas", 8, "bold"),
            fg=ACCENT,
            bg="#0f2024",
            padx=7,
            pady=2,
            highlightthickness=1,
            highlightbackground="#24545a",
        ).pack(side="right", padx=(0, 12))

        tk.Label(
            sig,
            text="Cloud",
            font=("Consolas", 10, "italic"),
            fg=BLUE, bg=BG,
        ).pack(side="left")

        tk.Label(
            sig,
            text=" & ",
            font=("Consolas", 9, "italic"),
            fg=DIM, bg=BG,
        ).pack(side="left")

        tk.Label(
            sig,
            text="Lock",
            font=("Consolas", 10, "italic"),
            fg=ROSE, bg=BG,
        ).pack(side="left")

        tk.Button(
            footer_right,
            text="ACTIVITY",
            font=("Consolas", 9, "bold"),
            fg=WHITE, bg="#16202c",
            activeforeground=WHITE,
            activebackground="#1d2c3d",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#334155",
            padx=10, pady=3,
            command=self._show_activity_center,
        ).pack(side="right", padx=(0, 10))

        tk.Button(
            footer_right,
            text="OPEN BACKUPS",
            font=("Consolas", 9, "bold"),
            fg=BLUE, bg="#101a28",
            activeforeground=BLUE,
            activebackground="#152235",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#274766",
            padx=10, pady=3,
            command=self._open_backup_folder,
        ).pack(side="right", padx=(0, 10))

        tk.Button(
            footer_right,
            text="COPY SUMMARY",
            font=("Consolas", 9, "bold"),
            fg=ACCENT, bg="#102123",
            activeforeground=ACCENT,
            activebackground="#173136",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#24545a",
            padx=10, pady=3,
            command=self._copy_summary,
        ).pack(side="right", padx=(0, 10))

        tk.Button(
            footer_right,
            text="EXPORT SUPPORT",
            font=("Consolas", 9, "bold"),
            fg=GREEN, bg="#062118",
            activeforeground=GREEN,
            activebackground="#0a3023",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#0d5f46",
            padx=10, pady=3,
            command=self._export_support_bundle,
        ).pack(side="right", padx=(0, 10))

        tk.Button(
            footer_right,
            text="PATCHGUARD INFO",
            font=("Consolas", 9, "bold"),
            fg=AMBER, bg="#241900",
            activeforeground=AMBER,
            activebackground="#3a2a00",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#6e5600",
            padx=10, pady=3,
            command=self._show_patchguard_info,
        ).pack(side="right", padx=(0, 10))

        tk.Button(
            self,
            text="RESTART TO APPLY",
            font=("Consolas", 10, "bold"),
            fg=AMBER, bg="#241900",
            activeforeground=AMBER,
            activebackground="#3a2a00",
            relief="flat", bd=0,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground="#6e5600",
            padx=12, pady=9,
            command=self._confirm_reboot,
        ).pack(side="bottom", fill="x", padx=20, pady=(0, 6))

        log_border = tk.Frame(
            self, bg=PANEL,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        log_border.pack(side="bottom", fill="x", padx=20, pady=(0, 4))

        self._log = tk.Text(
            log_border,
            height=4, bg=PANEL, fg=DIM,
            font=MONO_SM, relief="flat",
            state="disabled", wrap="word",
            padx=8, pady=6,
            insertbackground=WHITE,
            selectbackground="#2a2a2a",
        )
        self._log.pack(fill="both", expand=False)

        tk.Frame(self, bg=BORDER, height=1).pack(
            side="bottom", fill="x", padx=20, pady=(4, 0))

        canvas_frame = tk.Frame(self, bg=BG)
        canvas_frame.pack(fill="both", expand=True, padx=0, pady=0)

        self._canvas = tk.Canvas(
            canvas_frame, bg=BG, bd=0,
            highlightthickness=0,
            yscrollincrement=1,
        )
        scrollbar = tk.Scrollbar(
            canvas_frame, orient="vertical",
            command=self._canvas.yview,
            bg=BG, troughcolor=PANEL, relief="flat",
        )
        self._canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._scroll_frame = tk.Frame(self._canvas, bg=BG)
        self._canvas_window = self._canvas.create_window(
            (0, 0), window=self._scroll_frame, anchor="nw"
        )

        self._canvas.bind("<Configure>", self._on_canvas_resize)
        self._scroll_frame.bind("<Configure>", self._on_inner_resize)

        self._canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        row_parent = self._scroll_frame

        self._row_hv = _ToggleRow(
            row_parent,
            title="HYPER-V",
            on_toggle=self._toggle_hyperv,
        )
        self._row_dse = _ToggleRow(
            row_parent,
            title="DRIVER SIGNATURE ENFORCEMENT",
            on_toggle=self._toggle_dse,
        )
        self._row_vbs = _ToggleRow(
            row_parent,
            title="VBS  (Virtualization Based Security)",
            on_toggle=self._toggle_vbs,
        )
        self._row_cpuvirt = _ToggleRow(
            row_parent,
            title="CPU VIRTUALIZATION  (VT-x / AMD-V)",
            on_toggle=self._toggle_cpuvirt,
        )
        self._row_meltdown = _ToggleRow(
            row_parent,
            title="MELTDOWN PROTECTION  (KVA Shadow)",
            on_toggle=self._toggle_meltdown,
        )
        self._row_spectre = _ToggleRow(
            row_parent,
            title="SPECTRE PROTECTION  (IBRS / SSBD)",
            on_toggle=self._toggle_spectre,
        )
        self._row_credguard = _ToggleRow(
            row_parent,
            title="CREDENTIAL GUARD  (LSA)",
            on_toggle=self._toggle_credguard,
        )
        self._row_bitlocker = _ToggleRow(
            row_parent,
            title="BITLOCKER  (SYSTEM DRIVE)",
            on_toggle=self._toggle_bitlocker,
        )
        self._row_secureboot = _ToggleRow(
            row_parent,
            title="SECURE BOOT",
            on_toggle=self._toggle_secureboot,
        )
        self._row_hello = _ToggleRow(
            row_parent,
            title="WINDOWS HELLO  (PROVISIONING)",
            on_toggle=self._toggle_windows_hello,
        )

        self._basic_rows = (
            self._row_hv,
            self._row_dse,
            self._row_vbs,
            self._row_cpuvirt,
        )
        self._advanced_rows = (
            self._row_meltdown,
            self._row_spectre,
            self._row_credguard,
            self._row_bitlocker,
            self._row_secureboot,
            self._row_hello,
        )
        self._apply_mode()

    # ------------------------------------------------------------------
    # Canvas scroll helpers
    # ------------------------------------------------------------------

    def _on_canvas_resize(self, event: tk.Event) -> None:
        self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _on_inner_resize(self, event: tk.Event) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_mousewheel(self, event: tk.Event) -> None:
        self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _center(self, win_w: int, win_h: int) -> None:
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - win_w) // 2
        y = (self.winfo_screenheight() - win_h) // 2
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")

    # ------------------------------------------------------------------
    # State refresh
    # ------------------------------------------------------------------

    def _refresh_all(self) -> None:
        self._refresh_all_async()

    def _refresh_all_async(self) -> None:
        if self._refresh_worker and self._refresh_worker.is_alive():
            self._refresh_pending = True
            return

        include_advanced = not self._basic_mode()

        def worker():
            _clear_caches()
            data = {}
            try:
                data.update(_collect_basic_snapshot())
                if include_advanced:
                    data.update(_collect_advanced_snapshot())
            except Exception:
                pass

            def apply():
                try:
                    self._apply_snapshot(data)
                    if not include_advanced and not self._basic_mode():
                        self._refresh_advanced_async()
                finally:
                    if self._refresh_pending:
                        self._refresh_pending = False
                        self._refresh_all_async()

            self.after(0, apply)

        self._refresh_worker = threading.Thread(target=worker, daemon=True)
        self._refresh_worker.start()

    def _apply_snapshot(self, data: dict) -> None:
        self._last_vbs = data.get("vbs", None)
        self._last_hyperv_feature = data.get("hyperv_feature", None)
        self._last_dse_partial = data.get("dse_partial", [])
        try:
            runtime, configured = data.get("hyperv", (None, None))
            self._apply_hyperv(runtime, configured)
        except Exception:
            self._refresh_hyperv()
        try:
            self._apply_dse(data.get("dse", None), data.get("dse_partial", []))
        except Exception:
            self._refresh_dse()
        try:
            self._apply_vbs(data.get("vbs", None))
        except Exception:
            self._refresh_vbs()
        try:
            cpuvirt_state, cpuvirt_source = data.get("cpuvirt", (None, ""))
            self._apply_cpuvirt(cpuvirt_state, cpuvirt_source)
        except Exception:
            self._refresh_cpuvirt()
        if "vendor" in data:
            try:
                vendor = data.get("vendor", "unknown")
                self._apply_meltdown(vendor, data.get("meltdown", None))
                self._apply_spectre(vendor, data.get("spectre", None))
                runtime, configured = data.get("credguard", (None, None))
                self._apply_credguard(runtime, configured)
                self._apply_bitlocker(data.get("bitlocker", None))
                self._apply_secureboot(data.get("secureboot", None))
                allowed, source = data.get("hello", (None, ""))
                self._apply_windows_hello(allowed, source)
            except Exception:
                self._refresh_advanced_async()

    def _refresh_advanced_async(self) -> None:
        if self._basic_mode():
            return
        if self._advanced_refresh_worker and self._advanced_refresh_worker.is_alive():
            self._advanced_refresh_pending = True
            return

        def worker():
            _clear_caches()
            data = {}
            try:
                data.update(_collect_advanced_snapshot())
            except Exception:
                pass

            def apply():
                try:
                    vendor = data.get("vendor", "unknown")
                    self._apply_meltdown(vendor, data.get("meltdown", None))
                    self._apply_spectre(vendor, data.get("spectre", None))
                    runtime, configured = data.get("credguard", (None, None))
                    self._apply_credguard(runtime, configured)
                    self._apply_bitlocker(data.get("bitlocker", None))
                    self._apply_secureboot(data.get("secureboot", None))
                    allowed, source = data.get("hello", (None, ""))
                    self._apply_windows_hello(allowed, source)
                finally:
                    if self._advanced_refresh_pending:
                        self._advanced_refresh_pending = False
                        self._refresh_advanced_async()

            self.after(0, apply)

        self._advanced_refresh_worker = threading.Thread(target=worker, daemon=True)
        self._advanced_refresh_worker.start()

    def _btn_style_enable(self) -> tuple[str, str, str, str]:
        return (GREEN, "#04291f", "#08392c", "#0a6b53")

    def _btn_style_disable(self) -> tuple[str, str, str, str]:
        return (RED, "#2a0b16", "#40101f", "#7f1d39")

    def _apply_pending_row(
        self,
        row: _ToggleRow,
        runtime: bool | None,
        configured: bool | None,
        active_label: str,
        inactive_label: str,
        btn_active: str,
        btn_inactive: str,
        pending_enable_label: str,
        pending_disable_label: str,
        configured_enable_label: str,
        configured_disable_label: str,
    ) -> None:
        if runtime is True:
            if configured is False:
                fg, bg, abg, hb = self._btn_style_enable()
                row.update_custom(
                    status_text=f"\u25d0  {pending_disable_label}",
                    status_fg=AMBER,
                    btn_text=btn_inactive,
                    btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                    active_state=False,
                )
                return
            row.update(
                True,
                active_label=active_label,
                inactive_label=inactive_label,
                btn_when_active=btn_active,
                btn_when_inactive=btn_inactive,
            )
            return

        if runtime is False:
            if configured is True:
                fg, bg, abg, hb = self._btn_style_disable()
                row.update_custom(
                    status_text=f"\u25d0  {pending_enable_label}",
                    status_fg=AMBER,
                    btn_text=btn_active,
                    btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                    active_state=True,
                )
                return
            row.update(
                False,
                active_label=active_label,
                inactive_label=inactive_label,
                btn_when_active=btn_active,
                btn_when_inactive=btn_inactive,
            )
            return

        if configured is True:
            fg, bg, abg, hb = self._btn_style_disable()
            row.update_custom(
                status_text=f"\u25d0  {configured_enable_label}",
                status_fg=AMBER,
                btn_text=btn_active,
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=True,
            )
            return
        if configured is False:
            fg, bg, abg, hb = self._btn_style_enable()
            row.update_custom(
                status_text=f"\u25d0  {configured_disable_label}",
                status_fg=AMBER,
                btn_text=btn_inactive,
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=False,
            )
            return

        row.update(
            None,
            active_label=active_label,
            inactive_label=inactive_label,
            btn_when_active=btn_active,
            btn_when_inactive=btn_inactive,
        )

    def _refresh_hyperv(self) -> None:
        runtime, configured = hyperv_status()
        self._apply_hyperv(runtime, configured)

    def _apply_hyperv(self, runtime: bool | None, configured: bool | None) -> None:
        self._apply_pending_row(
            self._row_hv,
            runtime,
            configured,
            active_label="ACTIVATED",
            inactive_label="DEACTIVATED",
            btn_active="DEACTIVATE",
            btn_inactive="ACTIVATE",
            pending_enable_label="ACTIVATED  (PENDING REBOOT)",
            pending_disable_label="ACTIVATED  (PENDING DISABLE)",
            configured_enable_label="ACTIVATED  (CONFIGURED)",
            configured_disable_label="DEACTIVATED  (CONFIGURED)",
        )
        if self._basic_mode():
            self._row_hv.set_subtitle("")
            self._row_hv._btn.config(state="normal", cursor="hand2")
            return
        kind = hyperv_driver_kind(runtime, configured, self._last_vbs)
        feature = self._last_hyperv_feature
        if feature is None:
            feat_text = "UNKNOWN"
        else:
            feat_text = "ON" if feature else "OFF"
        subtitle_parts = [
            f"RUNTIME: {_bool_text(runtime)}",
            f"CONFIG: {_bool_text(configured)}",
            f"DRIVER: {kind}",
            f"FEATURE: {feat_text}",
        ]
        reasons = _hyperv_capability_reasons()
        if reasons and runtime is not True and configured is not True:
            subtitle_parts.append("CHECK: " + _first_reason(reasons))
        else:
            if _is_amd_fx_cpu():
                subtitle_parts.append("AMD FX: CAPABILITY CHECKS APPLY")
        pending = _pending_reboot_text()
        if pending:
            subtitle_parts.append(pending)
        self._row_hv._btn.config(state="normal", cursor="hand2")
        self._row_hv.set_subtitle("   |   ".join(subtitle_parts))

    def _refresh_dse(self) -> None:
        enforced = dse_is_enforced()
        partial = _dse_partial_enforcement() if enforced is False else []
        self._apply_dse(enforced, partial)

    def _apply_dse(self, enforced: bool | None, partial: list[str] | None = None) -> None:
        self._row_dse.update(
            enforced,
            active_label="ENFORCED",
            inactive_label="DISABLED",
            btn_when_active="DISABLE DSE",
            btn_when_inactive="ENABLE DSE",
        )
        if self._basic_mode():
            self._row_dse.set_subtitle("")
            return
        partial = partial or []
        subtitle_parts: list[str] = [f"RUNTIME: {_bool_text(enforced)}"]
        if enforced is False and partial:
            subtitle_parts.append("OTHER ENFORCERS: " + ", ".join(partial))
        pending = _pending_reboot_text()
        if pending:
            subtitle_parts.append(pending)
        self._row_dse.set_subtitle("   |   ".join(subtitle_parts) if subtitle_parts else "")

    def _refresh_vbs(self) -> None:
        active = vbs_is_active()
        self._apply_vbs(active)

    def _apply_vbs(self, active: bool | None) -> None:
        self._last_vbs = active
        self._row_vbs.update(
            active,
            active_label="ACTIVATED",
            inactive_label="DEACTIVATED",
            btn_when_active="DEACTIVATE",
            btn_when_inactive="ACTIVATE",
        )
        if self._basic_mode():
            self._row_vbs.set_subtitle("")
            self._row_vbs._btn.config(state="normal", cursor="hand2")
            return
        subtitle_parts = [f"RUNTIME: {_bool_text(active)}"]
        reasons = _vbs_capability_reasons()
        if reasons and active is not True:
            subtitle_parts.append("CHECK: " + _first_reason(reasons))
        else:
            if _is_amd_fx_cpu():
                subtitle_parts.append("AMD FX: VBS-family changes stay guarded on this platform")
        pending = _pending_reboot_text()
        if pending:
            subtitle_parts.append(pending)
        self._row_vbs.set_subtitle("   |   ".join(subtitle_parts))
        self._row_vbs._btn.config(state="normal", cursor="hand2")

    def _refresh_hvci(self) -> None:
        runtime, configured = hvci_status()
        self._apply_hvci(runtime, configured)

    def _apply_hvci(self, runtime: bool | None, configured: bool | None) -> None:
        self._apply_pending_row(
            self._row_hvci,
            runtime,
            configured,
            active_label="ENABLED  (ACTIVE)",
            inactive_label="DISABLED",
            btn_active="DISABLE",
            btn_inactive="ENABLE",
            pending_enable_label="ENABLED  (PENDING REBOOT)",
            pending_disable_label="ENABLED  (PENDING DISABLE)",
            configured_enable_label="ENABLED  (CONFIGURED)",
            configured_disable_label="DISABLED  (CONFIGURED)",
        )
        self._row_hvci.set_subtitle(
            f"RUNTIME: {_bool_text(runtime)}   |   CONFIG: {_bool_text(configured)}"
        )

    def _refresh_dma(self) -> None:
        runtime, policy = dma_status()
        support = dma_support_available()
        self._apply_dma(runtime, policy, support)

    def _apply_dma(
        self,
        runtime: bool | None,
        policy: bool | None,
        support: bool | None = None,
    ) -> None:
        self._last_dma_support = support
        if support is None:
            support_text = "UNKNOWN"
        else:
            support_text = "YES" if support else "NO"
        subtitle = (
            f"RUNTIME: {_bool_text(runtime)}   |   "
            f"POLICY: {_bool_text(policy)}   |   "
            f"SUPPORT: {support_text}"
        )
        self._row_dma.set_subtitle(subtitle)

        if runtime is True and policy is True:
            self._row_dma.update(
                True,
                active_label="ACTIVE",
                inactive_label="INACTIVE",
                btn_when_active="DISABLE",
                btn_when_inactive="ENABLE",
            )
            return

        if runtime is True and policy is False:
            fg, bg, abg, hb = self._btn_style_enable()
            self._row_dma.update_custom(
                status_text="\u25d0  ACTIVE  (FIRMWARE ONLY)",
                status_fg=AMBER,
                btn_text="ENABLE",
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=False,
            )
            return

        if runtime is False and policy is True:
            fg, bg, abg, hb = self._btn_style_disable()
            self._row_dma.update_custom(
                status_text="\u25d0  POLICY ACTIVE",
                status_fg=AMBER,
                btn_text="DISABLE",
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=True,
            )
            return

        if runtime is False and policy is False:
            self._row_dma.update(
                False,
                active_label="ACTIVE",
                inactive_label="INACTIVE",
                btn_when_active="DISABLE",
                btn_when_inactive="ENABLE",
            )
            return

        if runtime is None and policy is True:
            fg, bg, abg, hb = self._btn_style_disable()
            self._row_dma.update_custom(
                status_text="\u25d0  POLICY ACTIVE  (RUNTIME UNKNOWN)",
                status_fg=AMBER,
                btn_text="DISABLE",
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=True,
            )
            return

        if runtime is None and policy is False:
            fg, bg, abg, hb = self._btn_style_enable()
            self._row_dma.update_custom(
                status_text="\u25d0  RUNTIME UNKNOWN",
                status_fg=AMBER,
                btn_text="ENABLE",
                btn_fg=fg, btn_bg=bg, btn_activebg=abg, btn_highlight=hb,
                active_state=False,
            )
            return

        self._row_dma.update(
            None,
            active_label="ACTIVE",
            inactive_label="INACTIVE",
            btn_when_active="DISABLE",
            btn_when_inactive="ENABLE",
        )

    def _refresh_cpuvirt(self) -> None:
        enabled, source = cpu_virt_status()
        self._apply_cpuvirt(enabled, source)

    def _apply_cpuvirt(self, enabled: bool | None, source: str = "") -> None:
        self._row_cpuvirt.update(
            enabled,
            active_label="ENABLED",
            inactive_label="DISABLED",
            btn_when_active="BIOS ONLY",
            btn_when_inactive="BIOS ONLY",
        )
        if self._basic_mode():
            self._row_cpuvirt.set_subtitle("")
            return
        subtitle_parts: list[str] = []
        if source:
            subtitle_parts.append(f"SOURCE: {source}")
        if _is_amd_fx_cpu():
            subtitle_parts.append("AMD FX SAFEGUARD ACTIVE")
        self._row_cpuvirt.set_subtitle("   |   ".join(subtitle_parts))

    def _refresh_meltdown(self) -> None:
        vendor = _get_cpu_vendor()
        protected = None if vendor == "amd" else meltdown_is_protected()
        self._apply_meltdown(vendor, protected)

    def _apply_meltdown(self, vendor: str, protected: bool | None) -> None:
        if vendor == "amd":
            self._row_meltdown.update(
                True,
                active_label="N/A  \u2014  NOT APPLICABLE (AMD)",
                inactive_label="N/A  \u2014  NOT APPLICABLE (AMD)",
                btn_when_active="AMD CPU",
                btn_when_inactive="AMD CPU",
            )
            try:
                self._row_meltdown._btn.config(state="disabled", cursor="arrow")
            except Exception:
                pass
            return
        self._row_meltdown.update(
            protected,
            active_label="PROTECTED",
            inactive_label="UNPROTECTED",
            btn_when_active="READ ONLY",
            btn_when_inactive="READ ONLY",
        )
        try:
            self._row_meltdown._btn.config(state="disabled", cursor="arrow")
        except Exception:
            pass
        self._row_meltdown.set_subtitle("SAFETY MODE: registry-only toggle disabled")

    def _refresh_spectre(self) -> None:
        vendor = _get_cpu_vendor()
        protected = spectre_is_protected()
        self._apply_spectre(vendor, protected)

    def _apply_spectre(self, vendor: str, protected: bool | None) -> None:
        if vendor == "amd":
            active_lbl = "PROTECTED  (V1 / V2 / V4)"
            inactive_lbl = "UNPROTECTED  (V1 / V2 / V4)"
        elif vendor == "intel":
            active_lbl = "PROTECTED  (V1 / V2 / V4 / L1TF / MDS)"
            inactive_lbl = "UNPROTECTED  (V1 / V2 / V4 / L1TF / MDS)"
        else:
            active_lbl = "PROTECTED"
            inactive_lbl = "UNPROTECTED"

        self._row_spectre.update(
            protected,
            active_label=active_lbl,
            inactive_label=inactive_lbl,
            btn_when_active="READ ONLY",
            btn_when_inactive="READ ONLY",
        )
        try:
            self._row_spectre._btn.config(state="disabled", cursor="arrow")
        except Exception:
            pass
        self._row_spectre.set_subtitle("SAFETY MODE: registry-only toggle disabled")

    def _refresh_credguard(self) -> None:
        runtime, configured = credential_guard_status()
        self._apply_credguard(runtime, configured)

    def _apply_credguard(self, runtime: bool | None, configured: bool | None) -> None:
        self._apply_pending_row(
            self._row_credguard,
            runtime,
            configured,
            active_label="ACTIVE",
            inactive_label="OFF",
            btn_active="DISABLE",
            btn_inactive="ENABLE",
            pending_enable_label="ACTIVE  (PENDING REBOOT)",
            pending_disable_label="ACTIVE  (PENDING DISABLE)",
            configured_enable_label="ACTIVE  (CONFIGURED)",
            configured_disable_label="OFF  (CONFIGURED)",
        )
        subtitle = f"RUNTIME: {_bool_text(runtime)}   |   CONFIG: {_bool_text(configured)}"
        reasons = _credential_guard_capability_reasons()
        if reasons and runtime is not True and configured is not True:
            subtitle += f"   |   CHECK: {_first_reason(reasons)}"
        subtitle += "   |   SAFETY MODE: registry-only toggle disabled"
        self._row_credguard._btn.config(state="disabled", cursor="arrow", text="READ ONLY")
        self._row_credguard.set_subtitle(subtitle)

    def _refresh_bitlocker(self) -> None:
        self._apply_bitlocker(_bitlocker_protection_on())

    def _apply_bitlocker(self, active: bool | None) -> None:
        if active is None:
            self._row_bitlocker.update_custom(
                status_text="◐  STATE UNKNOWN",
                status_fg=AMBER,
                btn_text="READ ONLY",
                btn_fg=AMBER,
                btn_bg="#241900",
                btn_activebg="#3a2a00",
                btn_highlight="#6e5600",
                btn_state="disabled",
                btn_cursor="arrow",
                active_state=None,
            )
        else:
            self._row_bitlocker.update(
                active,
                active_label="PROTECTED",
                inactive_label="SUSPENDED",
                btn_when_active="READ ONLY",
                btn_when_inactive="READ ONLY",
            )
            self._row_bitlocker._btn.config(state="disabled", cursor="arrow")
        self._row_bitlocker.set_subtitle("SAFETY MODE: non-BCD toggle disabled")

    def _refresh_secureboot(self) -> None:
        self._apply_secureboot(_secure_boot_enabled())

    def _apply_secureboot(self, enabled: bool | None) -> None:
        if enabled is None:
            self._row_secureboot.update_custom(
                status_text="◐  STATUS UNKNOWN",
                status_fg=AMBER,
                btn_text="BIOS ONLY",
                btn_fg=AMBER,
                btn_bg="#241900",
                btn_activebg="#3a2a00",
                btn_highlight="#6e5600",
                btn_state="normal",
                btn_cursor="hand2",
                active_state=None,
            )
        else:
            self._row_secureboot.update(
                enabled,
                active_label="ON",
                inactive_label="OFF",
                btn_when_active="BIOS ONLY",
                btn_when_inactive="BIOS ONLY",
            )
        self._row_secureboot.set_subtitle("FIRMWARE SETTING")

    def _refresh_windows_hello(self) -> None:
        allowed, source = windows_hello_status()
        self._apply_windows_hello(allowed, source)

    def _apply_windows_hello(self, allowed: bool | None, source: str = "") -> None:
        if allowed is None:
            self._row_hello.update_custom(
                status_text="◐  POLICY UNKNOWN",
                status_fg=AMBER,
                btn_text="READ ONLY",
                btn_fg=AMBER,
                btn_bg="#241900",
                btn_activebg="#3a2a00",
                btn_highlight="#6e5600",
                btn_state="disabled",
                btn_cursor="arrow",
                active_state=None,
            )
        else:
            self._row_hello.update(
                allowed,
                active_label="ALLOWING PROVISIONING",
                inactive_label="SUSPENDED",
                btn_when_active="READ ONLY",
                btn_when_inactive="READ ONLY",
            )
            self._row_hello._btn.config(state="disabled", cursor="arrow")
        subtitle = "PROVISIONING POLICY ONLY - EXISTING PIN/BIOMETRIC MAY STILL WORK"
        if source:
            subtitle += f"   |   SOURCE: {source}"
        subtitle += "   |   SAFETY MODE: registry-only toggle disabled"
        self._row_hello.set_subtitle(subtitle)

    def _backup_changes(self, tag: str, reg_paths: tuple[str, ...]) -> tuple[bool, str]:
        parts: list[str] = []
        ok_bcd, bcd_result = _export_bcd_backup(tag)
        if ok_bcd:
            parts.append(f"BCD backup: {bcd_result}")
        else:
            parts.append(f"BCD backup failed: {bcd_result}")

        failures: list[str] = []
        if reg_paths:
            exported, failures = _export_registry_backup(tag, reg_paths)
            if exported:
                parts.append(f"Registry backup: {len(exported)} key(s)")
            if failures:
                parts.append("Registry backup issues:\n- " + "\n- ".join(failures))

        ok = ok_bcd and not failures
        return ok, "\n\n".join(parts)

    def _basic_preflight(self, label: str, want_enabled: bool) -> bool:
        if not self._basic_mode():
            return True

        if self._basic_change_pending:
            messagebox.showwarning(
                "Basic mode",
                "Basic mode is meant for one change at a time.\n\n"
                "Restart, test what you needed to test, then reopen HyperSwitch if you want to change something else.",
                parent=self,
            )
            return False

        warnings: list[str] = []
        pending_reboot = _pending_reboot_reasons()
        if pending_reboot:
            messagebox.showwarning(
                "Pending reboot required",
                "Windows already has a pending reboot state (" + ", ".join(pending_reboot) + ").\n\n"
                "HyperSwitch safety mode blocks boot-setting changes until that reboot is completed.",
                parent=self,
            )
            return False

        if not want_enabled:
            secure_boot = _secure_boot_enabled()
            if secure_boot is True:
                warnings.append("Secure Boot is on. Boot-entry changes may be blocked until you turn it off in firmware.")

            bitlocker = _bitlocker_protection_on()
            if bitlocker is True:
                warnings.append("BitLocker protection is on for the system drive. Make sure you have recovery access before testing boot-setting changes.")

            hello = _windows_hello_present()
            if hello is True and label in ("Hyper-V", "VBS"):
                warnings.append("Windows Hello / PIN signals were found. Sign-in features can behave differently while you are testing VBS-related changes.")

            cred_guard = _credential_guard_configured()
            if cred_guard is True and label in ("Hyper-V", "VBS"):
                warnings.append("Credential Guard / LSA protection is configured. That can keep part of the VBS stack alive or make the result look inconsistent until after reboot.")

        if not warnings:
            return True

        return messagebox.askyesno(
            "Basic mode checks",
            "Before this change, HyperSwitch found a few things worth calling out:\n\n"
            + "\n\n".join(f"- {item}" for item in warnings)
            + "\n\nContinue anyway?",
            parent=self,
        )

    def _platform_guard(self, label: str, want_enabled: bool) -> bool:
        return True

    def _confirm_toggle(
        self,
        label: str,
        want_enabled: bool,
        reg_paths: tuple[str, ...],
        risk_note: str,
    ) -> bool:
        if not self._platform_guard(label, want_enabled):
            return False
        if not self._basic_preflight(label, want_enabled):
            return False
        action = "enable" if want_enabled else "disable"
        if self._basic_mode():
            prompt = (
                f"{action.title()} {label} on the next restart?\n\n"
                "Use one change at a time, restart, test, then restart again.\n"
                f"{risk_note}\n\nContinue?"
            )
        else:
            prompt = (
                f"{action.title()} {label} on the next restart?\n\n"
                f"{risk_note}\n\nContinue?"
            )
        if not messagebox.askyesno(
            f"Confirm {label}",
            prompt,
            parent=self,
        ):
            return False

        ok_backup, detail = self._backup_changes(label.lower().replace(" ", "-"), reg_paths)
        self._append_log(f"[BACKUP] {label}  {'OK' if ok_backup else 'WARN'}")
        if not ok_backup:
            proceed = messagebox.askyesno(
                "Backup warning",
                "HyperSwitch could not save a full rollback backup.\n\n"
                f"{detail}\n\n"
                "Continue anyway?",
                parent=self,
            )
            if not proceed:
                return False
        return True

    # ------------------------------------------------------------------
    # Toggle actions
    # ------------------------------------------------------------------

    def _toggle_hyperv(self, currently_active: bool | None) -> None:
        if currently_active is None:
            self._refresh_all_async()
            return
        want = not currently_active
        if not self._confirm_toggle(
            "Hyper-V",
            want,
            (),
            "This only changes the hypervisorlaunchtype boot setting. It does not modify VBS, HVCI, or optional Hyper-V features.",
        ):
            return
        ok, msg = hyperv_set(want)
        self._append_log(f"[HYPER-V] {'ON' if want else 'OFF'}  {'OK' if ok else 'FAILED'}  {msg}")
        if ok:
            self._refresh_all_async()
            self._post_change_basic_mode("Hyper-V")
        else:
            messagebox.showerror(_status_error_title(msg, "DSE change error"), msg, parent=self)

    def _toggle_dse(self, currently_enforced: bool | None) -> None:
        if currently_enforced is None:
            self._refresh_all_async()
            return
        want_enforced = not currently_enforced
        if not self._confirm_toggle(
            "Driver Signature Enforcement",
            want_enforced,
            (),
            "This only changes the testsigning and nointegritychecks BCD values.",
        ):
            return
        ok, msg = dse_set_enforced(want_enforced)
        action = "ENFORCED" if want_enforced else "DISABLED"
        self._append_log(f"[DSE] {action}  {'OK' if ok else 'FAILED'}  {msg}")
        if ok:
            self._refresh_all_async()
            # If DSE was just disabled, check for other active enforcement layers
            # that would still cause signature errors despite DSE being off.
            if not want_enforced:
                partial = _dse_partial_enforcement()
                if partial:
                    layers = "\n  \u2022 ".join(partial)
                    messagebox.showwarning(
                        "Signature enforcement still active",
                        "DSE has been disabled, but the following independent\n"
                        "enforcement layers are still active and may still\n"
                        "cause driver signature errors:\n\n"
                        f"  \u2022 {layers}\n\n"
                        "These operate independently of DSE and cannot be\n"
                        "disabled from this tool alone.",
                        parent=self,
                    )
            self._post_change_basic_mode("Driver Signature Enforcement")
        else:
            messagebox.showerror(_status_error_title(msg, "bcdedit error"), msg, parent=self)

    def _toggle_vbs(self, currently_active: bool | None) -> None:
        if currently_active is None:
            self._refresh_all_async()
            return
        want = not currently_active
        if not self._confirm_toggle(
            "VBS",
            want,
            (),
            "This only changes the vsmlaunchtype BCD value.",
        ):
            return
        ok, msg = vbs_set(want)
        self._append_log(f"[VBS] {'ON' if want else 'OFF'}  {'OK' if ok else 'FAILED'}  {msg}")
        if ok:
            self._refresh_all_async()
            self._post_change_basic_mode("VBS")
        else:
            messagebox.showerror(_status_error_title(msg, "bcdedit error"), msg, parent=self)

    def _toggle_hvci(self, currently_active: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only security-policy changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_dma(self, currently_active: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only security-policy changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_cpuvirt(self, _currently_active: bool | None) -> None:
        messagebox.showinfo(
            "CPU Virtualization",
            "CPU Virtualization (VT-x / AMD-V) is a firmware setting.\n\n"
            "It can only be enabled or disabled inside your\n"
            "BIOS / UEFI firmware settings.\n\n"
            "Restart your PC and enter BIOS setup (usually Del, F2, or F10)\n"
            "to change this setting.",
            parent=self,
        )

    def _toggle_meltdown(self, currently_protected: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only mitigation changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_spectre(self, currently_protected: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only mitigation changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_credguard(self, currently_active: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only security-policy changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_bitlocker(self, currently_active: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables non-BCD changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    def _toggle_secureboot(self, _currently_active: bool | None) -> None:
        messagebox.showinfo(
            "Secure Boot",
            "Secure Boot is a firmware setting.\n\n"
            "You can view its state here, but you must change it in BIOS / UEFI.",
            parent=self,
        )

    def _toggle_windows_hello(self, currently_allowed: bool | None) -> None:
        messagebox.showinfo(
            "Read only",
            "Safety mode disables registry-only provisioning-policy changes.\n\n"
            "HyperSwitch is limited to a small BCD edit allowlist.",
            parent=self,
        )

    # ------------------------------------------------------------------
    # Reboot
    # ------------------------------------------------------------------

    def _confirm_reboot(self) -> None:
        if messagebox.askyesno(
            "Restart",
            "Schedule a restart in 5 seconds?",
            parent=self,
        ):
            schedule_reboot(5)
            self._append_log("[REBOOT] Restart scheduled in 5 seconds.")
            self.after(6000, self.destroy)

    # ------------------------------------------------------------------
    # Log
    # ------------------------------------------------------------------

    def _persist_tool_state(self) -> None:
        self._tool_state["preferred_mode"] = self._mode_var.get()
        self._tool_state["history"] = list(self._history_cache[-80:])
        _save_tool_state(self._tool_state)

    def _record_activity(self, text: str) -> None:
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._history_cache.append({"when": stamp, "text": text})
        self._history_cache = self._history_cache[-80:]
        self._persist_tool_state()

    def _append_log(self, text: str, persist: bool = True) -> None:
        self._log.config(state="normal")
        self._log.insert("end", text + "\n")
        self._log.see("end")
        self._log.config(state="disabled")
        if persist:
            self._record_activity(text)

    def _open_path_in_explorer(self, path: str) -> bool:
        try:
            os.startfile(path)
            return True
        except Exception as exc:
            messagebox.showerror(
                "Open path failed",
                f"HyperSwitch could not open:\n{path}\n\n{exc}",
                parent=self,
            )
            return False

    def _open_backup_folder(self) -> None:
        path = _backup_dir()
        if self._open_path_in_explorer(path):
            self._append_log(f"[BACKUPS] Opened {path}")

    def _open_support_folder(self) -> None:
        path = _support_bundle_dir()
        if self._open_path_in_explorer(path):
            self._append_log(f"[SUPPORT] Opened {path}")

    def _build_operator_summary(self) -> str:
        runtime_hv, configured_hv = hyperv_status()
        hvci_runtime, hvci_configured = hvci_status()
        dma_runtime, dma_policy = dma_status()
        cpuvirt_state, cpuvirt_source = cpu_virt_status()
        cred_runtime, cred_configured = credential_guard_status()
        hello_allowed, hello_source = windows_hello_status()

        lines = [
            f"{APP_NAME} {APP_VERSION}",
            f"Mode: {self._mode_var.get()}",
            f"Pending reboot: {', '.join(_pending_reboot_reasons()) or 'none'}",
            f"Hyper-V runtime/configured: {_bool_text(runtime_hv)} / {_bool_text(configured_hv)}",
            f"DSE enforced: {_bool_text(dse_is_enforced())}",
            f"VBS active: {_bool_text(vbs_is_active())}",
            f"HVCI runtime/configured: {_bool_text(hvci_runtime)} / {_bool_text(hvci_configured)}",
            f"DMA runtime/policy: {_bool_text(dma_runtime)} / {_bool_text(dma_policy)}",
            f"CPU virtualization: {_bool_text(cpuvirt_state)} ({cpuvirt_source})",
            f"Credential Guard runtime/configured: {_bool_text(cred_runtime)} / {_bool_text(cred_configured)}",
            f"Secure Boot: {_bool_text(_secure_boot_enabled())}",
            f"BitLocker system drive: {_bool_text(_bitlocker_protection_on())}",
            f"Windows Hello provisioning: {_bool_text(hello_allowed)} ({hello_source or 'no source'})",
        ]
        return "\n".join(lines)

    def _copy_summary(self) -> None:
        summary = self._build_operator_summary()
        try:
            self.clipboard_clear()
            self.clipboard_append(summary)
            self.update_idletasks()
            self._append_log("[SUMMARY] Copied operator summary to clipboard.")
            messagebox.showinfo(
                "Summary copied",
                "HyperSwitch copied a quick operator summary to the clipboard.",
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(
                "Clipboard error",
                f"HyperSwitch could not copy the summary.\n\n{exc}",
                parent=self,
            )

    def _export_support_bundle(self) -> None:
        try:
            _write_debug_report()
            summary = self._build_operator_summary()
            bundle_dir = _support_bundle_dir()
            bundle_name = f"HyperSwitch-support-{_timestamp_slug()}.zip"
            bundle_path = os.path.join(bundle_dir, bundle_name)
            manifest_lines = [
                f"{APP_NAME} Support Bundle",
                f"Version: {APP_VERSION}",
                "",
                summary,
                "",
                f"State file: {_state_file_path()}",
                f"Debug report: {_debug_report_path()}",
                f"Backup folder: {_backup_dir()}",
                f"Support folder: {_support_bundle_dir()}",
            ]

            with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("summary.txt", summary + "\n")
                archive.writestr("manifest.txt", "\n".join(manifest_lines) + "\n")
                activity_lines = [
                    f"{entry.get('when', '')}  {entry.get('text', '')}".rstrip()
                    for entry in self._history_cache[-80:]
                ]
                archive.writestr("activity.txt", "\n".join(activity_lines) + "\n")

                debug_path = _debug_report_path()
                if os.path.exists(debug_path):
                    archive.write(debug_path, arcname="debugger.txt")

                state_path = _state_file_path()
                if os.path.exists(state_path):
                    archive.write(state_path, arcname="state.json")

                for backup_path in _recent_backup_paths():
                    arcname = os.path.join("backups", os.path.basename(backup_path))
                    archive.write(backup_path, arcname=arcname)

                for support_path in _recent_support_bundle_paths():
                    if os.path.abspath(support_path) == os.path.abspath(bundle_path):
                        continue
                    arcname = os.path.join("recent-support", os.path.basename(support_path))
                    archive.write(support_path, arcname=arcname)

            self._append_log(f"[SUPPORT] Exported support bundle to {bundle_path}")
            messagebox.showinfo(
                "Support bundle ready",
                "HyperSwitch exported a support bundle with the latest debug report,\n"
                "current state summary, and recent rollback artifacts.\n\n"
                f"{bundle_path}",
                parent=self,
            )
        except Exception as exc:
            self._append_log(f"[SUPPORT] Export failed  {exc}")
            messagebox.showerror(
                "Support bundle failed",
                f"HyperSwitch could not export the support bundle.\n\n{exc}",
                parent=self,
            )

    def _show_activity_center(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title(f"{APP_NAME} Activity")
        dialog.configure(bg=BG)
        dialog.resizable(True, True)
        dialog.minsize(700, 460)
        dialog.transient(self)
        dialog.grab_set()

        shell = tk.Frame(dialog, bg=BG, padx=18, pady=16)
        shell.pack(fill="both", expand=True)

        tk.Label(
            shell,
            text="Activity Center",
            font=MONO_HDR,
            fg=WHITE,
            bg=BG,
        ).pack(anchor="w")

        tk.Label(
            shell,
            text="Recent operator actions, support exports, and rollback paths.",
            font=MONO_SM,
            fg=MUTED,
            bg=BG,
        ).pack(anchor="w", pady=(4, 12))

        summary = tk.Text(
            shell,
            height=4,
            bg=PANEL_ALT,
            fg=WHITE,
            font=MONO_SM,
            relief="flat",
            wrap="word",
            padx=10,
            pady=8,
            insertbackground=WHITE,
        )
        summary.insert("1.0", self._build_operator_summary())
        summary.config(state="disabled")
        summary.pack(fill="x")

        tk.Label(
            shell,
            text=f"State: {_state_file_path()}   |   Backups: {_backup_dir()}   |   Support: {_support_bundle_dir()}",
            font=MONO_SM,
            fg=DIM,
            bg=BG,
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(10, 8))

        history_frame = tk.Frame(
            shell,
            bg=PANEL,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        history_frame.pack(fill="both", expand=True)

        history = tk.Text(
            history_frame,
            bg=PANEL,
            fg=DIM,
            font=MONO_SM,
            relief="flat",
            wrap="word",
            padx=10,
            pady=8,
            insertbackground=WHITE,
        )
        history.pack(fill="both", expand=True)

        entries = self._history_cache[-60:]
        if entries:
            for entry in entries:
                history.insert("end", f"{entry.get('when', '')}  {entry.get('text', '')}\n")
        else:
            history.insert("end", "No persisted activity yet.\n")
        history.config(state="disabled")

        button_row = tk.Frame(shell, bg=BG)
        button_row.pack(fill="x", pady=(12, 0))

        tk.Button(
            button_row,
            text="OPEN SUPPORT",
            command=self._open_support_folder,
            font=("Consolas", 9, "bold"),
            fg=GREEN,
            bg="#062118",
            activeforeground=GREEN,
            activebackground="#0a3023",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side="left")

        tk.Button(
            button_row,
            text="OPEN BACKUPS",
            command=self._open_backup_folder,
            font=("Consolas", 9, "bold"),
            fg=BLUE,
            bg="#101a28",
            activeforeground=BLUE,
            activebackground="#152235",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=(10, 0))

        tk.Button(
            button_row,
            text="EXPORT SUPPORT",
            command=self._export_support_bundle,
            font=("Consolas", 9, "bold"),
            fg=ACCENT,
            bg="#102123",
            activeforeground=ACCENT,
            activebackground="#173136",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=(10, 0))

        tk.Button(
            button_row,
            text="CLOSE",
            command=dialog.destroy,
            font=("Consolas", 9, "bold"),
            fg=WHITE,
            bg="#1b2633",
            activeforeground=WHITE,
            activebackground="#243246",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side="right")

    def _on_mode_changed(self, _value=None) -> None:
        target_mode = self._mode_var.get()
        if target_mode == "Advanced" and self._last_mode != "Advanced":
            proceed = messagebox.askyesno(
                "Switch to Advanced mode",
                "Advanced mode opens the full diagnostic board.\n\n"
                "Safety mode still limits writes to the BCD allowlist.\n\n"
                "Open Advanced mode?",
                parent=self,
            )
            if not proceed:
                self._mode_var.set(self._last_mode)
                return
        if target_mode != self._last_mode:
            self._record_activity(f"[MODE] Switched to {target_mode}.")
        self._last_mode = target_mode
        self._persist_tool_state()
        self._apply_mode()

    def _basic_mode(self) -> bool:
        return self._mode_var.get() != "Advanced"

    def _apply_mode(self) -> None:
        basic_mode = self._basic_mode()

        if basic_mode:
            hint = (
                "BASIC MODE: safest path for live troubleshooting. Queue one BCD change, restart, validate the result, then switch it back manually when you are done."
            )
        else:
            hint = (
                "ADVANCED MODE: exposes the full status surface for deeper checks. "
                "Writes still stay limited to the BCD allowlist."
            )

        pending = _pending_reboot_text()
        if pending:
            hint += "   |   Restart state detected: " + pending
        self._mode_hint.config(text=hint)

        for row in self._basic_rows:
            row.show()

        for row in self._advanced_rows:
            if basic_mode:
                if hasattr(row, "hide"):
                    row.hide()
                else:
                    row.pack_forget()
            else:
                if hasattr(row, "show"):
                    row.show()
                else:
                    row.pack(fill="x", padx=20, pady=(4, 6))

        self.after_idle(lambda: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        if not basic_mode:
            self.after(25, self._refresh_advanced_async)

    def _post_change_basic_mode(self, label: str) -> None:
        if not self._basic_mode():
            return
        self._basic_change_pending = True
        self._append_log(f"[BASIC MODE] Restart next to apply {label}. Reboot again after testing, then switch it back manually if needed.")
        if self._ask_two_option_dialog(
            "Restart recommended",
            f"{label} is queued.\n\n"
            "Basic mode is meant for one change at a time.\n"
            "Restart now to apply it, test what you need, then switch it back manually if needed.",
            "Reboot now",
            "Reboot later",
        ):
            self._confirm_reboot()

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def show_help(self, _event=None) -> None:
        messagebox.showinfo(
            "Help",
            (
                f"{APP_NAME}\n\n"
                "Hyper-V\n"
                "  Starts or stops the Windows hypervisor on the next restart.\n"
                "  This toggle only changes hypervisorlaunchtype.\n"
                "  bcdedit key: hypervisorlaunchtype\n\n"
                "DSE -- Driver Signature Enforcement\n"
                "  Controls whether Windows will enforce signed-driver loading.\n"
                "  This toggle only changes testsigning and nointegritychecks.\n"
                "  bcdedit keys: testsigning, nointegritychecks\n\n"
                "VBS -- Virtualization Based Security\n"
                "  Covers Windows security features that run behind the hypervisor.\n"
                "  This toggle only changes vsmlaunchtype.\n"
                "  bcdedit key: vsmlaunchtype\n\n"
                "Mode\n"
                "  Basic mode is the default operating path and is meant for\n"
                "  one change at a time.\n"
                "  It also blocks boot edits while Windows already has a\n"
                "  pending restart state.\n"
                "  Advanced mode shows the full status board, but non-BCD\n"
                "  controls stay read-only in safety mode.\n\n"
                "Safety Mode\n"
                "  HyperSwitch only writes a short BCD allowlist on the current\n"
                "  boot entry: hypervisorlaunchtype, testsigning,\n"
                "  nointegritychecks, and vsmlaunchtype.\n\n"
                "Everything else is reported for visibility so you can see what\n"
                "Windows is doing without letting the tool make broad policy\n"
                "changes behind your back.\n\n"
                "All applied changes stay pending until restart."
            ),
            parent=self,
        )

    def _show_patchguard_info(self) -> None:
        messagebox.showinfo(
            "PatchGuard Info",
            "PatchGuard (Kernel Patch Protection) protects the Windows kernel\n"
            "from patching/hooking. Some hypervisor or anti-cheat drivers that\n"
            "use unsupported kernel hooks can crash when PatchGuard detects a\n"
            "modification.\n\n"
            "If you see crashes, update or replace the driver with a supported\n"
            "version and remove kernel hook/patch tools before rebooting.\n",
            parent=self,
        )

    def _show_f2_info(self, _event=None) -> None:
        messagebox.showinfo(
            f"{APP_NAME} Info",
            f"{APP_NAME} {APP_VERSION}\n"
            f"Roadmap target: {ROADMAP_TARGET}\n\n"
            "HyperSwitch is an independent troubleshooting utility for operators who "
            "need fast visibility into Hyper-V, driver integrity, and VBS state on a "
            "live Windows install.\n\n"
            "The tool is intentionally conservative: writes stay limited to a short "
            "BCD allowlist, while the broader security surface is shown read-only for "
            "clarity and safety.\n\n"
            "This project is not affiliated with the Hyper-V team or Microsoft "
            "support channels.\n\n"
            "Project direction, release notes, and support remain with Cloud. "
            "Discord: .cjmxo\n\n"
            "Thanks to everyone helping shape the 2.0 release.",
            parent=self,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if _is_debug_mode():
        _run_debug_gui()
        sys.exit(0)
    app = App()
    app.bind_all("<F1>", app.show_help)
    app.bind_all("<F2>", app._show_f2_info)
    app.mainloop()
