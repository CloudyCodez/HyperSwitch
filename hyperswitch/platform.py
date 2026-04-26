import ctypes
import subprocess

from .queries import (
    device_guard_has_value,
    is_amd_fx_cpu,
    parse_bool_text,
    platform_value,
    powershell_bool,
    powershell_value,
    query_kernel_ci_options,
    query_processor_value,
    query_wmi_device_guard,
    query_wmi_device_guard_list,
    read_registry_dword,
    read_registry_text,
    wmic_property_value,
)


HVCI_PATH = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperGuard"
HVCI_VALUE = "Enabled"
HVCI_PATH_LEGACY = (
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
)
HVCI_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
HVCI_POLICY_VALUE = "HypervisorEnforcedCodeIntegrity"

DMA_POLICY_PATH = r"SYSTEM\CurrentControlSet\Control\DmaSecurity"
DMA_POLICY_GPO_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
DMA_POLICY_VALUE = "DeviceEnumerationPolicy"


def secure_boot_enabled() -> bool | None:
    reg_value = read_registry_dword(
        None,
        r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "UEFISecureBootEnabled",
    )
    if reg_value is not None:
        return reg_value == 1

    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { if (Confirm-SecureBootUEFI) { 'True' } else { 'False' } } catch { '' }",
            ],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = proc.stdout.strip().lower()
        if output == "true":
            return True
        if output == "false":
            return False
    except Exception:
        pass
    return None


def reg_subkey_has_entries(path: str) -> bool | None:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            subkeys, values, _ = winreg.QueryInfoKey(key)
            return (subkeys > 0) or (values > 0)
    except FileNotFoundError:
        return None
    except Exception:
        try:
            proc = subprocess.run(
                ["reg", "query", f"HKLM\\{path}"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if proc.returncode != 0:
                return None
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            return len(lines) > 1
        except Exception:
            return None


def hvci_status() -> tuple[bool | None, bool | None]:
    runtime = None
    configured = None

    dg_running = device_guard_has_value("SecurityServicesRunning", 2)
    if dg_running is not None:
        runtime = dg_running

    if runtime is None:
        value = query_wmi_device_guard("HyperVisorEnforcedCodeIntegrityStatus")
        if value is not None:
            runtime = value >= 1

    if runtime is None:
        ci_options = query_kernel_ci_options()
        if ci_options is not None:
            runtime = bool(ci_options & 0x80)

    if runtime is None:
        value = read_registry_dword(
            None,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Status",
            "HvciStatus",
        )
        if value is not None:
            runtime = value >= 1

    config_seen = False
    config_enabled = False

    dg_configured = device_guard_has_value("SecurityServicesConfigured", 2)
    if dg_configured is not None:
        config_seen = True
        if dg_configured:
            config_enabled = True

    for reg_path, reg_name in (
        (HVCI_PATH, HVCI_VALUE),
        (HVCI_PATH_LEGACY, "Enabled"),
        (HVCI_POLICY_PATH, HVCI_POLICY_VALUE),
    ):
        value = read_registry_dword(None, reg_path, reg_name)
        if value is not None:
            config_seen = True
            if value >= 1:
                config_enabled = True

    if not config_seen and runtime is True:
        configured = True

    if config_seen:
        configured = config_enabled

    return runtime, configured


def hvci_is_active() -> bool | None:
    runtime, configured = hvci_status()
    if runtime is not None:
        return runtime
    if configured is not None:
        return configured
    return None


def dma_support_available() -> bool | None:
    properties = query_wmi_device_guard_list("AvailableSecurityProperties")
    if properties is not None:
        return 3 in properties

    for path in (
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\Default\VerifiedBuses\HSTI",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\VerifiedBuses\HSTI",
    ):
        hsti = reg_subkey_has_entries(path)
        if hsti is not None:
            return bool(hsti)

    return None


def dma_status() -> tuple[bool | None, bool | None]:
    runtime = None
    policy = None

    wmi_dma = query_wmi_device_guard("KernelDmaProtectionEnabled")
    if wmi_dma is not None:
        runtime = wmi_dma >= 1

    for path in (
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\Default\VerifiedBuses\HSTI",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\VerifiedBuses\HSTI",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\Default\AllowedBuses",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\Default\UnallowedBuses",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses",
        r"SYSTEM\CurrentControlSet\Control\DmaSecurity\UnallowedBuses",
    ):
        if runtime is not None:
            break
        entries = reg_subkey_has_entries(path)
        if entries is not None:
            runtime = bool(entries)

    if runtime is None:
        wmi_dma = query_wmi_device_guard("KernelDmaProtectionEnabled")
        if wmi_dma is not None:
            runtime = wmi_dma >= 1

    policy_value = read_registry_dword(None, DMA_POLICY_PATH, DMA_POLICY_VALUE)
    gpo_value = read_registry_dword(None, DMA_POLICY_GPO_PATH, DMA_POLICY_VALUE)
    if gpo_value is not None:
        policy_value = gpo_value

    if policy_value is not None:
        if policy_value <= 1:
            policy = True
        elif policy_value == 2:
            policy = False
    else:
        wmi_dma = query_wmi_device_guard("KernelDmaProtectionEnabled")
        if wmi_dma is not None:
            policy = wmi_dma >= 1
        else:
            policy = False

    return runtime, policy


def dma_is_active() -> bool | None:
    runtime, policy = dma_status()
    if runtime is not None:
        return runtime
    if policy is not None:
        return policy
    return None


def _virt_firmware_api_enabled() -> bool | None:
    try:
        return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(ctypes.c_uint(21)))
    except Exception:
        return None


def cpu_virt_status() -> tuple[bool | None, str]:
    api_value = _virt_firmware_api_enabled()
    if api_value is not None:
        return api_value, "PF_VIRT_FIRMWARE_ENABLED API"

    direct_sources: list[tuple[bool, str]] = []

    value = parse_bool_text(query_processor_value("VirtualizationFirmwareEnabled"))
    if value is not None:
        direct_sources.append((value, "CIM Win32_Processor.VirtualizationFirmwareEnabled"))

    raw = wmic_property_value("cpu", "VirtualizationFirmwareEnabled")
    value = parse_bool_text(raw)
    if value is not None:
        direct_sources.append((value, "WMIC cpu.VirtualizationFirmwareEnabled"))

    value = powershell_bool(
        "(Get-WmiObject -Class Win32_Processor "
        "-ErrorAction SilentlyContinue | Select-Object -First 1)"
        ".VirtualizationFirmwareEnabled"
    )
    if value is not None:
        direct_sources.append((value, "WMI Win32_Processor.VirtualizationFirmwareEnabled"))

    for state, source in direct_sources:
        if state is False:
            return False, source
    for state, source in direct_sources:
        if state is True:
            return True, source

    value = powershell_bool(
        "(Get-ComputerInfo -Property HyperVRequirementVirtualizationFirmwareEnabled "
        "-EA SilentlyContinue).HyperVRequirementVirtualizationFirmwareEnabled"
    )
    if value is not None:
        return value, "Get-ComputerInfo HyperVRequirementVirtualizationFirmwareEnabled"

    return None, "No firmware virtualization signal"


def cpu_virt_is_enabled() -> bool | None:
    state, _ = cpu_virt_status()
    return state


def processor_bool_property(property_name: str) -> bool | None:
    if property_name == "VMMonitorModeExtensions":
        cached = parse_bool_text(platform_value("HyperVRequirementVMMonitorModeExtensions"))
        if cached is not None:
            return cached
    if property_name == "SecondLevelAddressTranslationExtensions":
        cached = parse_bool_text(platform_value("HyperVRequirementSecondLevelAddressTranslation"))
        if cached is not None:
            return cached

    value = parse_bool_text(query_processor_value(property_name))
    if value is not None:
        return value

    raw = wmic_property_value("cpu", property_name)
    value = parse_bool_text(raw)
    if value is not None:
        return value

    value = powershell_bool(
        f"(Get-CimInstance Win32_Processor -EA SilentlyContinue | Select-Object -First 1).{property_name}"
    )
    if value is not None:
        return value

    return None


def dep_available() -> bool | None:
    cached = parse_bool_text(platform_value("HyperVRequirementDataExecutionPreventionAvailable"))
    if cached is not None:
        return cached

    value = powershell_bool(
        "(Get-ComputerInfo -Property HyperVRequirementDataExecutionPreventionAvailable "
        "-EA SilentlyContinue).HyperVRequirementDataExecutionPreventionAvailable"
    )
    if value is not None:
        return value

    raw = wmic_property_value("OS", "DataExecutionPrevention_Available")
    return parse_bool_text(raw)


def uefi_firmware_present() -> bool | None:
    value = read_registry_dword(None, r"SYSTEM\CurrentControlSet\Control", "PEFirmwareType")
    if value is not None:
        if value == 2:
            return True
        if value == 1:
            return False

    raw = platform_value("BiosFirmwareType").lower()
    if not raw:
        raw = powershell_value(
            "try { [string](Get-ComputerInfo -Property BiosFirmwareType -EA SilentlyContinue).BiosFirmwareType } catch { '' }"
        ).lower()
    if "uefi" in raw:
        return True
    if raw in ("legacy", "bios"):
        return False
    return None


def tpm_2_ready() -> bool | None:
    present = parse_bool_text(platform_value("TpmPresent"))
    ready = parse_bool_text(platform_value("TpmReady"))
    spec = platform_value("TpmSpecVersion")
    if present is not None or ready is not None or spec:
        if present is False:
            return False
        if ready is False:
            return False
        if "2.0" in spec:
            return True

    raw = powershell_value(
        "try { "
        "$t = Get-Tpm -EA Stop; "
        "if ($null -eq $t) { '' } else { "
        "[string]$t.TpmPresent + '|' + [string]$t.TpmReady + '|' + [string]$t.SpecVersion } "
        "} catch { '' }"
    )
    if raw:
        parts = raw.split("|")
        if len(parts) >= 3:
            present = parse_bool_text(parts[0])
            ready = parse_bool_text(parts[1])
            spec = parts[2]
            if present is False:
                return False
            if ready is False:
                return False
            if "2.0" in spec:
                return True

    return None


def os_edition() -> str:
    cached = platform_value("WindowsEditionId")
    if cached:
        return cached
    return read_registry_text(None, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID")


def pending_reboot_reasons() -> list[str]:
    reasons: list[str] = []
    checks = (
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", ""),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", ""),
        (r"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations"),
    )
    for path, value_name in checks:
        try:
            if value_name:
                raw = read_registry_text(None, path, value_name)
                if raw:
                    reasons.append(path.split("\\")[-1])
            else:
                proc = subprocess.run(
                    ["reg", "query", f"HKLM\\{path}"],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if proc.returncode == 0:
                    reasons.append(path.split("\\")[-1])
        except Exception:
            pass
    return reasons


def pending_reboot_text() -> str:
    reasons = pending_reboot_reasons()
    if not reasons:
        return ""
    return "PENDING REBOOT: " + ", ".join(reasons)


def edition_supports_hyperv() -> bool | None:
    edition = (os_edition() or "").lower()
    if not edition:
        return None
    if any(tag in edition for tag in ("professional", "enterprise", "education", "server")):
        return True
    if any(tag in edition for tag in ("core", "home")):
        return False
    return None


def edition_supports_credential_guard() -> bool | None:
    edition = (os_edition() or "").lower()
    if not edition:
        return None
    if any(tag in edition for tag in ("enterprise", "education", "server")):
        return True
    if any(tag in edition for tag in ("professional", "core", "home")):
        return False
    return None


def hyperv_capability_reasons() -> list[str]:
    reasons: list[str] = []

    edition_ok = edition_supports_hyperv()
    if edition_ok is False:
        reasons.append("Windows edition does not include Hyper-V.")

    cpuvirt = cpu_virt_is_enabled()
    if cpuvirt is False:
        reasons.append("Firmware virtualization is off in BIOS / UEFI.")

    vmx = processor_bool_property("VMMonitorModeExtensions")
    if vmx is False:
        reasons.append("VM Monitor Mode Extensions are missing.")

    slat = processor_bool_property("SecondLevelAddressTranslationExtensions")
    if slat is False:
        reasons.append("SLAT is missing.")

    dep = dep_available()
    if dep is False:
        reasons.append("NX / DEP is not available.")

    return reasons


def vbs_capability_reasons() -> list[str]:
    reasons = list(hyperv_capability_reasons())

    if is_amd_fx_cpu():
        reasons.append("AMD FX is treated as unsupported for VBS-family changes in HyperSwitch.")

    uefi = uefi_firmware_present()
    if uefi is False:
        reasons.append("UEFI firmware is not active.")

    tpm = tpm_2_ready()
    if tpm is False:
        reasons.append("TPM 2.0 is missing or not ready.")

    return reasons


def credential_guard_capability_reasons() -> list[str]:
    reasons = list(vbs_capability_reasons())
    edition_ok = edition_supports_credential_guard()
    if edition_ok is False:
        reasons.append("Windows edition does not support Credential Guard.")
    return reasons
