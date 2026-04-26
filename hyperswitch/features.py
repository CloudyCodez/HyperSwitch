import os

from .bcd import current_entry, format_bcdedit_failure, read_value, set_boot_value
from .queries import (
    dism_feature_state,
    powershell_bool,
    powershell_value,
    query_kernel_ci_options,
    query_wmi_device_guard,
    query_wmi_device_guard_list,
    read_registry_dword,
    service_is_running,
    wmic_property_value,
)


HYPERV_PLATFORM_FEATURES = (
    "Windows-Hypervisor-Platform",
    "VirtualMachinePlatform",
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Hypervisor",
    "Microsoft-Hyper-V-Services",
)

VBS_REG_PATH = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
VBS_REG_VALUE = "EnableVirtualizationBasedSecurity"
VBS_POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
VBS_STATUS_PATH = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Status"
VBS_STATUS_VALUE = "VirtualizationBasedSecurityStatus"
KSHADOW_PATH = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"
HVCI_PATH_LEGACY = (
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
)
HELLO_GPO_PATH = r"SOFTWARE\Policies\Microsoft\PassportForWork"
HELLO_GPO_VALUE = "Enabled"
HELLO_CSP_ROOT = r"SOFTWARE\Microsoft\Policies\PassportForWork"


def hyperv_status() -> tuple[bool | None, bool | None]:
    runtime = None
    configured = None

    hv_running = read_registry_dword(
        None, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Status", "HypervisorRunning"
    )
    if hv_running is not None:
        runtime = hv_running == 1

    if runtime is None:
        hv_present = read_registry_dword(
            None,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
            "HypervisorPresent",
        )
        if hv_present is not None:
            runtime = hv_present == 1

    if runtime is None:
        runtime = powershell_bool(
            "(Get-CimInstance -ClassName Win32_ComputerSystem "
            "-EA SilentlyContinue).HypervisorPresent"
        )

    if runtime is None:
        for service_name in ("HvHost", "vmms", "HvSocket"):
            try:
                if service_is_running(service_name):
                    runtime = True
                    break
            except Exception:
                pass

    if runtime is None:
        wmic_hv = wmic_property_value("computersystem", "HypervisorPresent")
        if wmic_hv:
            runtime = wmic_hv.upper() == "TRUE"

    value = read_value("hypervisorlaunchtype")
    if value is not None:
        configured = value == "auto"

    if configured is None:
        feature_state = hyperv_feature_enabled()
        if feature_state is False:
            configured = False

    return runtime, configured


def hyperv_driver_kind(
    runtime: bool | None,
    configured: bool | None,
    vbs_active: bool | None,
) -> str:
    if runtime is None:
        return "UNKNOWN"
    if not runtime:
        return "NONE"
    if configured is True or vbs_active is True:
        return "MICROSOFT"
    for service_name in ("HvHost", "vmms", "vmcompute"):
        if service_is_running(service_name):
            return "MICROSOFT"
    return "OTHER"


def hyperv_feature_enabled() -> bool | None:
    saw_disabled = False
    for feature_name in HYPERV_PLATFORM_FEATURES:
        state = dism_feature_state(feature_name)
        if state is None:
            continue
        lowered = state.lower()
        if lowered == "enabled":
            return True
        if lowered == "disabled":
            saw_disabled = True
    if saw_disabled:
        return False
    return None


def hyperv_set(
    active: bool,
    pending_reasons: list[str],
    secure_boot_enabled: bool | None,
) -> tuple[bool, str]:
    want = "auto" if active else "off"
    ok_launch, msg_launch = set_boot_value("hypervisorlaunchtype", want, pending_reasons)
    results = [f"hypervisorlaunchtype={want}({'OK' if ok_launch else 'FAIL'})"]
    details: list[str] = []

    if not ok_launch:
        details.append(
            format_bcdedit_failure(
                "hypervisorlaunchtype",
                want,
                msg_launch,
                secure_boot_enabled,
            )
        )

    message = "  |  ".join(results)
    if details:
        message += "\n\n" + "\n\n".join(details)
    return ok_launch, message


def dse_partial_enforcement() -> list[str]:
    active = []
    ci_opts = query_kernel_ci_options()

    if ci_opts is not None:
        if ci_opts & 0x004:
            active.append("UMCI (user-mode code integrity)")
        if ci_opts & 0x080:
            active.append("HVCI (hypervisor-protected code integrity)")
        if ci_opts & 0x800:
            active.append("WHQL enforcement")

    var_state = read_registry_dword(
        None,
        r"SYSTEM\CurrentControlSet\Control\CI\Policy",
        "VerifiedAndReputablePolicyState",
    )
    if var_state and var_state >= 1:
        active.append("Smart App Control / Verified & Reputable policy")

    emode = read_registry_dword(
        None,
        r"SYSTEM\CurrentControlSet\Control\CI\Policy",
        "EmodePolicyRequired",
    )
    if emode and emode >= 1:
        active.append("Enhanced Mode signing policy")

    for policy_file in (
        r"C:\Windows\System32\CodeIntegrity\SiPolicy.p7b",
        r"C:\Windows\System32\CodeIntegrity\driversipolicy.p7b",
    ):
        if os.path.exists(policy_file):
            active.append(f"CI policy file: {os.path.basename(policy_file)}")

    secure_boot = powershell_bool("try { [string](Confirm-SecureBootUEFI) } catch { '' }")
    if secure_boot is True:
        active.append("Secure Boot (firmware)")

    return active


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


def _ci_registry_disabled() -> bool:
    for path, name in (
        (r"SYSTEM\CurrentControlSet\Control\CI\Config", "DisableIntegrityChecks"),
        (r"SYSTEM\CurrentControlSet\Control\CI\Protected", "DisableIntegrityChecks"),
        (r"SYSTEM\CurrentControlSet\Control\CI", "DisableIntegrityChecks"),
        (
            r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
            "DisableExceptionChainValidation",
        ),
    ):
        if read_registry_dword(None, path, name) == 1:
            return True
    return False


def dse_is_enforced() -> bool | None:
    any_read_succeeded = False

    ci_opts = query_kernel_ci_options()
    if ci_opts is not None:
        any_read_succeeded = True
        if not (ci_opts & 0x01):
            return False
        if ci_opts & 0x02:
            return False
        if ci_opts & 0x200:
            return False
        return True

    wmi = query_wmi_device_guard("CodeIntegrityPolicyEnforcementStatus")
    if wmi is not None:
        any_read_succeeded = True
        return bool(wmi)

    ok, bcd_current, _ = current_entry()
    if ok and bcd_current:
        any_read_succeeded = True
        if _bcd_has_flag(bcd_current, "testsigning"):
            return False
        if _bcd_has_flag(bcd_current, "nointegritychecks"):
            return False
        if _bcd_loadoptions_has(
            bcd_current,
            (
                "testsigning",
                "nointegritychecks",
                "disable_integrity_checks",
                "disableintegritychecks",
                "ddisable_integrity_checks",
                "ddisableintegritychecks",
            ),
        ):
            return False

    any_read_succeeded = True
    if _ci_registry_disabled():
        return False

    if not any_read_succeeded:
        return None
    return True


def dse_set_enforced(
    enforced: bool,
    pending_reasons: list[str],
    secure_boot_enabled: bool | None,
) -> tuple[bool, str]:
    value = "no" if enforced else "yes"
    results = []
    details: list[str] = []

    ok_testsigning, msg_testsigning = set_boot_value("testsigning", value, pending_reasons)
    ok_integrity, msg_integrity = set_boot_value(
        "nointegritychecks",
        value,
        pending_reasons,
    )
    results.append(f"testsigning={value}({'OK' if ok_testsigning else 'FAIL'})")
    results.append(f"nointegritychecks={value}({'OK' if ok_integrity else 'FAIL'})")

    if not ok_testsigning:
        details.append(
            format_bcdedit_failure(
                "testsigning",
                value,
                msg_testsigning,
                secure_boot_enabled,
            )
        )
    if not ok_integrity:
        details.append(
            format_bcdedit_failure(
                "nointegritychecks",
                value,
                msg_integrity,
                secure_boot_enabled,
            )
        )

    ok = ok_testsigning and ok_integrity
    message = "  |  ".join(results)
    if details:
        message += "\n\n" + "\n\n".join(details)
    return ok, message


def vbs_is_active() -> bool | None:
    any_read_succeeded = False
    strong_on = False
    weak_on = False
    explicit_off = False

    wmi_running = query_wmi_device_guard_list("SecurityServicesRunning")
    if wmi_running is not None:
        any_read_succeeded = True
        if any(value > 0 for value in wmi_running):
            strong_on = True
        elif any(value == 0 for value in wmi_running):
            explicit_off = True

    wmi_configured = query_wmi_device_guard_list("SecurityServicesConfigured")
    if wmi_configured is not None:
        any_read_succeeded = True
        if any(value > 0 for value in wmi_configured):
            weak_on = True
        elif any(value == 0 for value in wmi_configured):
            explicit_off = True

    reg_status = read_registry_dword(None, VBS_STATUS_PATH, VBS_STATUS_VALUE)
    if reg_status is not None:
        any_read_succeeded = True
        if reg_status >= 1:
            strong_on = True
        else:
            explicit_off = True

    reg_enabled = read_registry_dword(None, VBS_REG_PATH, VBS_REG_VALUE)
    if reg_enabled is not None:
        any_read_succeeded = True
        if reg_enabled >= 1:
            strong_on = True
        else:
            explicit_off = True

    hvci_legacy = read_registry_dword(None, HVCI_PATH_LEGACY, "Enabled")
    if hvci_legacy is not None:
        any_read_succeeded = True
        if hvci_legacy >= 1:
            strong_on = True
        else:
            explicit_off = True

    kshadow_enabled = read_registry_dword(None, KSHADOW_PATH, "Enabled")
    if kshadow_enabled is not None:
        any_read_succeeded = True
        if kshadow_enabled >= 1:
            strong_on = True
        else:
            explicit_off = True

    policy_vbs = read_registry_dword(None, VBS_POLICY_PATH, "EnableVirtualizationBasedSecurity")
    if policy_vbs is not None:
        any_read_succeeded = True
        if policy_vbs >= 1:
            strong_on = True
        else:
            explicit_off = True

    lsa_cfg = read_registry_dword(None, VBS_POLICY_PATH, "LsaCfgFlags")
    if lsa_cfg is not None:
        any_read_succeeded = True
        if lsa_cfg >= 1:
            strong_on = True
        else:
            explicit_off = True

    value = read_value("vsmlaunchtype")
    if value is not None:
        any_read_succeeded = True
        if value == "auto":
            strong_on = True
        elif value == "off":
            explicit_off = True

    computer_info = powershell_value(
        "[int](Get-ComputerInfo -EA SilentlyContinue)"
        ".DeviceGuardVirtualizationBasedSecurityStatus"
    )
    if computer_info and computer_info.isdigit():
        any_read_succeeded = True
        if int(computer_info) >= 1:
            strong_on = True
        else:
            explicit_off = True

    wmi_status = query_wmi_device_guard("VirtualizationBasedSecurityStatus")
    if wmi_status is not None:
        any_read_succeeded = True
        if wmi_status >= 1:
            weak_on = True
        else:
            explicit_off = True

    raw_wmi = powershell_value(
        "(Get-WmiObject -Class Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard "
        "-EA SilentlyContinue).VirtualizationBasedSecurityStatus"
    )
    if raw_wmi and raw_wmi.isdigit():
        any_read_succeeded = True
        if int(raw_wmi) >= 1:
            weak_on = True
        else:
            explicit_off = True

    if strong_on:
        return True
    if weak_on and not explicit_off:
        return True
    if not any_read_succeeded:
        return None
    return False


def vbs_set(
    active: bool,
    pending_reasons: list[str],
    secure_boot_enabled: bool | None,
) -> tuple[bool, str]:
    value = "auto" if active else "off"
    ok, raw_message = set_boot_value("vsmlaunchtype", value, pending_reasons)
    results = [f"vsmlaunchtype={value}({'OK' if ok else 'FAIL'})"]
    details: list[str] = []

    if not ok:
        details.append(
            format_bcdedit_failure(
                "vsmlaunchtype",
                value,
                raw_message,
                secure_boot_enabled,
            )
        )

    message = "  |  ".join(results)
    if details:
        message += "\n\n" + "\n\n".join(details)
    return ok, message
