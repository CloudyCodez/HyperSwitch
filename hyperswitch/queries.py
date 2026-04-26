import ctypes
import os
import re
import subprocess


_CACHE_MISS = object()
_PS_CACHE: dict[str, str] = {}
_WMI_DG_CACHE: dict[str, object] = {}
_REG_CACHE: dict[tuple[str, str], int | None] = {}
_SERVICE_CACHE: dict[str, bool | None] = {}
_DISM_CACHE: dict[str, str | None] = {}
_PROC_CACHE: dict[str, str] = {}
_PLATFORM_CACHE: dict[str, str] = {}
_PROC_PRIMED = False
_WMI_DG_PRIMED = False
_PLATFORM_PRIMED = False
_CPU_VENDOR_CACHE: str | None = None
_CPU_VENDOR_PRIMED = False
_CI_CACHE: int | None | object = _CACHE_MISS
_WMI_DG_ARRAY_PROPS = {
    "AvailableSecurityProperties",
    "RequiredSecurityProperties",
    "SecurityServicesConfigured",
    "SecurityServicesRunning",
    "VirtualMachineIsolationProperties",
}


def powershell_value(command: str) -> str:
    if command in _PS_CACHE:
        return _PS_CACHE[command]
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        result = lines[0] if lines else ""
        _PS_CACHE[command] = result
        return result
    except Exception:
        _PS_CACHE[command] = ""
        return ""


def powershell_bool(command: str) -> bool | None:
    val = powershell_value(command).strip().lower()
    if val in ("true", "1"):
        return True
    if val in ("false", "0"):
        return False
    return None


def parse_bool_text(raw: str) -> bool | None:
    raw = raw.strip().lower()
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no"):
        return False
    return None


def parse_int_list(raw: str) -> tuple[int, ...] | None:
    if not raw:
        return None
    numbers = [int(part) for part in re.findall(r"\d+", raw)]
    if not numbers:
        return None
    return tuple(numbers)


def prime_processor_cache() -> None:
    global _PROC_PRIMED
    if _PROC_PRIMED:
        return
    props = (
        "Manufacturer",
        "Name",
        "ProcessorId",
        "Caption",
        "Description",
        "VirtualizationFirmwareEnabled",
        "VMMonitorModeExtensions",
        "SecondLevelAddressTranslationExtensions",
    )
    try:
        ps_lines = "; ".join([f"'{prop}=' + [string]$cpu.{prop}" for prop in props])
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$cpu=Get-CimInstance -ClassName Win32_Processor -EA SilentlyContinue | Select-Object -First 1; "
                f"if ($null -eq $cpu) {{ '' }} else {{ {ps_lines} }}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            _PROC_CACHE[key.strip()] = val.strip()
    except Exception:
        pass
    _PROC_PRIMED = True


def query_processor_value(property_name: str) -> str:
    prime_processor_cache()
    return _PROC_CACHE.get(property_name, "")


def query_cpu_registry_value(value_name: str) -> str:
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            winreg.KEY_READ,
        )
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return str(value).strip()
    except Exception:
        return ""


def prime_platform_cache() -> None:
    global _PLATFORM_PRIMED
    if _PLATFORM_PRIMED:
        return
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ci=Get-ComputerInfo -EA SilentlyContinue; "
                "if ($null -ne $ci) { "
                "'WindowsEditionId=' + [string]$ci.WindowsEditionId; "
                "'BiosFirmwareType=' + [string]$ci.BiosFirmwareType; "
                "'HyperVRequirementVirtualizationFirmwareEnabled=' + [string]$ci.HyperVRequirementVirtualizationFirmwareEnabled; "
                "'HyperVRequirementSecondLevelAddressTranslation=' + [string]$ci.HyperVRequirementSecondLevelAddressTranslation; "
                "'HyperVRequirementDataExecutionPreventionAvailable=' + [string]$ci.HyperVRequirementDataExecutionPreventionAvailable; "
                "'HyperVRequirementVMMonitorModeExtensions=' + [string]$ci.HyperVRequirementVMMonitorModeExtensions "
                "}; "
                "try { "
                "$sb = Confirm-SecureBootUEFI; "
                "'SecureBootEnabled=' + [string]$sb "
                "} catch { '' }; "
                "try { "
                "$t = Get-Tpm -EA Stop; "
                "if ($null -ne $t) { "
                "'TpmPresent=' + [string]$t.TpmPresent; "
                "'TpmReady=' + [string]$t.TpmReady; "
                "'TpmSpecVersion=' + [string]$t.SpecVersion "
                "} "
                "} catch { '' }",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            _PLATFORM_CACHE[key.strip()] = value.strip()
    except Exception:
        pass
    _PLATFORM_PRIMED = True


def platform_value(name: str) -> str:
    prime_platform_cache()
    return _PLATFORM_CACHE.get(name, "")


def wmic_property_value(wmi_class: str, property_name: str) -> str:
    try:
        proc = subprocess.run(
            ["wmic"] + wmi_class.split() + ["get", property_name, "/value"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for encoding in ("utf-16-le", "utf-8-sig", "utf-8", "latin-1"):
            try:
                raw = proc.stdout.decode(encoding, errors="replace")
                for line in raw.splitlines():
                    line = line.strip()
                    if "=" in line and property_name.lower() in line.lower():
                        return line.split("=", 1)[-1].strip()
                break
            except Exception:
                continue
    except Exception:
        pass
    return ""


def read_registry_dword(hive, path: str, value: str) -> int | None:
    cache_key = (path, value)
    if cache_key in _REG_CACHE:
        return _REG_CACHE[cache_key]

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        val, _ = winreg.QueryValueEx(key, value)
        winreg.CloseKey(key)
        result = val if isinstance(val, int) else None
        _REG_CACHE[cache_key] = result
        return result
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["reg", "query", f"HKLM\\{path}", "/v", value],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0].lower() == value.lower():
                    try:
                        result = int(parts[-1], 16)
                        _REG_CACHE[cache_key] = result
                        return result
                    except ValueError:
                        pass
    except Exception:
        pass

    _REG_CACHE[cache_key] = None
    return None


def read_registry_text(hive, path: str, value: str) -> str:
    hive_name = "HKLM" if hive is None else str(hive)
    try:
        proc = subprocess.run(
            ["reg", "query", f"{hive_name}\\{path}", "/v", value],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0:
            raw = proc.stdout.decode("utf-8-sig", errors="replace")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].lower() == value.lower():
                    return " ".join(parts[2:]).split(None, 1)[-1].strip()
    except Exception:
        pass
    return ""


def query_kernel_ci_options() -> int | None:
    global _CI_CACHE
    if _CI_CACHE is not _CACHE_MISS:
        return _CI_CACHE

    try:
        import ctypes.wintypes

        class SYSTEM_CODEINTEGRITY_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.wintypes.ULONG),
                ("CodeIntegrityOptions", ctypes.wintypes.ULONG),
            ]

        info = SYSTEM_CODEINTEGRITY_INFORMATION()
        info.Length = ctypes.sizeof(info)
        return_length = ctypes.wintypes.ULONG(0)

        status = ctypes.windll.ntdll.NtQuerySystemInformation(
            103,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(return_length),
        )
        if status == 0:
            _CI_CACHE = info.CodeIntegrityOptions
            return _CI_CACHE
        _CI_CACHE = None
        return None
    except Exception:
        _CI_CACHE = None
        return None


def get_cpu_vendor() -> str:
    global _CPU_VENDOR_CACHE, _CPU_VENDOR_PRIMED
    if _CPU_VENDOR_PRIMED:
        return _CPU_VENDOR_CACHE or "unknown"

    manufacturer = query_processor_value("Manufacturer")
    if manufacturer:
        raw = manufacturer.lower()
        if "intel" in raw or "genuineintel" in raw:
            _CPU_VENDOR_CACHE = "intel"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
        if "amd" in raw or "authenticamd" in raw:
            _CPU_VENDOR_CACHE = "amd"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            winreg.KEY_READ,
        )
        vendor, _ = winreg.QueryValueEx(key, "VendorIdentifier")
        winreg.CloseKey(key)
        raw = str(vendor).lower()
        if "genuineintel" in raw:
            _CPU_VENDOR_CACHE = "intel"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
        if "authenticamd" in raw or "amd" in raw:
            _CPU_VENDOR_CACHE = "amd"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["wmic", "cpu", "get", "Manufacturer", "/value"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        raw = proc.stdout.decode("utf-8-sig", errors="replace").lower()
        if "intel" in raw:
            _CPU_VENDOR_CACHE = "intel"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
        if "amd" in raw:
            _CPU_VENDOR_CACHE = "amd"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
    except Exception:
        pass

    cpu_name = query_cpu_registry_value("ProcessorNameString")
    if cpu_name:
        raw = cpu_name.lower()
        if "intel" in raw:
            _CPU_VENDOR_CACHE = "intel"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE
        if "amd" in raw or "fx-" in raw or "ryzen" in raw:
            _CPU_VENDOR_CACHE = "amd"
            _CPU_VENDOR_PRIMED = True
            return _CPU_VENDOR_CACHE

    _CPU_VENDOR_CACHE = "unknown"
    _CPU_VENDOR_PRIMED = True
    return _CPU_VENDOR_CACHE


def is_amd_fx_cpu() -> bool:
    cpu_name = query_cpu_registry_value("ProcessorNameString").lower()
    if "amd fx" in cpu_name or "fx-" in cpu_name or "fx(tm)" in cpu_name:
        return True

    identifier = query_cpu_registry_value("Identifier").lower()
    if get_cpu_vendor() == "amd" and "family 21" in identifier:
        return True

    cim_name = query_processor_value("Name").lower()
    return "amd fx" in cim_name or "fx-" in cim_name or "fx(tm)" in cim_name


def service_is_running(service_name: str) -> bool:
    if service_name in _SERVICE_CACHE:
        return bool(_SERVICE_CACHE[service_name])

    try:
        quoted = "','".join(("HvHost", "vmms", "HvSocket", "vmcompute"))
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Get-Service -Name '{quoted}' -EA SilentlyContinue | ForEach-Object {{ $_.Name + '=' + $_.Status.value__ }}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            name, val = line.split("=", 1)
            if val.strip().isdigit():
                _SERVICE_CACHE[name.strip()] = int(val.strip()) == 4
    except Exception:
        pass

    if service_name in _SERVICE_CACHE:
        return bool(_SERVICE_CACHE[service_name])

    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue).Status.value__",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        val = proc.stdout.strip()
        if val.isdigit():
            result = int(val) == 4
            _SERVICE_CACHE[service_name] = result
            return result
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["sc", "queryex", service_name],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        raw = proc.stdout.decode("utf-8", errors="replace") + proc.stdout.decode("latin-1", errors="replace")
        for line in raw.splitlines():
            if "STATE" in line.upper():
                parts = line.split(":")
                if len(parts) >= 2:
                    nums = [part.strip() for part in parts[1].split() if part.strip().isdigit()]
                    if nums and int(nums[0]) == 4:
                        _SERVICE_CACHE[service_name] = True
                        return True
    except Exception:
        pass

    _SERVICE_CACHE[service_name] = False
    return False


def dism_feature_state(feature_name: str) -> str | None:
    if feature_name in _DISM_CACHE:
        return _DISM_CACHE[feature_name]
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-WindowsOptionalFeature -Online "
                f"-FeatureName '{feature_name}' -EA SilentlyContinue).State",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if not lines:
            _DISM_CACHE[feature_name] = None
            return None
        result = lines[0]
        _DISM_CACHE[feature_name] = result
        return result
    except Exception:
        _DISM_CACHE[feature_name] = None
        return None


def query_wmi_device_guard(property_name: str) -> int | None:
    prime_device_guard_cache()
    cached = _WMI_DG_CACHE.get(property_name, _CACHE_MISS)
    if isinstance(cached, int) or cached is None:
        return cached
    if isinstance(cached, tuple):
        return cached[0] if len(cached) == 1 else None
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$v=(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA SilentlyContinue).{property_name}; "
                "if ($null -eq $v) { '' } else { [string]$v }",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        val = proc.stdout.strip().splitlines()[0].strip() if proc.stdout.strip() else ""
        result = int(val) if val.isdigit() else None
        _WMI_DG_CACHE[property_name] = result
        return result
    except Exception:
        _WMI_DG_CACHE[property_name] = None
        return None


def query_wmi_device_guard_list(property_name: str) -> tuple[int, ...] | None:
    prime_device_guard_cache()
    cached = _WMI_DG_CACHE.get(property_name, _CACHE_MISS)
    if isinstance(cached, tuple):
        return cached
    if isinstance(cached, int):
        return (cached,)
    if cached is None:
        return None
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$v=(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA SilentlyContinue).{property_name}; "
                "if ($null -eq $v) { '' } else { (@($v) | ForEach-Object { [string]$_ }) -join ',' }",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        result = parse_int_list(proc.stdout.strip())
        _WMI_DG_CACHE[property_name] = result
        return result
    except Exception:
        _WMI_DG_CACHE[property_name] = None
        return None


def device_guard_has_value(property_name: str, expected: int) -> bool | None:
    values = query_wmi_device_guard_list(property_name)
    if values is None:
        return None
    return expected in values


def prime_device_guard_cache() -> None:
    global _WMI_DG_PRIMED
    if _WMI_DG_PRIMED:
        return
    props = [
        "VirtualizationBasedSecurityStatus",
        "SecurityServicesRunning",
        "SecurityServicesConfigured",
        "HyperVisorEnforcedCodeIntegrityStatus",
        "AvailableSecurityProperties",
        "RequiredSecurityProperties",
        "KernelDmaProtectionEnabled",
        "CodeIntegrityPolicyEnforcementStatus",
    ]
    try:
        ps_parts = []
        for prop in props:
            if prop in _WMI_DG_ARRAY_PROPS:
                ps_parts.append(f"'{prop}=' + ((@($dg.{prop}) | ForEach-Object {{ [string]$_ }}) -join ',')")
            else:
                ps_parts.append(f"'{prop}=' + [string]$dg.{prop}")
        ps_lines = "; ".join(ps_parts)
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$dg=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard; "
                f"if ($null -eq $dg) {{ '' }} else {{ {ps_lines} }}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key in _WMI_DG_ARRAY_PROPS:
                _WMI_DG_CACHE[key] = parse_int_list(val)
            else:
                _WMI_DG_CACHE[key] = int(val) if val.isdigit() else None
    except Exception:
        pass
    _WMI_DG_PRIMED = True


def clear_query_caches() -> None:
    global _PROC_PRIMED, _WMI_DG_PRIMED, _PLATFORM_PRIMED, _CPU_VENDOR_CACHE, _CPU_VENDOR_PRIMED, _CI_CACHE
    _PS_CACHE.clear()
    _WMI_DG_CACHE.clear()
    _REG_CACHE.clear()
    _SERVICE_CACHE.clear()
    _DISM_CACHE.clear()
    _PROC_CACHE.clear()
    _PLATFORM_CACHE.clear()
    _PROC_PRIMED = False
    _WMI_DG_PRIMED = False
    _PLATFORM_PRIMED = False
    _CPU_VENDOR_CACHE = None
    _CPU_VENDOR_PRIMED = False
    _CI_CACHE = _CACHE_MISS


def bitlocker_protection_on() -> bool | None:
    val = powershell_value(
        "try { "
        "$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -EA Stop; "
        "if ($null -eq $v) { '' } else { [string]$v.ProtectionStatus } "
        "} catch { '' }"
    )
    if val.isdigit():
        return int(val) == 1
    val = powershell_value(
        "try { "
        "$vol = Get-CimInstance -Namespace 'Root/CIMV2/Security/MicrosoftVolumeEncryption' "
        "-ClassName Win32_EncryptableVolume -EA Stop | "
        "Where-Object { $_.DriveLetter -eq $env:SystemDrive } | Select-Object -First 1; "
        "if ($null -eq $vol) { '' } else { "
        "$r = Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus -EA Stop; "
        "[string]$r.ProtectionStatus } "
        "} catch { '' }"
    )
    if val.isdigit():
        return int(val) == 1
    return None


def windows_hello_present() -> bool | None:
    if service_is_running("NgcCtnrSvc") or service_is_running("NgcSvc"):
        return True
    ngc_path = os.path.join(
        os.environ.get("WINDIR", r"C:\\Windows"),
        "ServiceProfiles",
        "LocalService",
        "AppData",
        "Local",
        "Microsoft",
        "Ngc",
    )
    try:
        if os.path.isdir(ngc_path):
            with os.scandir(ngc_path) as entries:
                for _ in entries:
                    return True
            return False
    except Exception:
        pass
    return None


def credential_guard_configured(vbs_policy_path: str) -> bool | None:
    val = read_registry_dword(None, vbs_policy_path, "LsaCfgFlags")
    if val is not None:
        return val != 0
    configured = query_wmi_device_guard_list("SecurityServicesConfigured")
    if configured is not None:
        return 1 in configured
    return None


def credential_guard_running() -> bool | None:
    running = query_wmi_device_guard_list("SecurityServicesRunning")
    if running is not None:
        return 1 in running
    val = powershell_bool(
        "try { "
        "$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -EA Stop; "
        "if ($null -eq $dg) { '' } else { [string]($dg.SecurityServicesRunning -contains 1) } "
        "} catch { '' }"
    )
    if val is not None:
        return val
    return None


def credential_guard_status(vbs_policy_path: str) -> tuple[bool | None, bool | None]:
    runtime = credential_guard_running()
    configured = credential_guard_configured(vbs_policy_path)
    if runtime is None:
        lsa = read_registry_dword(None, vbs_policy_path, "LsaCfgFlags")
        if lsa is not None:
            runtime = lsa != 0
    return runtime, configured


def hello_csp_state(hello_csp_root: str) -> tuple[bool | None, str]:
    try:
        import winreg

        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hello_csp_root, 0, winreg.KEY_READ)
        states: list[int] = []
        conflict_labels: list[str] = []
        subkeys, _, _ = winreg.QueryInfoKey(root)
        for i in range(subkeys):
            tenant = winreg.EnumKey(root, i)
            for suffix, label in (("Device\\Policies", f"{tenant} device"), ("UserSid\\Policies", f"{tenant} user")):
                path = f"{hello_csp_root}\\{tenant}\\{suffix}"
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                    value, _ = winreg.QueryValueEx(key, "UsePassportForWork")
                    winreg.CloseKey(key)
                    if isinstance(value, int):
                        states.append(value)
                        conflict_labels.append(label)
                except Exception:
                    pass
        winreg.CloseKey(root)
        if 0 in states:
            return False, ", ".join(conflict_labels)
        if 1 in states:
            return True, ", ".join(conflict_labels)
    except Exception:
        pass
    return None, ""


def windows_hello_status(
    hello_gpo_path: str,
    hello_gpo_value: str,
    hello_csp_root: str,
) -> tuple[bool | None, str]:
    gpo_val = read_registry_dword(None, hello_gpo_path, hello_gpo_value)
    csp_val, csp_label = hello_csp_state(hello_csp_root)
    post_logon = read_registry_dword(None, hello_gpo_path, "DisablePostLogonProvisioning")

    notes: list[str] = []
    if gpo_val is not None:
        notes.append(f"GPO={gpo_val}")
    if post_logon is not None:
        notes.append(f"PostLogon={post_logon}")
    if csp_label:
        notes.append(f"CSP={csp_label}")

    if gpo_val == 0:
        return False, " | ".join(notes) if notes else "GPO disable"
    if gpo_val == 1:
        return True, " | ".join(notes) if notes else "GPO enable"
    if post_logon == 1:
        return False, " | ".join(notes) if notes else "Post-logon provisioning disabled"
    if csp_val is False:
        return False, " | ".join(notes) if notes else "CSP disable"
    if csp_val is True:
        return True, " | ".join(notes) if notes else "CSP enable"
    return True, "Not configured - provisioning allowed"
