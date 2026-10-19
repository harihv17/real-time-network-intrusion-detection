"""Network interface discovery and live capture prerequisites validation.

Inspects the host operating system, checks for Npcap/WinPcap drivers,
evaluates administrative privileges, detects cloud-hosted environments,
and enumerates valid network adapters without failing in headless containers.
"""

import os
import sys
import ctypes
from typing import List, Dict, Any, Optional

try:
    import scapy.config
    if os.name == "nt":
        try:
            import scapy.arch.windows
        except (ImportError, Exception):
            pass
    SCAPY_AVAILABLE = True
except (ImportError, Exception):
    SCAPY_AVAILABLE = False


def is_running_as_admin() -> bool:
    """Checks whether the current process has administrative elevation."""
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_cloud_environment() -> bool:
    """Detects whether application is running in a public/containerized cloud environment (e.g. Streamlit Cloud)."""
    indicators = [
        os.environ.get("STREAMLIT_SERVER_HEADLESS") == "true" and os.name != "nt",
        os.environ.get("STREAMLIT_HOSTED") == "true",
        os.environ.get("STREAMLIT_SHARING_MODE") is not None,
        os.path.exists("/.dockerenv"),
        os.environ.get("KUBERNETES_SERVICE_HOST") is not None,
        bool(os.environ.get("HOSTNAME", "").startswith("streamlit")),
    ]
    return any(indicators)


def check_capture_prerequisites() -> Dict[str, Any]:
    """Diagnoses system readiness for live network packet capture across Windows, Linux, and Cloud."""
    cloud = is_cloud_environment()
    admin = is_running_as_admin()
    scapy_ok = SCAPY_AVAILABLE

    npcap_ok = False
    pcap_provider_name = "None"

    if scapy_ok:
        try:
            npcap_ok = bool(scapy.config.conf.use_pcap)
            if hasattr(scapy.config.conf, "pcap_provider"):
                pcap_provider_name = str(scapy.config.conf.pcap_provider)
        except Exception:
            npcap_ok = False

    npcap_file_exists = False
    if os.name == "nt":
        paths_to_check = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
            r"C:\Windows\System32\Npcap",
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\SysWOW64\Npcap",
            r"C:\Windows\SysWOW64\wpcap.dll",
            r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        ]
        for p in paths_to_check:
            if os.path.exists(p):
                npcap_file_exists = True
                break

    # Determine whether genuine hardware capture is viable
    if cloud:
        can_capture = False
    elif os.name == "nt":
        can_capture = scapy_ok and (npcap_ok or npcap_file_exists)
    else:
        # Linux/macOS local: requires root or raw socket capabilities
        can_capture = scapy_ok and admin

    diagnostic_notes = []
    if cloud:
        diagnostic_notes.append(
            "Hosted Cloud Container Detected: This instance is running on a public cloud server "
            "(Streamlit Community Cloud). Cloud containers do not have raw socket permissions "
            "(CAP_NET_RAW) or physical access to visitors' personal network hardware. "
            "Simulation Mode is fully operational and provides deterministic, reproducible traffic."
        )
    else:
        if not scapy_ok:
            diagnostic_notes.append("Scapy library is not installed (run `pip install scapy`).")
        if os.name == "nt" and not (npcap_ok or npcap_file_exists):
            diagnostic_notes.append(
                "Npcap packet capture driver is not detected. "
                "On Windows, live promiscuous packet capture requires Npcap (https://npcap.com/#download). "
                "Please install Npcap with 'Install Npcap in WinPcap API-compatible Mode' enabled."
            )
        if not admin:
            diagnostic_notes.append(
                "Application is running without Administrator elevation. "
                "Capturing packets on network adapters usually requires opening PowerShell/terminal as Administrator."
            )

    return {
        "can_capture": can_capture,
        "is_cloud": cloud,
        "is_admin": admin,
        "scapy_installed": scapy_ok,
        "npcap_installed": (npcap_ok or npcap_file_exists) if os.name == "nt" else False,
        "pcap_provider": pcap_provider_name,
        "diagnostic_notes": diagnostic_notes,
    }


def get_available_interfaces() -> List[Dict[str, Any]]:
    """Retrieves network interfaces available on the host machine without crashing on cloud Linux."""
    interfaces: List[Dict[str, Any]] = []

    if not SCAPY_AVAILABLE:
        return interfaces

    try:
        if os.name == "nt":
            from scapy.arch.windows import get_windows_if_list
            raw_list = get_windows_if_list()

            for item in raw_list:
                name = item.get("name", "Unknown Interface")
                desc = item.get("description", "")
                ips = item.get("ips", [])
                mac = item.get("mac", "")
                guid = item.get("guid", "")

                # Skip non-essential tunnel miniports to keep selection clean
                if any(x in desc.lower() for x in ["wan miniport", "filter-0000", "packet scheduler", "kernel debugger"]):
                    continue

                display_label = f"{name} ({desc})" if desc else name
                if ips:
                    display_label += f" — IP: {', '.join(ips[:2])}"

                interfaces.append({
                    "id": name,
                    "name": name,
                    "description": desc,
                    "ips": ips,
                    "mac": mac,
                    "guid": guid,
                    "display_label": display_label,
                    "is_active": len(ips) > 0,
                })
        else:
            try:
                from scapy.all import get_if_list
                for iface in get_if_list():
                    interfaces.append({
                        "id": str(iface),
                        "name": str(iface),
                        "description": f"Interface {iface}",
                        "ips": [],
                        "mac": "",
                        "guid": str(iface),
                        "display_label": str(iface),
                        "is_active": True,
                    })
            except Exception:
                pass
    except Exception:
        # Fallback empty list if interface listing encounters platform exception
        pass

    # Sort with active IP interfaces first
    interfaces.sort(key=lambda x: (not x.get("is_active", False), x.get("name", "")))
    return interfaces
