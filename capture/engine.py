"""Thread-safe live packet capture engine using Scapy.

Manages background capture threads, validates hardware and driver prerequisites,
and streams parsed PacketEvents into a thread-safe FIFO queue for the detection pipeline.
"""

from collections import deque
import threading
import queue
import time
from typing import Optional, List, Set, Dict, Any

from simulator.models import PacketEvent
from capture.parser import parse_packet_metadata
from capture.interfaces import check_capture_prerequisites


class CaptureState:
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    CAPTURING = "CAPTURING"
    PAUSED = "PAUSED"
    ERROR = "ERROR"


class LiveCaptureEngine:
    """Manages asynchronous live network packet sniffing and queue buffering."""

    def __init__(self, max_buffer_size: int = 5000):
        self.state: str = CaptureState.STOPPED
        self.selected_interface: Optional[str] = None
        self.bpf_filter: Optional[str] = None
        self.error_message: Optional[str] = None
        self.diagnostic_advice: Optional[str] = None
        self.is_paused: bool = False

        # Thread-safe packet delivery queue for consumer
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)

        # In-memory historical buffer for UI visualisations (strictly live packets)
        self.captured_events_buffer: deque[PacketEvent] = deque(maxlen=max_buffer_size)

        # Telemetry counters
        self.captured_packets_count: int = 0
        self.observed_bytes_count: int = 0
        self.unique_src_ips: Set[str] = set()
        self.unique_dst_ips: Set[str] = set()
        self.start_time: Optional[float] = None

        # Rolling 1-second packet rate tracker
        self._rate_timestamps: deque[float] = deque()

        # Thread management
        self._thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()

    @property
    def current_packet_rate(self) -> float:
        """Returns instantaneous packet rate (packets per second) over a 1-second rolling window."""
        now = time.time()
        cutoff = now - 1.0
        with self._lock:
            while self._rate_timestamps and self._rate_timestamps[0] < cutoff:
                self._rate_timestamps.popleft()
            return float(len(self._rate_timestamps))

    def start_capture(self, interface_name: Optional[str] = None, bpf_filter: Optional[str] = None) -> bool:
        """Initiates live packet capture on the specified or default network interface."""
        with self._lock:
            if self.state == CaptureState.CAPTURING:
                return True
            if self._thread and self._thread.is_alive():
                self.state = CaptureState.CAPTURING
                return True
            if self.state == CaptureState.PAUSED:
                self.is_paused = False
                self.state = CaptureState.CAPTURING
                return True

            self.state = CaptureState.STARTING
            self.error_message = None
            self.diagnostic_advice = None
            self.selected_interface = interface_name
            self.bpf_filter = bpf_filter.strip() if bpf_filter and bpf_filter.strip() else None
            self.is_paused = False

            # 1. Verify Prerequisites (Cloud vs Local, Npcap / libpcap)
            diag = check_capture_prerequisites()
            if diag.get("is_cloud", False):
                self.state = CaptureState.ERROR
                self.error_message = "Live packet capture is unavailable on hosted cloud containers."
                self.diagnostic_advice = (
                    "Streamlit Community Cloud operates inside an isolated Linux container without physical network adapter access.\n\n"
                    "For public demonstrations, use Simulation Mode (100% functional) to test all detection algorithms, "
                    "or clone this repository to run locally on a machine with Npcap/libpcap installed."
                )
                return False

            if not diag["scapy_installed"]:
                self.state = CaptureState.ERROR
                self.error_message = "Scapy library is missing."
                self.diagnostic_advice = "Install scapy using: pip install scapy"
                return False

            if not diag["can_capture"]:
                self.state = CaptureState.ERROR
                if diag.get("npcap_installed") is False:
                    self.error_message = "Npcap packet capture driver is not installed on this system."
                    self.diagnostic_advice = (
                        "Windows requires Npcap to capture live packets from physical/virtual network adapters.\n\n"
                        "Installation Steps:\n"
                        "1. Download Npcap from: https://npcap.com/#download\n"
                        "2. Run the installer and ensure 'Install Npcap in WinPcap API-compatible Mode' is checked.\n"
                        "3. Re-run this application in PowerShell with 'Run as administrator'."
                    )
                else:
                    self.error_message = "Insufficient permissions for raw network packet capture."
                    self.diagnostic_advice = (
                        "Raw socket packet capture requires elevated privileges (Administrator on Windows, root/CAP_NET_RAW on Linux).\n"
                        "Please re-launch PowerShell as Administrator."
                    )
                return False

            # 2. Reset stop signal and spawn background worker
            self._stop_event.clear()
            self.start_time = time.time()

            self._thread = threading.Thread(
                target=self._worker_loop,
                args=(interface_name, self.bpf_filter),
                daemon=True,
                name="LiveCaptureWorker",
            )
            self._thread.start()
            return True

    def pause_capture(self) -> None:
        """Pauses packet ingestion without killing the worker thread."""
        with self._lock:
            if self.state == CaptureState.CAPTURING:
                self.is_paused = True
                self.state = CaptureState.PAUSED

    def resume_capture(self) -> None:
        """Resumes packet ingestion from a paused state."""
        with self._lock:
            if self.state == CaptureState.PAUSED:
                self.is_paused = False
                self.state = CaptureState.CAPTURING

    def stop_capture(self) -> None:
        """Signals background sniffing loop to terminate gracefully."""
        with self._lock:
            if self.state == CaptureState.STOPPED:
                return
            self._stop_event.set()
            self.is_paused = False
            self.state = CaptureState.STOPPED

    def reset(self) -> None:
        """Stops active sniffing and clears all telemetry and buffer state."""
        self.stop_capture()
        with self._lock:
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break

            self.captured_events_buffer.clear()
            self.captured_packets_count = 0
            self.observed_bytes_count = 0
            self.unique_src_ips.clear()
            self.unique_dst_ips.clear()
            self.error_message = None
            self.diagnostic_advice = None
            self.start_time = None
            self._rate_timestamps.clear()
            self.is_paused = False

    def drain_packet_queue(self, max_packets: int = 100) -> List[PacketEvent]:
        """Drains accumulated events from the capture queue without blocking."""
        drained: List[PacketEvent] = []
        for _ in range(max_packets):
            try:
                event = self.packet_queue.get_nowait()
                drained.append(event)
            except queue.Empty:
                break
        return drained

    def ingest_packet_direct(self, packet) -> Optional[PacketEvent]:
        """Direct packet parsing and queue insertion (also used for testing and custom sources)."""
        event = parse_packet_metadata(packet)
        if event is not None:
            self._record_live_event(event)
            try:
                self.packet_queue.put_nowait(event)
            except queue.Full:
                pass
            return event
        return None

    def _packet_callback(self, pkt) -> None:
        """Callback invoked by Scapy for every captured layer 2/3 frame."""
        if self._stop_event.is_set():
            return
        if self.is_paused:
            return

        event = parse_packet_metadata(pkt)
        if event is not None:
            self._record_live_event(event)
            try:
                self.packet_queue.put_nowait(event)
            except queue.Full:
                pass

    def _record_live_event(self, event: PacketEvent) -> None:
        """Records packet into internal ledger and bounded history buffer."""
        now = time.time()
        self.captured_events_buffer.append(event)
        self.captured_packets_count += 1
        self.observed_bytes_count += event.packet_size
        self.unique_src_ips.add(event.src_ip)
        self.unique_dst_ips.add(event.dst_ip)
        self._rate_timestamps.append(now)

    def _worker_loop(self, interface: Optional[str], bpf_filter: Optional[str]) -> None:
        """Continuous sniffing loop executed on background worker thread."""
        try:
            from scapy.all import sniff

            with self._lock:
                self.state = CaptureState.CAPTURING

            kwargs: Dict[str, Any] = {
                "prn": self._packet_callback,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "store": False,
            }
            if interface:
                kwargs["iface"] = interface
            if bpf_filter:
                kwargs["filter"] = bpf_filter

            # Execute blocking sniff until stop_filter signals
            sniff(**kwargs)

            with self._lock:
                if self.state in (CaptureState.CAPTURING, CaptureState.PAUSED):
                    self.state = CaptureState.STOPPED

        except RuntimeError as re:
            with self._lock:
                self.state = CaptureState.ERROR
                self.error_message = f"Capture Driver Error: {re}"
                self.diagnostic_advice = (
                    "Layer 2 packet capture is unavailable. On Windows, Npcap with WinPcap API compatibility is required. "
                    "Download and install Npcap from https://npcap.com/#download."
                )
        except PermissionError as pe:
            with self._lock:
                self.state = CaptureState.ERROR
                self.error_message = f"Socket Permission Error: {pe}"
                self.diagnostic_advice = (
                    "Live network packet capture requires Administrator elevation on Windows or root on Linux.\n"
                    "Please re-launch PowerShell as Administrator."
                )
        except Exception as e:
            with self._lock:
                self.state = CaptureState.ERROR
                self.error_message = f"Capture Failure: {type(e).__name__}: {str(e)}"
                self.diagnostic_advice = (
                    "Capture failed. Please verify that Npcap is installed with WinPcap API compatibility "
                    "and that the selected interface is active and authorized."
                )

    def get_status(self) -> Dict[str, Any]:
        """Returns snapshot telemetry for UI status indicators."""
        return {
            "state": self.state,
            "selected_interface": self.selected_interface or "Default / All",
            "bpf_filter": self.bpf_filter or "None (All Traffic)",
            "captured_packets": self.captured_packets_count,
            "observed_bytes": self.observed_bytes_count,
            "current_rate": self.current_packet_rate,
            "unique_src_ips_count": len(self.unique_src_ips),
            "unique_dst_ips_count": len(self.unique_dst_ips),
            "error_message": self.error_message,
            "diagnostic_advice": self.diagnostic_advice,
            "buffer_size": len(self.captured_events_buffer),
        }
