"""Stateful simulation engine managing buffer, timing, and scenario controls."""

from collections import deque
import time
from typing import List, Optional, Set
from simulator.models import PacketEvent, ScenarioType
from simulator.generator import TrafficGenerator
from utils.config import SimulatorConfig, DEFAULT_CONFIG


class SimulationEngine:
    """Manages the real-time or discrete stepped execution of traffic simulation."""

    def __init__(self, config: Optional[SimulatorConfig] = None):
        self.config = config or DEFAULT_CONFIG.simulator
        self.generator = TrafficGenerator(seed=self.config.random_seed)
        self.is_running: bool = False
        self.is_paused: bool = False
        self.current_scenario: ScenarioType = ScenarioType.NORMAL
        self.events_per_second: float = self.config.default_events_per_second

        # Bounded in-memory event deque to prevent memory leaks
        self.event_buffer: deque[PacketEvent] = deque(maxlen=self.config.max_history_events)

        # Cumulative telemetry
        self.total_events: int = 0
        self.total_bytes: int = 0
        self.unique_src_ips: Set[str] = set()
        self.unique_dst_ips: Set[str] = set()
        self.start_time: float = time.time()
        self._last_tick_time: float = time.time()
        self._simulated_clock: float = 1000.0  # Normalized epoch for reproducible runs

    def start(self) -> None:
        """Starts the active simulation."""
        self.is_running = True
        self.is_paused = False
        self._last_tick_time = time.time()

    def pause(self) -> None:
        """Pauses the simulation without losing state or history."""
        self.is_paused = True

    def stop(self) -> None:
        """Stops the active simulation without clearing history or counters."""
        self.is_running = False
        self.is_paused = False

    def resume(self) -> None:
        """Resumes a paused simulation."""
        self.is_paused = False
        self._last_tick_time = time.time()

    def reset(self, new_seed: Optional[int] = None) -> None:
        """Completely resets state, counters, buffers, and generator."""
        self.is_running = False
        self.is_paused = False
        self.event_buffer.clear()
        self.total_events = 0
        self.total_bytes = 0
        self.unique_src_ips.clear()
        self.unique_dst_ips.clear()
        self.start_time = time.time()
        self._last_tick_time = time.time()
        self._simulated_clock = 1000.0
        seed = new_seed if new_seed is not None else self.config.random_seed
        self.generator.seed(seed)

    def set_scenario(self, scenario: ScenarioType) -> None:
        """Changes the current traffic scenario."""
        self.current_scenario = scenario

    def set_rate(self, rate: float) -> None:
        """Updates the target events per second rate."""
        self.events_per_second = max(0.5, float(rate))

    def step(self, num_events: int = 1, use_real_timestamp: bool = True) -> List[PacketEvent]:
        """Generates a discrete batch of events. Useful for tests and deterministic stepping."""
        generated: List[PacketEvent] = []
        for _ in range(num_events):
            if use_real_timestamp:
                ts = time.time()
            else:
                # High-rate volumetric scenario generates bursts with sub-window inter-packet intervals
                effective_rate = self.events_per_second * 3.0 if self.current_scenario == ScenarioType.HIGH_RATE else self.events_per_second
                self._simulated_clock += (1.0 / effective_rate)
                ts = self._simulated_clock

            event = self.generator.generate_event(self.current_scenario, timestamp=ts)
            self._record_event(event)
            generated.append(event)
        return generated

    def tick(self, current_time: Optional[float] = None) -> List[PacketEvent]:
        """Processes elapsed time and produces the appropriate number of events."""
        if not self.is_running or self.is_paused:
            return []

        now = current_time if current_time is not None else time.time()
        elapsed = now - self._last_tick_time
        self._last_tick_time = now

        # Compute number of events due based on elapsed time and target rate
        events_to_generate = int(elapsed * self.events_per_second)
        if events_to_generate <= 0:
            return []

        # Bound single tick burst to prevent freezing during lag
        events_to_generate = min(events_to_generate, 100)
        return self.step(num_events=events_to_generate, use_real_timestamp=True)

    def _record_event(self, event: PacketEvent) -> None:
        """Internal ledger update."""
        self.event_buffer.append(event)
        self.total_events += 1
        self.total_bytes += event.packet_size
        self.unique_src_ips.add(event.src_ip)
        self.unique_dst_ips.add(event.dst_ip)

    def get_recent_events(self, limit: int = 100) -> List[PacketEvent]:
        """Retrieves a slice of the most recent events."""
        if limit <= 0:
            return []
        items = list(self.event_buffer)
        return items[-limit:]

    def get_summary_stats(self) -> dict:
        """Computes current high-level telemetry."""
        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "current_scenario": self.current_scenario.value,
            "events_per_second": self.events_per_second,
            "total_events": self.total_events,
            "total_bytes": self.total_bytes,
            "unique_src_ips_count": len(self.unique_src_ips),
            "unique_dst_ips_count": len(self.unique_dst_ips),
            "buffer_size": len(self.event_buffer),
        }
