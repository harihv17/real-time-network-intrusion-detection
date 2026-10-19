import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from simulator.models import ScenarioType
from simulator.generator import TrafficGenerator
from utils.export import export_events_to_csv


def generate_sample_data():
    gen = TrafficGenerator(seed=123)
    events = []
    ts = 1700000000.0

    # 1. 200 normal events
    for _ in range(200):
        ts += 0.1
        events.append(gen.generate_normal_event(timestamp=ts))

    # 2. 50 port scan events
    for _ in range(50):
        ts += 0.05
        events.append(gen.generate_port_scan_event(timestamp=ts))

    # 3. 50 high rate events
    for _ in range(50):
        ts += 0.02
        events.append(gen.generate_high_rate_event(timestamp=ts))

    # 4. 50 syn flood events
    for _ in range(50):
        ts += 0.03
        events.append(gen.generate_syn_flood_event(timestamp=ts))

    # 5. 50 icmp spike events
    for _ in range(50):
        ts += 0.04
        events.append(gen.generate_icmp_spike_event(timestamp=ts))

    # 6. 100 mixed events
    for _ in range(100):
        ts += 0.1
        events.append(gen.generate_mixed_event(timestamp=ts))

    csv_data = export_events_to_csv(events)
    os.makedirs("data", exist_ok=True)
    with open("data/sample_traffic.csv", "w", encoding="utf-8") as f:
        f.write(csv_data)
    print(f"Generated {len(events)} sample events to data/sample_traffic.csv")


if __name__ == "__main__":
    generate_sample_data()
