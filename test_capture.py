"""
test_capture.py

Test UniGuard AI passive packet capture.
"""

import logging
import threading
import time

from capture.passive_capture import PassiveCapture
from capture.flow_manager import FlowManager


# ============================================================
# LOGGING CONFIGURATION
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)


# ============================================================
# PACKET CALLBACK
# ============================================================

packet_counter = 0


def on_packet():
    """
    Called whenever a packet is successfully parsed.
    """
    global packet_counter

    packet_counter += 1

    if packet_counter % 10 == 0:
        print(f"Packets captured: {packet_counter}")


# ============================================================
# FLOW CLOSED CALLBACK
# ============================================================

def on_flow_closed(flow):
    """
    Called when a flow is closed by FlowManager.
    """
    try:
        print("\n" + "=" * 60)
        print("FLOW CLOSED")
        print("=" * 60)
        print(flow.to_dict())
        print("=" * 60 + "\n")

    except Exception as exc:
        print(f"Flow display error: {exc}")


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("        UNIGUARD AI - PASSIVE CAPTURE TEST")
    print("=" * 70)
    print("Starting live packet capture...")
    print("Press CTRL+C to stop.")
    print()

    # Create FlowManager
    flow_manager = FlowManager(
        flow_timeout_seconds=10,
        on_flow_closed=on_flow_closed
    )

    # Create PassiveCapture
    capture = PassiveCapture(
        interface=None,
        bpf_filter="ip",
        cleanup_interval_seconds=5,
        flow_manager=flow_manager,
        on_packet=on_packet
    )

    capture_thread = threading.Thread(
        target=capture.start,
        kwargs={
            "packet_count": 0,
            "timeout": None
        },
        daemon=True
    )

    try:
        capture_thread.start()

        while capture_thread.is_alive():
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping passive capture...")

    finally:
        capture.stop()

        # Close remaining active flows
        try:
            flow_manager.sweep_expired(
                now=time.time() + 999999
            )
        except Exception as exc:
            print(f"Final flow cleanup warning: {exc}")

        capture_thread.join(timeout=5)

        print()
        print("=" * 70)
        print("PASSIVE CAPTURE TEST STOPPED")
        print(f"Total packets captured: {packet_counter}")
        print("=" * 70)


if __name__ == "__main__":
    main()