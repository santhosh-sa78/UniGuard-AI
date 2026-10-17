"""
main.py
============================================================
UniGuard-AI - Unidirectional Network Threat Detection
============================================================

Supports:
    - Live passive capture
    - PCAP / PCAPNG replay
    - CIC-IDS2017 CSV replay
    - 48-feature scaled CSV detection
    - Dashboard integration

Dashboard:
    http://127.0.0.1:5000
============================================================
"""

from __future__ import annotations

import argparse
from collections import deque
import logging
import logging.config
import os
import sys
import threading
import time

from pathlib import Path
from typing import Optional

import yaml

BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from capture.passive_capture import (
    PassiveCapture,
    load_config as load_capture_config,
)
from capture.replay_engine import ReplayEngine
from capture.unidirectional_flow_manager import (
    UniFlow,
    UnidirectionalFlowManager,
)
from features.unidirectional_pipeline import (
    UnidirectionalFeaturePipeline,
)
from features.feature_schema import (
    UNIDIRECTIONAL_FLOW_FEATURES,
)
from detection.threat_detector import ThreatDetector
from alerts.alert_manager import AlertManager
from alerts.alert_system import AlertSystem
from monitoring.performance_monitor import (
    PerformanceMonitor,
    StageTimer,
)
from monitoring.throughput_monitor import ThroughputMonitor

logger = logging.getLogger("uniguard.main")


# ============================================================
# LOGGING
# ============================================================

def setup_logging():
    log_dir = BASE_DIR / "logs"

    (log_dir / "system_logs").mkdir(
        parents=True,
        exist_ok=True,
    )

    (log_dir / "performance_logs").mkdir(
        parents=True,
        exist_ok=True,
    )

    log_config_path = (
        BASE_DIR / "config" / "logging.yaml"
    )

    if log_config_path.exists():
        try:
            with open(
                log_config_path,
                "r",
                encoding="utf-8",
            ) as file:
                config = yaml.safe_load(file)

            logging.config.dictConfig(config)

        except Exception as exc:
            print(
                f"Logging configuration failed: {exc}"
            )

            logging.basicConfig(
                level=logging.INFO,
                format=(
                    "%(asctime)s "
                    "[%(levelname)s] "
                    "%(name)s: %(message)s"
                ),
            )

    else:
        logging.basicConfig(
            level=logging.INFO,
            format=(
                "%(asctime)s "
                "[%(levelname)s] "
                "%(name)s: %(message)s"
            ),
        )


# ============================================================
# LIVE DASHBOARD RATE TRACKER
# ============================================================

class LiveRateTracker:
    """Thread-safe rolling counters used for live dashboard updates."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._packets = deque()
        self._flows = deque()
        self._detections = deque()

    def _trim(self, values, now):
        cutoff = now - self.window_seconds
        while values and values[0] < cutoff:
            values.popleft()

    def _record(self, values):
        now = time.monotonic()
        with self._lock:
            values.append(now)
            self._trim(values, now)

    def record_packet(self):
        self._record(self._packets)

    def record_flow(self):
        self._record(self._flows)

    def record_detection(self):
        self._record(self._detections)

    def snapshot(self):
        now = time.monotonic()
        with self._lock:
            self._trim(self._packets, now)
            self._trim(self._flows, now)
            self._trim(self._detections, now)

            divisor = self.window_seconds
            return {
                "packets_per_second": len(self._packets) / divisor,
                "flows_per_second": len(self._flows) / divisor,
                "detections_per_second": len(self._detections) / divisor,
            }


# ============================================================
# UNIGUARD PIPELINE
# ============================================================

class UniGuardPipeline:

    def __init__(
        self,
        detection_threshold: float = 0.75,
    ):

        logger.info(
            "Initializing UniGuard-AI pipeline..."
        )

        logger.info(
            "Traffic direction: UNIDIRECTIONAL"
        )

        # ----------------------------------------------------
        # MONITORS
        # ----------------------------------------------------

        self.performance_monitor = (
            PerformanceMonitor()
        )

        self.throughput_monitor = (
            ThroughputMonitor(
                window_seconds=60.0
            )
        )

        # Independent rolling counters for true live WebSocket updates.
        # The existing ThroughputMonitor remains the source for REST APIs.
        self.live_rate_tracker = LiveRateTracker(
            window_seconds=2.0
        )

        self.alert_system = AlertSystem()

        self.alert_manager = AlertManager(
            on_alert=self._dispatch_alert
        )

        logger.info(
            "Shared monitors initialized successfully."
        )

        # ----------------------------------------------------
        # AI MODEL
        # ----------------------------------------------------

        self.detector: Optional[ThreatDetector] = None
        self.models_ready = False

        try:

            self.detector = ThreatDetector(
                detection_threshold=detection_threshold,
                feature_names=UNIDIRECTIONAL_FLOW_FEATURES,
                mode="unidirectional",
            )

            self.models_ready = True

            logger.info(
                "Threat detection model loaded successfully."
            )

        except FileNotFoundError as exc:

            logger.warning(
                "AI model not found: %s",
                exc,
            )

            logger.warning(
                "AI detection disabled."
            )

        except Exception as exc:

            logger.exception(
                "ThreatDetector initialization failed: %s",
                exc,
            )

        # ----------------------------------------------------
        # FLOW MANAGER
        # ----------------------------------------------------

        self.flow_manager = (
            UnidirectionalFlowManager(
                flow_timeout_seconds=10,
                source_window_seconds=10,
                on_flow_closed=self.on_flow_closed,
            )
        )

        logger.info(
            "Unidirectional flow manager initialized."
        )

        # ----------------------------------------------------
        # FEATURE PIPELINE
        # ----------------------------------------------------

        self.feature_pipeline = (
            UnidirectionalFeaturePipeline(
                flow_manager=self.flow_manager,
                on_vector_ready=self._on_vector_ready,
            )
        )

        logger.info(
            "Unidirectional feature pipeline initialized."
        )

    # ========================================================
    # LIVE PACKET CALLBACK
    # ========================================================

    def on_packet(self, *args, **kwargs):
        """Record a captured packet and update live dashboard counters."""
        try:
            result = self.throughput_monitor.record_packet(
                *args, **kwargs
            )
        finally:
            self.live_rate_tracker.record_packet()

        return result

    # ========================================================
    # ALERT DISPATCH
    # ========================================================

    def _dispatch_alert(self, alert):

        try:
            self.alert_system.dispatch(alert)

        except Exception as exc:
            logger.exception(
                "AlertSystem dispatch failed: %s",
                exc,
            )

        self.throughput_monitor.record_detection()
        self.live_rate_tracker.record_detection()

        logger.info(
            "Threat detected: %s",
            getattr(
                alert,
                "threat_type",
                "Unknown",
            ),
        )

        try:

            from dashboard.websocket_server import (
                broadcast_alert,
            )

            broadcast_alert(
                alert.to_dict()
            )

        except Exception as exc:

            logger.debug(
                "Alert broadcast failed: %s",
                exc,
            )

    # ========================================================
    # LIVE VECTOR CALLBACK
    # ========================================================

    def _on_vector_ready(
        self,
        flow: UniFlow,
        vector,
    ):

        if not self.models_ready:
            logger.warning(
                "Skipping detection: model unavailable."
            )
            return
        
        self.throughput_monitor.record_packet()
        self.throughput_monitor.record_flow()

        self.live_rate_tracker.record_packet()
        self.live_rate_tracker.record_flow()

        try:

            with StageTimer(
                self.performance_monitor,
                "detection",
            ):

                detection = self.detector.analyze(
                    flow,
                    vector,
                )

            if detection:

                self.alert_manager.create_alert_from_detection(
                    detection
                )

        except Exception as exc:

            logger.exception(
                "Detection failed: %s",
                exc,
            )

    # ========================================================
    # CSV VECTOR CALLBACK
    # ========================================================

    def _on_csv_vector_ready(
        self,
        flow,
        vector,
    ):

        if not self.models_ready:

            logger.warning(
                "Skipping CSV detection: model unavailable."
            )

            return

        # Update replay traffic counters
        self.throughput_monitor.record_packet()
        self.throughput_monitor.record_flow()

        self.live_rate_tracker.record_packet()
        self.live_rate_tracker.record_flow()

        try:

            with StageTimer(
                self.performance_monitor,
                "detection",
            ):

                detection = self.detector.analyze(
                    flow,
                    vector,
                )

            if detection:

                self.alert_manager.create_alert_from_detection(
                    detection
                )

        except Exception as exc:

            logger.exception(
                "CSV replay detection failed: %s",
                exc,
            )
    # ========================================================
    # FLOW CLOSED
    # ========================================================

    def on_flow_closed(
        self,
        flow: UniFlow,
    ):

        logger.info(
            "Unidirectional flow closed: "
            "%s -> %s | protocol=%s | packets=%s",
            flow.src_ip,
            flow.dst_ip,
            flow.protocol,
            flow.total_packets(),
        )

        self.throughput_monitor.record_flow()
        self.live_rate_tracker.record_flow()

        start_time = time.perf_counter()

        try:

            with StageTimer(
                self.performance_monitor,
                "feature_extraction",
            ):

                self.feature_pipeline.process_flow(
                    flow
                )

            total_ms = (
                time.perf_counter() - start_time
            ) * 1000

            self.performance_monitor.record_latency(
                total_ms
            )

        except Exception as exc:

            logger.exception(
                "Feature extraction failed: %s",
                exc,
            )


# ============================================================
# LIVE DASHBOARD BROADCAST
# ============================================================

def live_dashboard_broadcast_loop(
    pipeline: UniGuardPipeline,
    stop_event: threading.Event,
):
    """Push live packet/flow/detection rates to connected dashboards."""
    try:
        from dashboard.websocket_server import broadcast_throughput
    except Exception as exc:
        logger.exception(
            "Live dashboard broadcaster could not start: %s",
            exc,
        )
        return

    logger.info(
        "Live dashboard broadcast thread started."
    )

    while not stop_event.wait(1.0):
        try:
            stats = pipeline.live_rate_tracker.snapshot()
            broadcast_throughput(stats)
        except Exception as exc:
            logger.debug(
                "Live dashboard broadcast failed: %s",
                exc,
            )


# ============================================================
# LIVE PASSIVE CAPTURE
# ============================================================

def run_passive(
    pipeline: UniGuardPipeline,
):

    cfg = load_capture_config()

    interface = cfg.get(
        "interface"
    )

    bpf_filter = cfg.get(
        "bpf_filter",
        "ip",
    )

    flow_timeout = cfg.get(
        "flow_timeout_seconds",
        60,
    )

    cleanup_interval = cfg.get(
        "flow_cleanup_interval_seconds",
        10,
    )

    logger.info(
        "=================================================="
    )

    logger.info(
        "STARTING LIVE PASSIVE CAPTURE"
    )

    logger.info(
        "Interface: %s",
        interface,
    )

    logger.info(
        "BPF Filter: %s",
        bpf_filter,
    )

    logger.info(
        "Direction: UNIDIRECTIONAL"
    )

    logger.info(
        "=================================================="
    )

    capture = PassiveCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        flow_timeout_seconds=flow_timeout,
        cleanup_interval_seconds=cleanup_interval,
        flow_manager=pipeline.flow_manager,
        on_packet=pipeline.on_packet,
    )

    logger.info(
        "PassiveCapture object created successfully."
    )

    logger.info(
        "Waiting for live packets..."
    )

    try:

        capture.start()

    except KeyboardInterrupt:

        logger.info(
            "Capture interrupted."
        )

        capture.stop()

    except Exception as exc:

        logger.exception(
            "Passive capture failed: %s",
            exc,
        )

        try:
            capture.stop()
        except Exception:
            pass

        raise


# ============================================================
# REPLAY
# ============================================================

def run_replay(
    pipeline: UniGuardPipeline,
    path: str,
    realtime: bool,
    max_rows: Optional[int] = None,
    skip_benign: bool = False,
):

    target = Path(path)

    if not target.exists():

        raise FileNotFoundError(
            f"Replay path not found: {target}"
        )

    logger.info(
        "=================================================="
    )

    logger.info(
        "STARTING UNIGUARD-AI REPLAY"
    )

    logger.info(
        "Replay path: %s",
        target,
    )

    logger.info(
        "Direction: UNIDIRECTIONAL"
    )

    logger.info(
        "=================================================="
    )

    engine = ReplayEngine(
        flow_manager=pipeline.flow_manager,
        on_flow_closed=pipeline.on_flow_closed,
        on_csv_vector_ready=pipeline._on_csv_vector_ready,
    )

    # --------------------------------------------------------
    # SINGLE FILE
    # --------------------------------------------------------

    if target.is_file():

        suffix = target.suffix.lower()

        if suffix == ".csv":

            logger.info(
                "CSV replay selected: %s",
                target.name,
            )

            processed = engine.replay_csv(
                str(target),
                max_rows=max_rows,
                skip_benign=skip_benign,
                realtime=realtime,
            )

            logger.info(
                "CSV replay finished: %d rows",
                processed,
            )

            return

        if suffix in (
            ".pcap",
            ".pcapng",
        ):

            logger.info(
                "PCAP replay selected: %s",
                target.name,
            )

            processed = engine.replay_pcap(
                str(target),
                realtime=realtime,
            )

            logger.info(
                "PCAP replay finished: %d packets",
                processed,
            )

            return

        raise ValueError(
            f"Unsupported replay file: {target}"
        )

    # --------------------------------------------------------
    # DIRECTORY
    # --------------------------------------------------------

    csv_files = sorted(
        target.glob("*.csv")
    )

    pcap_files = sorted(
        target.glob("*.pcap")
    )

    pcap_files.extend(
        sorted(target.glob("*.pcapng"))
    )

    # --------------------------------------------------------
    # CSV DIRECTORY
    # --------------------------------------------------------

    if csv_files:

        logger.info(
            "CIC-IDS2017 CSV files found: %d",
            len(csv_files),
        )

        total_rows = 0

        for csv_file in csv_files:

            logger.info(
                "--------------------------------------------------"
            )

            logger.info(
                "Replaying CSV: %s",
                csv_file.name,
            )

            rows = engine.replay_csv(
                str(csv_file),
                max_rows=max_rows,
                skip_benign=skip_benign,
                realtime=realtime,
            )

            total_rows += rows

        logger.info(
            "=================================================="
        )

        logger.info(
            "ALL CSV REPLAY COMPLETE"
        )

        logger.info(
            "Total rows processed: %d",
            total_rows,
        )

        logger.info(
            "=================================================="
        )

        return

    # --------------------------------------------------------
    # PCAP DIRECTORY
    # --------------------------------------------------------

    if pcap_files:

        logger.info(
            "PCAP files found: %d",
            len(pcap_files),
        )

        total_packets = 0

        for pcap_file in pcap_files:

            logger.info(
                "Replaying PCAP: %s",
                pcap_file.name,
            )

            total_packets += engine.replay_pcap(
                str(pcap_file),
                realtime=realtime,
            )

        logger.info(
            "=================================================="
        )

        logger.info(
            "ALL PCAP REPLAY COMPLETE"
        )

        logger.info(
            "Total packets processed: %d",
            total_packets,
        )

        logger.info(
            "=================================================="
        )

        return

    logger.warning(
        "No .csv, .pcap or .pcapng files found in: %s",
        target,
    )


# ============================================================
# DASHBOARD
# ============================================================

def run_dashboard(
    pipeline: UniGuardPipeline,
):

    from dashboard.app import create_app
    from dashboard.websocket_server import socketio

    host = os.getenv(
        "DASHBOARD_HOST",
        "127.0.0.1",
    )

    port = int(
        os.getenv(
            "DASHBOARD_PORT",
            "5000",
        )
    )

    app = create_app(
        performance_monitor=(
            pipeline.performance_monitor
        ),
        throughput_monitor=(
            pipeline.throughput_monitor
        ),
        alert_manager=(
            pipeline.alert_manager
        ),
    )

    logger.info(
        "=================================================="
    )

    logger.info(
        "UNIGUARD-AI DASHBOARD STARTED"
    )

    logger.info(
        "Website: http://%s:%d",
        host,
        port,
    )

    logger.info(
        "Dashboard uses shared pipeline monitors."
    )

    logger.info(
        "=================================================="
    )

    try:

        socketio.run(
            app,
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
        )

    except Exception as exc:

        logger.exception(
            "Dashboard failed to start: %s",
            exc,
        )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "UniGuard-AI "
            "Unidirectional Threat Detection"
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "passive",
            "replay",
        ],
        default="passive",
        help="Execution mode.",
    )

    parser.add_argument(
        "--path",
        help=(
            "PCAP/PCAPNG file, CIC CSV file, "
            "or replay directory."
        ),
    )

    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Replay using realtime pacing.",
    )

    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help=(
            "Maximum number of CSV rows to replay."
        ),
    )

    parser.add_argument(
        "--skip-benign",
        action="store_true",
        help=(
            "Skip BENIGN rows during CSV replay."
        ),
    )

    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help=(
            "Run capture/replay without dashboard."
        ),
    )

    parser.add_argument(
        "--detection-threshold",
        type=float,
        default=0.75,
        help="AI detection confidence threshold.",
    )

    args = parser.parse_args()

    setup_logging()

    logger.info(
        "=================================================="
    )

    logger.info(
        "UNIGUARD-AI STARTING"
    )

    logger.info(
        "Mode: %s",
        args.mode,
    )

    logger.info(
        "Direction: UNIDIRECTIONAL"
    )

    logger.info(
        "Detection threshold: %.2f",
        args.detection_threshold,
    )

    if args.max_rows is not None:

        logger.info(
            "CSV max rows: %d",
            args.max_rows,
        )

    if args.skip_benign:

        logger.info(
            "BENIGN rows will be skipped."
        )

    logger.info(
        "=================================================="
    )

    pipeline = UniGuardPipeline(
        detection_threshold=(
            args.detection_threshold
        )
    )

    live_broadcast_stop = threading.Event()
    live_broadcast_thread = None

    if not args.no_dashboard:

        dashboard_thread = threading.Thread(
            target=run_dashboard,
            args=(pipeline,),
            daemon=True,
            name="UniGuard-Dashboard",
        )

        dashboard_thread.start()

        logger.info(
            "Dashboard thread started."
        )

        time.sleep(2)

        live_broadcast_thread = threading.Thread(
            target=live_dashboard_broadcast_loop,
            args=(
                pipeline,
                live_broadcast_stop,
            ),
            daemon=True,
            name="UniGuard-Live-Dashboard-Broadcast",
        )
        live_broadcast_thread.start()

    try:

        if args.mode == "passive":

            run_passive(
                pipeline
            )

        elif args.mode == "replay":

            if not args.path:

                parser.error(
                    "--path is required in replay mode."
                )

            run_replay(
                pipeline=pipeline,
                path=args.path,
                realtime=args.realtime,
                max_rows=args.max_rows,
                skip_benign=args.skip_benign,
            )

    except KeyboardInterrupt:

        logger.info(
            "Shutting down UniGuard-AI..."
        )

    except Exception as exc:

        logger.exception(
            "UniGuard-AI stopped because of an error: %s",
            exc,
        )

        raise

    finally:

        live_broadcast_stop.set()

        logger.info(
            "UniGuard-AI stopped."
        )


if __name__ == "__main__":
    main()