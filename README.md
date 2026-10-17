# UniGuard-AI

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

UniGuard-AI is a machine-learning-based network intrusion / threat detection
system. Its primary design target is **unidirectional IP traffic** — traffic
observed by a sensor that only ever sees ONE direction of a conversation
(a one-way network tap, a data diode, a port mirror placed upstream of
return traffic, or an asymmetrically-routed link, as commonly used in
ICS/SCADA and high-assurance network segregation). It also supports a
conventional bidirectional mode for comparison/benchmarking.

## Why unidirectional matters

Most public IDS datasets (including CIC-IDS2017) and most flow exporters
(CICFlowMeter, NetFlow) are built assuming BOTH directions of a
conversation are visible, and compute features like backward-packet
counts, backward inter-arrival time, and download/upload ratio. A
unidirectional sensor structurally cannot produce those features — it
never observes the reply traffic at all. This project addresses that
constraint end to end:

- `capture/unidirectional_flow_manager.py` groups packets into
  single-direction conversations and never waits for or infers a "reply"
  side. Flow closure is timeout-driven only (a locally observed FIN/RST
  can't be confirmed by a returning ACK on a one-way link).
- A per-source-IP sliding-window profile (`SourceProfile`) tracks how
  many distinct destinations/ports a source has touched and at what
  rate — the primary signal for detecting scans/floods when you can't
  see failed handshakes or RSTs coming back.
- `preprocessing/unidirectional_filter.py` strips every
  backward/bidirectional-only column out of the CIC-IDS2017 export
  before training, so the "unidirectional" model is honestly trained
  only on what a one-way sensor could have computed.
- `features/unidirectional_features.py` and
  `features/feature_schema.py::UNIDIRECTIONAL_FLOW_FEATURES` define the
  live-capture feature set with the same constraint.
- `model/train_model.py --mode unidirectional` and
  `preprocessing/prepare_dataset.py --mode unidirectional` train and
  prepare data specifically for this mode, saving artifacts under a
  `_unidirectional` suffix so both model families coexist.
- `main.py --direction unidirectional` runs the full live pipeline in
  this mode.

The original bidirectional pipeline (`capture/flow_manager.py`,
`features/live_features.py`, default `model/train_model.py`) is kept
as-is for comparison and as a general-purpose NIDS baseline.

## Features

- Passive packet capture and flow reconstruction (`capture/`)
- CIC-IDS2017-based dataset cleaning and preprocessing (`preprocessing/`)
- Statistical, DNS, and TLS metadata feature extraction (`features/`)
- Supervised threat classification + unsupervised anomaly detection (`model/`, `detection/`)
- MITRE ATT&CK mapping, evidence building, and response playbooks (`intelligence/`)
- Alerting pipeline with pluggable channels (`alerts/`)
- Real-time web dashboard (Flask + WebSocket) (`dashboard/`)
- Persistent storage of alerts/flows/metrics (`storage/`)
- System health & throughput monitoring (`monitoring/`)

## Quick start

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

# 1. Place CIC-IDS2017 CSVs in dataset/raw/CIC-IDS2017/
# 2. Clean + prepare the dataset
python preprocessing/clean_dataset.py
python preprocessing/prepare_dataset.py

# 3. Train models
python model/train_model.py

# 4. Evaluate
python model/evaluate_model.py

# 5. Run the full pipeline (capture -> detect -> alert -> dashboard)
python main.py
```

Dashboard will be available at `http://localhost:5000` by default.

## Project layout

See the top-level folders:

| Folder           | Purpose                                              |
|-------------------|-------------------------------------------------------|
| `dataset/`        | Raw + processed CIC-IDS2017 data                      |
| `capture/`        | Live packet capture, flow assembly, replay            |
| `preprocessing/`  | Cleaning, missing-value handling, scaling, validation |
| `features/`       | Feature schema + extraction pipelines                 |
| `model/`          | Training, evaluation, model registry, artifacts       |
| `detection/`      | Real-time threat/anomaly detection engines            |
| `alerts/`         | Alert generation, schema, history                     |
| `intelligence/`   | MITRE mapping, context, playbooks                     |
| `dashboard/`      | Flask + WebSocket UI and REST API                      |
| `storage/`        | DB models & migrations                                |
| `monitoring/`     | Performance & system health monitors                  |
| `tests/`          | Unit/integration tests                                |
| `config/`         | YAML configuration                                    |
| `logs/`           | Runtime logs                                          |

## License

MIT (adjust as needed for your use case).
