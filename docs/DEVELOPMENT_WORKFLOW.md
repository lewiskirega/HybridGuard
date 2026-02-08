# Modular and Iterative Development Workflow — HybridGuard

This document describes the **modular and iterative workflow** used (or recommended) for building HybridGuard: separate components developed in phases, then integrated and refined in cycles.

---

## 1. Workflow overview

![Modular and iterative development workflow](hybridguard_development_workflow.png)

*Diagram: seven phases (Config → Sniffer → Signatures → Anomaly → Alerts → Controller & GUI → Test & refine); iterate by changing a module → running tests → running the app → adjusting.*

Development proceeds in **phases**. Each phase adds or refines one **module**; the **controller** and **integration** are updated iteratively so the system stays runnable and testable.

```
Phase 1: Config & features  →  Phase 2: Capture & flows  →  Phase 3: Signatures
        ↓                                                           ↓
Phase 7: Test & refine  ←  Phase 6: Controller & GUI  ←  Phase 5: Alerts  ←  Phase 4: ML
```

---

## 2. Phases (modular and iterative)

### Phase 1: Foundation — config and feature set

- **Module:** `config.py`
- **Goal:** Centralize paths (models, logs), the **21 live feature columns** used everywhere, and signature thresholds (SYN flood, port scan, etc.).
- **Output:** Single source of truth for feature names and constants; no magic numbers in other modules.
- **Iteration:** Add or rename features here; all downstream modules (sniffer, anomaly detector) stay aligned.

### Phase 2: Capture and flow aggregation

- **Module:** `packet_sniffer.py`
- **Goal:** Capture packets (Scapy), group by flow (src/dst IP:port, protocol), compute the **21 flow features** when a flow times out, and pass a feature dict to a callback.
- **Output:** Reusable sniffer that emits the same feature set as defined in config; testable with PCAP replay.
- **Iteration:** Tune flow timeout, add/remove features in config and here; verify with `replay_pcap.py`.

### Phase 3: Signature-based detection

- **Module:** `signature_detector.py`
- **Goal:** Implement rule-based detection: SYN flood, port scan, SQL injection, XSS, ICMP flood, using per-IP state and time windows from config.
- **Output:** `detect(flow_features)` returns a list of alerts; no ML yet.
- **Iteration:** Add new rules or thresholds; run `test_detection.py` to confirm signatures fire as expected.

### Phase 4: ML anomaly detection

- **Module:** `anomaly_detector.py`
- **Goal:** Load pre-trained Isolation Forest and scaler from `models/`, normalize flow features with the same 21 columns, and predict anomaly + severity.
- **Output:** `predict(flow_features)` returns anomaly result or None; works only when model/scaler are present.
- **Iteration:** Ensure feature order and count match config and sniffer; test with `test_detection.py` when model exists.

### Phase 5: Alerts and persistence

- **Module:** `alert_manager.py`
- **Goal:** Store alerts in memory, write to `logs/alerts.log`, support JSON and PDF export, and optional clear-logs-to-disk.
- **Output:** Single place for adding, querying, and exporting alerts; thread-safe.
- **Iteration:** Add export formats or log formats without changing detection logic.

### Phase 6: Controller and GUI

- **Modules:** `main.py` (IDSController), `gui.py`
- **Goal:** Wire sniffer → signature detector → anomaly detector → alert manager; start/stop monitoring; provide Tkinter UI (dashboard, alert table, export, clear).
- **Output:** One entry point (`main.py`), one GUI; all modules used via the controller.
- **Iteration:** Add buttons or views; keep controller thin (delegate to modules).

### Phase 7: Test and refine

- **Artifacts:** `tests/test_detection.py`, `tests/replay_pcap.py`, `scripts/docker-traffic-test.sh`
- **Goal:** Verify detection pipeline without root (simulated flows), with PCAP, or with live-like traffic via Docker/nmap.
- **Iteration:** After any change to signatures, ML, or features, re-run tests and manual checks; fix regressions before the next phase.

---

## 3. Modularity principles

| Principle | How HybridGuard applies it |
|-----------|----------------------------|
| **Single responsibility** | Each of config, sniffer, signature_detector, anomaly_detector, alert_manager, gui has one clear role. |
| **Shared contract** | The 21 feature names in `config.LIVE_FEATURE_COLUMNS` are the contract between sniffer and anomaly detector. |
| **No training in app** | Model and scaler are pre-trained; the app only loads and predicts, so no data_loader or model_trainer in the runtime path. |
| **Controller orchestrates** | `main.py` owns startup, shutdown, and the flow: sniffer callback → signature detect → if no hit, anomaly predict → alert_manager. |
| **Testability** | Signature and ML logic can be tested with synthetic flows (`test_detection.py`) or PCAP (`replay_pcap.py`) without live capture. |

---

## 4. Iteration cycle

1. **Change one module** (e.g. add a signature rule or adjust a threshold).
2. **Run tests** — `python tests/test_detection.py` and, if relevant, `replay_pcap.py`.
3. **Run the app** — `python main.py` (or with sudo for live capture); check GUI and logs.
4. **Adjust config or other modules** if the contract (e.g. feature set) changed.
5. **Repeat** from step 1.

This keeps the system **modular** (clear boundaries) and **iterative** (small, testable steps with a working product at each stage).
