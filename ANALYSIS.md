# HybridGuard — Analysis, Recommendations & What to Add

## 1. Work Analysis

### Architecture (strengths)
- **Clear separation of concerns**: Data loading, model training, packet capture, signature rules, ML anomaly detection, alert handling, and GUI are in separate modules.
- **Hybrid design**: Signature-based rules run first; ML (Isolation Forest) runs only when no signature alert fires, which reduces duplicate alerts and keeps logic simple.
- **Thread safety**: `AlertManager` and `PacketSniffer` use locks; GUI updates run on a background thread with `root.after()` for UI updates.
- **Fallback behavior**: If no CIC-IDS2017 data exists, sample data is generated so the app can train and run without the real dataset.
- **Persistence**: Model and scaler are saved/loaded; alerts can be exported to JSON and logged to file.

### Implemented features
| Component | Status | Notes |
|-----------|--------|--------|
| Data loader (CIC-IDS2017 + sample) | ✅ | Handles missing dir/files, inf/nan, median fill |
| Isolation Forest training | ✅ | Contamination 0.1, 100 estimators, metrics + confusion matrix |
| Packet sniffer (Scapy) | ✅ | Flow aggregation, TCP flags, cleanup on timeout |
| Signature detector | ✅ | SYN flood, port scan, SQLi, XSS, ICMP flood |
| Anomaly detector | ✅ | Load model, scale features, score + severity |
| Alert manager | ✅ | In-memory list, file log, JSON export, filters |
| Tkinter GUI | ✅ | Start/stop, stats, filterable alert table, export, log panel |

---

## 2. Does It Work?

**Yes, with caveats.**

- **Startup**: With dependencies installed (`uv sync` or `pip install -e .`), the app should start, train (or load) the model, and open the GUI.
- **Packet capture**: Requires **root/sudo** (or admin on Windows). Without it, the sniffer will fail to start; signature and ML logic still run on any flows you feed in (e.g. from PCAP or tests).
- **ML in production**: There is a **train/serve feature mismatch** (see below). The live sniffer produces fewer features than the CIC-IDS2017 training set; missing ones are passed as 0. The model runs but may be less accurate or biased.

### Bugs / issues found

1. **Port-scan logic (fixed in code)**  
   Per-IP `ports` set was never time-windowed, so after an IP ever reached 20+ distinct ports, every new flow from that IP could trigger “Port Scan” indefinitely. Ports should be limited to a recent time window (e.g. 30 s) like `port_attempts`.

2. **Train/serve feature mismatch**  
   - **Training**: `DataLoader` uses 50+ CIC-IDS2017 features (IAT, header lengths, subflows, etc.).  
   - **Live**: `PacketSniffer.compute_flow_features()` only fills ~20 fields; many (e.g. Fwd/Bwd Packet Length Std, all IAT features, header lengths) are 0 or missing.  
   - **AnomalyDetector** uses 21 features and fills missing with 0. So the model gets a different feature distribution at inference than at training → possible accuracy drop and false positives/negatives.

3. **`Packet Length Std` with one packet**  
   `np.std` on a single value is NaN; the sniffer can emit NaN for single-packet flows. Anomaly detector coerces NaN to 0, but it’s better to fix at the source (e.g. 0 when `len(packet_lengths) < 2`).

---

## 3. Recommendations

### High priority
1. **Align live features with training**  
   - Either extend `compute_flow_features()` to compute IAT (inter-arrival times), fwd/bwd packet length std, and any other CIC-style stats you use in training, or  
   - Train a model only on the subset of features that the sniffer actually produces, and use that same subset in `AnomalyDetector.feature_columns`.

2. **Time-window port-scan state**  
   Keep only ports (and attempts) from the last 30 seconds per IP so “port scan” reflects recent behavior (already fixed in code).

3. **Harden single-packet flows**  
   In `compute_flow_features()`, set `Packet Length Std` (and any other std/variance) to 0 when there’s only one packet to avoid NaN.

4. **Install/run instructions**  
   In README, add:
   - `uv sync` or `pip install -e .` (or `pip install -r requirements.txt` if you add one).
   - Run with `sudo python main.py` (or admin shell on Windows) for packet capture.

### Medium priority
5. **Limit in-memory growth**  
   - `SignatureDetector.ip_stats`: call `cleanup_old_stats()` periodically (e.g. from the sniffer cleanup loop or a timer) so long-running runs don’t grow unbounded.  
   - Optionally cap `AlertManager.alerts` by count and/or age.

6. **Graceful handling when sniffer fails**  
   If `PacketSniffer.start()` fails (e.g. no privileges), show a clear message in the GUI and keep the app usable (e.g. “Monitoring unavailable – need root”).

7. **Config file**  
   Move magic numbers (SYN threshold 100, port-scan 20 ports / 30 s, flow timeout, model path, log dir) into a config (e.g. YAML/JSON or `pyproject.toml` [tool.hybridguard]) so you can tune without editing code.

### Lower priority
8. **Unit tests**  
   Add tests for: `DataLoader` (sample data + preprocess), `SignatureDetector` (each rule with fixed inputs), `AnomalyDetector.preprocess_features` and `predict` (with a tiny saved model or mock), and `AlertManager` (add/filter/export).

9. **Logging**  
   Use a single logging config (e.g. in `main.py`) and avoid `logging.basicConfig` in multiple modules so log level and format stay consistent.

10. **pyproject.toml**  
    Set `name = "hybridguard"` and add a `[project.scripts]` entry point so users can run `hybridguard` after install.

---

## 4. What to Add

### Features
- **PCAP replay**: Load a PCAP file and run the same pipeline (signature + ML) without live capture — useful for testing and demos.
- **Retrain from GUI**: Button/menu to “Retrain model” (with current data path or sample data) and reload the model without restarting.
- **Basic reporting**: Daily/weekly summary (counts by type/severity, top sources) and optional HTML/PDF export.
- **Whitelist**: Ignore alerts from certain IPs or subnets (config or simple file).
- **Notifications**: Optional email or webhook when severity is CRITICAL (or configurable).
- **Simple dashboard metrics**: Packets/sec, flows/sec, alert rate over last 1/5/15 minutes.

### Security / operations (as in README)
- Log rotation and secure storage for `logs/`.
- Optional authentication for the GUI (e.g. local-only + password or SSO).
- Encrypt or restrict access to exported alert files if they contain sensitive data.

### Code quality
- **Type hints** on public functions and main classes.
- **requirements.txt** (or keep only `pyproject.toml`) and document one clear install path.
- **CI**: Lint (e.g. ruff) + tests on push/PR.

---

## 5. Summary

| Question | Answer |
|----------|--------|
| **Does it work?** | Yes: app starts, trains/loads model, GUI runs; packet capture needs root. |
| **Is the design sound?** | Yes: hybrid signature + ML, clear modules, thread-safe alerts. |
| **Main risk?** | Train/serve feature mismatch and port-scan state not time-windowed (latter fixed). |
| **Next steps** | Align live features with training (or train on sniffer features only), fix NaN for single-packet flows, add install/run docs and optional tests/config. |

Implementing the high-priority recommendations will make the system more reliable and easier to deploy; the “What to add” section gives a roadmap for future improvements.
