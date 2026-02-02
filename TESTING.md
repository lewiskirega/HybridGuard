# How to Run and Test HybridGuard

This guide answers: **How do I run it? How do I test it and see if it’s working? Do I need VirtualBox?**

---

## Testing with real traffic (quick reference)

| Method | Root? | What you need | Command / steps |
|--------|--------|----------------|-----------------|
| **Live capture (same machine)** | Yes | `sudo` | `sudo python main.py` → Start Monitoring → browse/ping/run tools → watch GUI & `logs/alerts.log` |
| **Live capture (two VMs)** | Yes on VM1 | 2 VMs, same network | VM1: `sudo python main.py` + Start Monitoring. VM2: generate traffic (see below). |
| **PCAP replay** | No | A `.pcap` file | Capture with Wireshark/tcpdump, then: `python tests/replay_pcap.py capture.pcap` |

**Generating traffic that triggers rules (for live or PCAP):**

- **Port scan**: `nmap -sT <target_IP>` (from another machine or VM).
- **SYN flood** (test lab only): `sudo hping3 -S -p 80 --flood <target_IP>` (from VM2 toward VM1).
- **SQLi / XSS**: Browse or `curl 'http://server/?id=1 union select ...'`; capture the traffic, then replay the PCAP or run HybridGuard on the machine that sees that traffic.

**Capture real traffic to a PCAP (no root for replay):**

```bash
# Linux: capture 1000 packets on default interface, save to real_traffic.pcap
sudo tcpdump -i any -w real_traffic.pcap -c 1000

# Then replay through HybridGuard (no root needed):
python tests/replay_pcap.py real_traffic.pcap
```

---

## 1. Run the application

### Without live packet capture (no root)

```bash
cd /path/to/HybridGuard
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -e .
python main.py
```

- The GUI opens. On first run, the app trains a model (1–2 min), then shows the dashboard.
- **Start Monitoring** will fail with a clear message: packet capture needs root. You can still use the GUI and export; detection is tested in step 2.

### With live packet capture (root required)

```bash
sudo python main.py
```

- Click **Start Monitoring**. Capture starts on the default interface.
- Generate traffic (browse, ping, etc.) to see flows and possible alerts.
- Alerts appear in the table and are written to `logs/alerts.log`.

---

## 2. Test that detection works (no root, no VM)

This confirms that **signature and ML logic** work, without needing admin or a VM:

```bash
python tests/test_detection.py
```

- Simulates SQL injection, XSS, SYN flood, and port-scan flows through the same pipeline.
- Expected: **"All signature detection tests PASSED."**
- If the model exists, ML anomaly detection is also exercised.

---

## 3. Test with a PCAP file (no root)

If you have a `.pcap` (e.g. from Wireshark):

```bash
python tests/replay_pcap.py path/to/file.pcap
```

- Packets are replayed through the same flow aggregation and detection as live capture.
- Output shows flow and alert counts.

---

## 4. Do I need VirtualBox?

**No.** You can:

- **Same machine**: Run `python main.py` (or `sudo python main.py` for live capture) and `python tests/test_detection.py` as above.
- **VirtualBox (optional)**: Use two VMs when you want to test with real traffic between two machines (e.g. one runs HybridGuard, the other generates attacks). See README section **“How to Test (full workflow)” → Option B: VirtualBox**.

Summary:

| Goal                         | Need root? | Need VM? | Command / step                    |
|-----------------------------|------------|----------|------------------------------------|
| Open GUI, train/load model  | No         | No       | `python main.py`                   |
| Test detection logic       | No         | No       | `python tests/test_detection.py`   |
| Test with PCAP             | No         | No       | `python tests/replay_pcap.py file.pcap` |
| Live packet capture        | Yes        | No       | `sudo python main.py` → Start Monitoring |
| Real traffic between 2 VMs | Yes (on VM running IDS) | Optional | Two VMs: one runs HybridGuard, other generates traffic |

---

## 5. Quick checklist: “Is it working?”

1. **Install**: `pip install -e .` (inside a venv).
2. **GUI**: `python main.py` → GUI opens, model trains or loads.
3. **Detection test**: `python tests/test_detection.py` → “All signature detection tests PASSED.”
4. **Live capture** (optional): `sudo python main.py` → Start Monitoring → generate traffic → see alerts in GUI and in `logs/alerts.log`.

If steps 2 and 3 succeed, the hybrid intrusion detection system is running and detecting as designed.
