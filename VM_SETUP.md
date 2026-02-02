# HybridGuard VM Testing Guide

This guide explains how to test HybridGuard with **real traffic** using two virtual machines: one runs the IDS, the other generates traffic (including attacks).

---

## Recommended OS for Each VM

| VM | Role | Recommended OS | Why |
|----|------|----------------|-----|
| **VM 1** | HybridGuard (IDS) | **Ubuntu 22.04 LTS** (Server or Desktop) | Python 3.10+, easy `sudo`, stable. |
| **VM 2** | Traffic / attack generator | **Ubuntu 22.04 LTS** or **Kali Linux** / **Parrot OS** | Ubuntu: `nmap`, `hping3` via apt. Kali/Parrot: security tools preinstalled. |

**Practical choice:** Use **Ubuntu 22.04 LTS** for both VMs if you want a simple, consistent setup. Use Kali or Parrot for VM 2 if you prefer a security-focused distro with tools already installed.

---

## 1. Create the VMs (VirtualBox)

1. **Install VirtualBox** on your host (https://www.virtualbox.org/).
2. **Create VM 1 (IDS):**
   - New VM → Name: `HybridGuard-IDS` → Type: Linux → Version: Ubuntu (64-bit).
   - Memory: 2048 MB or more.
   - Create a virtual hard disk (VDI, ~20 GB).
   - Settings → Network → Adapter 1: **Host-only Adapter** (recommended; see “Network” section below).
3. **Create VM 2 (Traffic generator):**
   - New VM → Name: `HybridGuard-Attacker` → Type: Linux → Version: Ubuntu (64-bit).
   - Memory: 1024 MB is enough.
   - Create a virtual hard disk (~15 GB).
   - Settings → Network → Adapter 1: **Host-only Adapter** (same as VM 1 so they can talk).
4. **Install the OS** on both VMs (attach Ubuntu ISO, install, set user/password).

---

## 2. VM 1 – Install and Run HybridGuard

1. **Install Python and dependencies (Ubuntu):**
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv
   ```
2. **Copy the HybridGuard project** into the VM (e.g. shared folder, USB, or `git clone`/scp).
3. **From the project directory:**
   ```bash
   cd /path/to/HybridGuard
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```
4. **Run HybridGuard with root** (required for packet capture):
   ```bash
   sudo $(which python3) main.py
   ```
   Or activate the venv and use the venv’s Python with sudo:
   ```bash
   source .venv/bin/activate
   sudo .venv/bin/python main.py
   ```
5. In the GUI, click **Start Monitoring**. Leave the window open.
6. **Note VM 1’s IP** (e.g. `ip addr` or `hostname -I`). You’ll use it from VM 2.

---

## 3. VM 2 – Generate Traffic

1. **Install tools (Ubuntu):**
   ```bash
   sudo apt update
   sudo apt install -y nmap hping3 curl
   ```
   Replace `VM1_IP` below with VM 1’s actual IP (e.g. `192.168.56.101` in Host-only).

2. **Port scan** (should trigger “Port Scan” on VM 1):
   ```bash
   nmap -sT VM1_IP
   ```

3. **SYN flood** (test lab only; should trigger “SYN Flood”):
   ```bash
   sudo hping3 -S -p 80 --flood VM1_IP
   ```
   Run for a few seconds then stop (Ctrl+C).

4. **HTTP with SQLi-like payload** (if VM 1 or a server in the same network sees the traffic):
   ```bash
   curl "http://VM1_IP/?id=1%20union%20select%20*%20from%20users--"
   ```
   Signature detection only sees this if HybridGuard is capturing the interface that carries this traffic.

---

## 4. Which IP address to use

**Use VM 1’s IP address** in all commands you run on VM 2 (port scan, SYN flood, curl). That’s the machine running HybridGuard; traffic to that IP is what the IDS sees.

**Find VM 1’s IP (on VM 1):**

```bash
# Option 1: short list of addresses
hostname -I

# Option 2: full interface list (look for the Host-only adapter, e.g. enp0s3 or eth0)
ip addr
```

- With **Host-only**, VM 1 usually gets an address like **`192.168.56.101`** (VirtualBox often uses `192.168.56.0/24`). The exact number can be `192.168.56.101`, `192.168.56.102`, etc.
- With **Bridged**, VM 1 gets an IP on your LAN (e.g. `192.168.1.x`). Use that.

**On VM 2**, use that IP in place of `VM1_IP`:

```bash
# Example: if VM 1’s IP is 192.168.56.101
nmap -sT 192.168.56.101
sudo hping3 -S -p 80 --flood 192.168.56.101
```

You do **not** need to configure a fixed IP. Use whatever address VM 1 shows from `hostname -I` or `ip addr` on the Host-only (or Bridged) interface.

---

## 5. Check Results on VM 1

- **GUI:** Alerts appear in the table (severity, type, source IP).
- **Log file:** `logs/alerts.log` (same directory as `main.py`).
- **Export:** Use “Export Alerts” in the GUI to save alerts to JSON in `logs/`.

---

## 6. Which network to use in VirtualBox

**Use Host-only for this setup.**

| Network type   | What it does | When to use it |
|----------------|--------------|----------------|
| **Host-only**  | VMs and host share a private network. VMs can talk to each other and the host, but not the internet or your LAN. | **Recommended for HybridGuard testing.** Isolated and safe; no impact on other devices. |
| **Bridged**    | Each VM gets an IP on your real LAN (same as your PC). VMs can reach the internet and other LAN devices. | Only if you need internet inside the VMs or to test from another physical machine. Use only in a lab you control. |
| **NAT**         | VMs share one “NAT” connection; they can reach the internet but usually not each other easily. | Not suitable here; VM 2 must reach VM 1 for traffic to be seen by the IDS. |
| **Internal**    | VMs on the same “internal” virtual network; no host, no internet. | Works too, but Host-only is simpler (host can still SSH/copy to VMs). |

**Steps for Host-only:**

1. In VirtualBox: **File → Host Network Manager** → create or use the default “VirtualBox Host-Only Ethernet Adapter”.
2. For **both** VM 1 and VM 2: **Settings → Network → Adapter 1** → enable **Host-only Adapter** → choose that adapter (e.g. “VirtualBox Host-Only Ethernet Adapter”).
3. Start both VMs. On VM 2, run `ping <VM1_IP>` (get VM 1’s IP with `ip addr` or `hostname -I` on VM 1). If ping works, the IDS on VM 1 will see traffic from VM 2.

Use the **same** adapter type for both VMs so they are on the same network.

---

## 7. Troubleshooting

| Issue | What to do |
|-------|------------|
| “Failed to start monitoring” on VM 1 | Run with `sudo` and ensure no other sniffer is using the interface. |
| No alerts for port scan / SYN | Confirm VM 2’s traffic goes through VM 1’s monitored interface (same VirtualBox network). Ping VM1_IP from VM 2. |
| Can’t copy project into VM | Use VirtualBox “Shared Folders” or copy via `scp` from host to VM. |

---

## 8. Quick Checklist

1. [ ] VM 1 and VM 2 created in VirtualBox, same network (Host-only or Bridged).
2. [ ] Ubuntu (or chosen OS) installed on both.
3. [ ] VM 1: Python, venv, `pip install -e .`, then `sudo python main.py` → Start Monitoring.
4. [ ] VM 2: `nmap`, `hping3` installed; run `nmap -sT VM1_IP` and optionally `sudo hping3 -S -p 80 --flood VM1_IP`.
5. [ ] VM 1: Check GUI and `logs/alerts.log` for Port Scan and SYN Flood alerts.
