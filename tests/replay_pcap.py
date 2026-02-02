#!/usr/bin/env python3
"""
Replay a PCAP file through HybridGuard detection (no root required).

Loads packets with Scapy, feeds them into the same flow aggregation and
detection pipeline as live capture, then prints flow and alert counts.
Useful for testing with real traffic captured via tcpdump or Wireshark.

Usage: python tests/replay_pcap.py <path_to.pcap>
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    if len(sys.argv) < 2:
        print("Usage: python tests/replay_pcap.py <file.pcap>")
        sys.exit(1)
    pcap_path = sys.argv[1]
    if not os.path.isfile(pcap_path):
        print(f"File not found: {pcap_path}")
        sys.exit(1)

    try:
        from scapy.all import rdpcap
    except ImportError:
        print("Scapy is required: pip install scapy")
        sys.exit(1)

    from src.packet_sniffer import PacketSniffer
    from main import IDSController

    controller = IDSController()
    controller.initialize()
    sniffer = PacketSniffer(interface=None, flow_timeout=0)
    sniffer.flow_callback = controller.process_flow
    sniffer.running = True

    # Feed all packets into sniffer so flows are built (no live capture)
    packets = rdpcap(pcap_path)
    for pkt in packets:
        sniffer.packet_handler(pkt)

    # Close all flows and run detection on each (flow_timeout=0 so none auto-expire)
    for flow_key in list(sniffer.flows.keys()):
        feats = sniffer.compute_flow_features(flow_key)
        if feats and sniffer.flow_callback:
            sniffer.flow_callback(feats)
        del sniffer.flows[flow_key]

    recent = controller.get_recent_alerts(100)
    stats = controller.get_statistics()
    print(f"Replayed {len(packets)} packets -> {stats.get('packets', 0)} flows, {stats.get('total', 0)} alerts")
    for a in recent[:25]:
        print(f"  [{a['severity']}] {a['type']}: {a['description'][:65]}")
    if len(recent) > 25:
        print(f"  ... and {len(recent) - 25} more")


if __name__ == "__main__":
    main()
