# Network Anomaly Detector

A real-time network anomaly detector built on top of Scapy. Instead of just
printing captured packets, it tracks per-host behavior in a sliding time
window and flags hosts that look like they're port-scanning or flooding —
the same signatures you'd hand-check for in a SOC, just automated.

## Why I built this

After building a basic packet sniffer for my CodeAlpha Cybersecurity
Internship, I wanted to go a step further: not just capture traffic, but
actually reason about it. This tool applies a simple but effective
statistical approach — no ML model, no black box — so every alert is fully
explainable.

## How it works

For every packet seen on the wire, the tool:

1. Buckets it by source IP.
2. Keeps a rolling window (default 10s) of timestamps per host.
3. Tracks how many **distinct destination ports** that host has touched.
4. Flags the host if either:
   - **Packet rate** exceeds a threshold within the window (flood-like behavior)
   - **Port diversity** exceeds a threshold (scan-like behavior — one host
     hitting many different ports in a short time)

This mirrors two of the most common early-warning signs analysts look for:
SYN floods and port scans, without needing a labeled dataset or a trained
model.

## Usage

```bash
pip install scapy
sudo python3 anomaly_sniffer.py --iface eth0 --window 10 --pps 100 --ports 15
```

| Flag | Description | Default |
|------|-------------|---------|
| `--iface` | Network interface to sniff on | scapy auto-picks |
| `--window` | Sliding window size in seconds | 10 |
| `--pps` | Packets-per-window threshold before flagging | 100 |
| `--ports` | Distinct-port threshold before flagging a scan | 15 |

## Sample output

```
[*] Watching eth0 | window=10s pps_threshold=100 port_threshold=15
[*] Ctrl+C to stop

[!] 14:32:07 ANOMALY from 192.168.56.101
    -> 143 pkts in last 10s (limit 100)
    -> touched 22 distinct ports (possible port scan)
```

## Testing it yourself

On a lab network (e.g. a Kali VM and a target VM on a host-only network),
you can trigger an alert safely with:

```bash
# from Kali, against a Windows/Linux VM target
nmap -p 1-100 <target-ip>
```

You should see the detector flag the scanning host within a few seconds.

## Notes / limitations

- Thresholds are static — a production version would adapt them per
  network baseline over time.
- IPv4 only for now.
- Alerts are printed to stdout; piping to a log file or SIEM would be the
  natural next step.

## Tech

- Python 3.10+
- [Scapy](https://scapy.net/) for packet capture and parsing

## License

MIT
