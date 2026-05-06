# Packet Sniffer

A simple Python packet sniffer that captures and analyzes network packets on a specified interface.

## Features

- ✅ Captures Ethernet frames
- ✅ Parses IPv4 packets
- ✅ Extracts TCP, UDP, and ICMP protocols
- ✅ Displays source/destination IPs and ports
- ✅ Shows TCP flags and payload data
- ✅ User-friendly formatted output

## Installation

```bash
pip install scapy
```

## Usage

```bash
sudo python3 packet_sniffer.py <interface>
```

### Examples

```bash
# Linux/Mac
sudo python3 packet_sniffer.py eth0
sudo python3 packet_sniffer.py en0

# Windows (run as Administrator)
python packet_sniffer.py Ethernet
```

## Finding Your Network Interface

**Linux/Mac:**
```bash
ip link show
ifconfig
```

**Windows:**
```cmd
ipconfig
```

## Important Notes

⚠️ **Root/Administrator privileges required** - Packet sniffing needs elevated permissions

## Output

The script displays:
- **Ethernet Frame**: Source/Destination MAC addresses
- **IPv4 Packet**: Version, Header Length, TTL, Protocol, Source/Destination IPs
- **TCP Segment**: Ports, Sequence/Acknowledgment numbers, TCP flags, Payload
- **UDP Segment**: Ports, Length, Payload
- **ICMP Packet**: Type, Code, Checksum

## Example Output

```
======================================================================
PACKET CAPTURED
======================================================================
Ethernet Frame:
  Source MAC: AA:BB:CC:DD:EE:FF
  Destination MAC: 11:22:33:44:55:66
  Protocol: 8
IPv4 Packet:
  Version: 4
  Header Length: 20 bytes
  TTL: 64
  Protocol: 6
  Source: 192.168.1.100
  Destination: 142.251.40.46
TCP Segment:
  Source Port: 54321
  Destination Port: 443
  Sequence: 1234567890
  Acknowledgment: 987654321
  Flags:
    URG: 0
    ACK: 1
    PSH: 0
    RST: 0
    SYN: 0
    FIN: 0
```

## Requirements

- Python 3.6+
- Scapy
- Root/Administrator privileges
