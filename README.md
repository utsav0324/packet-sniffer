# Packet Sniffer
A simple Python packet sniffer that captures and analyzes network packets on a specified interface.
The script displays:
- **Ethernet Frame**: Source/Destination MAC addresses
- **IPv4 Packet**: Version, Header Length, TTL, Protocol, Source/Destination IPs
- **TCP Segment**: Ports, Sequence/Acknowledgment numbers, TCP flags, Payload
- **UDP Segment**: Ports, Length, Payload
- **ICMP Packet**: Type, Code, Checksum
