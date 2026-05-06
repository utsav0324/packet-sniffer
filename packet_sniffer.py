import scapy.all as scapy
import textwrap
import struct
import ipaddress
import sys


def format_multi_line(prefix, bytes_data, size=80):
    """Format multi-line data for readable output."""
    if isinstance(bytes_data, bytes):
        bytes_data = bytes_data.decode('utf-8', errors='ignore')
    if isinstance(bytes_data, str):
        bytes_data = bytes_data.encode('utf-8')

    lines = textwrap.wrap(bytes_data, size)
    output = ''
    for i, line in enumerate(lines):
        prefix_line = prefix if i == 0 else ' ' * len(prefix)
        output += prefix_line + line + '\n'

    return output


def format_ethernet_frame(data):
    """Extract and format Ethernet frame details."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_addr(dest_mac), format_mac_addr(src_mac), proto, data[14:]


def format_ipv4_packet(data):
    """Extract and format IPv4 packet details."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipaddress.IPv4Address(src), ipaddress.IPv4Address(target), data[header_length:]


def format_icmp_packet(data):
    """Extract and format ICMP packet details."""
    icmp_type, code, checksum = struct.unpack('! B B 2x H', data[:6])
    return icmp_type, code, checksum, data[8:]


def format_tcp_segment(data):
    """Extract and format TCP segment details."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def format_udp_segment(data):
    """Extract and format UDP segment details."""
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


def format_mac_addr(bytes_addr):
    """Format MAC address."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def format_packet(packet):
    """Format and display packet information."""
    print('\n' + '='*70)
    print('PACKET CAPTURED')
    print('='*70)

    if packet.haslayer(scapy.Ether):
        src, dest, eth_proto, data = format_ethernet_frame(packet[scapy.Ether].build())
        print(f'Ethernet Frame:')
        print(f'  Source MAC: {src}')
        print(f'  Destination MAC: {dest}')
        print(f'  Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, dest, data = format_ipv4_packet(data)
            print(f'IPv4 Packet:')
            print(f'  Version: {version}')
            print(f'  Header Length: {header_length} bytes')
            print(f'  TTL: {ttl}')
            print(f'  Protocol: {proto}')
            print(f'  Source: {src}')
            print(f'  Destination: {dest}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = format_icmp_packet(data)
                print(f'ICMP Packet:')
                print(f'  Type: {icmp_type}')
                print(f'  Code: {code}')
                print(f'  Checksum: {checksum}')

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = format_tcp_segment(data)
                print(f'TCP Segment:')
                print(f'  Source Port: {src_port}')
                print(f'  Destination Port: {dest_port}')
                print(f'  Sequence: {sequence}')
                print(f'  Acknowledgment: {acknowledgment}')
                print(f'  Flags:')
                print(f'    URG: {flag_urg}')
                print(f'    ACK: {flag_ack}')
                print(f'    PSH: {flag_psh}')
                print(f'    RST: {flag_rst}')
                print(f'    SYN: {flag_syn}')
                print(f'    FIN: {flag_fin}')
                if payload:
                    print(f'  Payload: {format_multi_line("    ", payload)}')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = format_udp_segment(data)
                print(f'UDP Segment:')
                print(f'  Source Port: {src_port}')
                print(f'  Destination Port: {dest_port}')
                print(f'  Length: {length}')
                if data:
                    print(f'  Payload: {format_multi_line("    ", data)}')


def sniff(interface):
    """Main packet sniffing function."""
    scapy.sniff(iface=interface, prn=lambda x: format_packet(x), store=False)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 packet_sniffer.py <interface>')
        print('Example: python3 packet_sniffer.py eth0')
        sys.exit(1)

    interface = sys.argv[1]
    print(f'Starting packet sniffer on interface: {interface}')
    print('Press Ctrl+C to stop...\n')
    
    try:
        sniff(interface)
    except KeyboardInterrupt:
        print('\n\nPacket sniffer stopped.')
        sys.exit(0)
    except PermissionError:
        print('Error: This script requires root/administrator privileges!')
        sys.exit(1)
