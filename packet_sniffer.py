import scapy.all as scapy
import struct
import textwrap
import ipaddress
import sys


def format_multi_line(prefix, string, size=80):
    """Format multi-line data for readable output."""
    size -= len(prefix)

    if isinstance(string, bytes):
        string = ' '.join(f'{b:02x}' for b in string)

    return '\n'.join(
        [prefix + line for line in textwrap.wrap(string, size)]
    )


def format_mac(mac_bytes):
    """Convert MAC address bytes into readable format."""
    return ':'.join(map('{:02X}'.format, mac_bytes))


# =========================
# Ethernet
# =========================
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])

    return (
        format_mac(src_mac),
        format_mac(dest_mac),
        proto,
        data[14:]
    )


# =========================
# IPv4
# =========================
def ipv4_packet(data):
    version_header_length = data[0]

    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack(
        '!8xBB2x4s4s',
        data[:20]
    )

    return (
        version,
        header_length,
        ttl,
        proto,
        ipaddress.IPv4Address(src),
        ipaddress.IPv4Address(target),
        data[header_length:]
    )


# =========================
# ICMP
# =========================
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])

    return icmp_type, code, checksum, data[4:]


# =========================
# TCP
# =========================
def tcp_segment(data):
    (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        offset_reserved_flags
    ) = struct.unpack('!HHLLH', data[:14])

    offset = (offset_reserved_flags >> 12) * 4

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:]
    )


# =========================
# UDP
# =========================
def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack(
        '!HHHH',
        data[:8]
    )

    return src_port, dest_port, length, checksum, data[8:]


# =========================
# Packet Formatter
# =========================
def process_packet(packet):
    raw_data = bytes(packet)

    print('\n' + '=' * 80)
    print('PACKET CAPTURED')
    print('=' * 80)

    # Ethernet Frame
    src_mac, dest_mac, eth_proto, data = ethernet_frame(raw_data)

    print('Ethernet Frame:')
    print(f'  Source MAC      : {src_mac}')
    print(f'  Destination MAC : {dest_mac}')
    print(f'  EtherType       : 0x{eth_proto:04X}')

    # =========================
    # IPv4
    # =========================
    if eth_proto == 0x0800:
        (
            version,
            header_length,
            ttl,
            proto,
            src,
            target,
            data
        ) = ipv4_packet(data)

        print('\nIPv4 Packet:')
        print(f'  Version         : {version}')
        print(f'  Header Length   : {header_length} bytes')
        print(f'  TTL             : {ttl}')
        print(f'  Protocol        : {proto}')
        print(f'  Source IP       : {src}')
        print(f'  Destination IP  : {target}')

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)

            print('\nICMP Packet:')
            print(f'  Type            : {icmp_type}')
            print(f'  Code            : {code}')
            print(f'  Checksum        : {checksum}')

        # TCP
        elif proto == 6:
            (
                src_port,
                dest_port,
                sequence,
                acknowledgment,
                flag_urg,
                flag_ack,
                flag_psh,
                flag_rst,
                flag_syn,
                flag_fin,
                payload
            ) = tcp_segment(data)

            print('\nTCP Segment:')
            print(f'  Source Port     : {src_port}')
            print(f'  Destination Port: {dest_port}')
            print(f'  Sequence        : {sequence}')
            print(f'  Acknowledgment  : {acknowledgment}')

            print('  Flags:')
            print(f'    URG : {flag_urg}')
            print(f'    ACK : {flag_ack}')
            print(f'    PSH : {flag_psh}')
            print(f'    RST : {flag_rst}')
            print(f'    SYN : {flag_syn}')
            print(f'    FIN : {flag_fin}')

            if payload:
                print('\n  Payload:')
                print(format_multi_line('    ', payload))

        # UDP
        elif proto == 17:
            src_port, dest_port, length, checksum, payload = udp_segment(data)

            print('\nUDP Segment:')
            print(f'  Source Port     : {src_port}')
            print(f'  Destination Port: {dest_port}')
            print(f'  Length          : {length}')
            print(f'  Checksum        : {checksum}')

            if payload:
                print('\n  Payload:')
                print(format_multi_line('    ', payload))

    # =========================
    # ARP
    # =========================
    elif eth_proto == 0x0806:
        print('\nARP Packet')

    # =========================
    # IPv6
    # =========================
    elif eth_proto == 0x86DD:
        print('\nIPv6 Packet')

    else:
        print('\nUnknown EtherType')


# =========================
# Sniffer
# =========================
def sniff(interface):
    scapy.sniff(
        iface=interface,
        store=False,
        prn=process_packet
    )


# =========================
# Main
# =========================
if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('Usage:')
        print('  sudo python3 packet_sniffer.py <interface>')
        print('\nExample:')
        print('  sudo python3 packet_sniffer.py eth0')
        sys.exit(1)

    interface = sys.argv[1]

    print('=' * 80)
    print(f'Starting packet sniffer on interface: {interface}')
    print('Press CTRL+C to stop...')
    print('=' * 80)

    try:
        sniff(interface)

    except KeyboardInterrupt:
        print('\nPacket sniffer stopped.')

    except PermissionError:
        print('\nError: Run with sudo/root privileges.')

    except Exception as e:
        print(f'\nError: {e}')