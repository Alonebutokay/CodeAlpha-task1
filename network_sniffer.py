#!/usr/bin/env python3
"""
Basic Network Sniffer in Python

Captures and analyzes network packets on the selected interface.

Note:
- Must be run with administrator/root privileges
- Works on Linux (may require modifications for Windows)
"""

import socket
import struct
import textwrap
import datetime

def ethernet_frame(data):
    """Unpack Ethernet frame"""
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), socket.htons(proto), data[14:]

def mac_addr(mac_raw):
    """Convert a MAC address to a readable string"""
    bytes_str = map('{:02x}'.format, mac_raw)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    """Unpack IPv4 packet"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Return dotted IPv4 address from bytes"""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Unpack TCP segment"""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    flag_urg = (flags & 0x020) >> 5
    flag_ack = (flags & 0x010) >> 4
    flag_psh = (flags & 0x008) >> 3
    flag_rst = (flags & 0x004) >> 2
    flag_syn = (flags & 0x002) >> 1
    flag_fin = flags & 0x001
    return src_port, dest_port, sequence, acknowledgment, offset, flag_urg, \
           flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    """Unpack UDP segment"""
    src_port, dest_port, size = struct.unpack('!HHH', data[:6])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    """Format multi-line output"""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    lines = textwrap.wrap(string, size)
    return '\n'.join(prefix + line for line in lines)

def main():
    # create a raw socket and bind it to the public interface
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Starting network sniffer... Press Ctrl+C to stop.")
    packet_count = 0
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            packet_count +=1
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            # Parse Ethernet Frame
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            print(f"\nPacket #{packet_count} - {timestamp}")
            print(f"Ethernet Frame: Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

            # IPv4
            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print(f"IPv4 Packet: Version: {version}, Header Length: {header_length} bytes, TTL: {ttl}")
                print(f"Protocol: {proto}, Source: {src}, Target: {target}")

                # TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, \
                    flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    print(f"TCP Segment: Src Port: {src_port}, Dest Port: {dest_port}")
                    print(f"Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                    flags = []
                    if flag_urg: flags.append("URG")
                    if flag_ack: flags.append("ACK")
                    if flag_psh: flags.append("PSH")
                    if flag_rst: flags.append("RST")
                    if flag_syn: flags.append("SYN")
                    if flag_fin: flags.append("FIN")
                    print(f"Flags: {','.join(flags)}")
                    print(f"Data Size: {len(data)} bytes")

                # UDP
                elif proto == 17:
                    src_port, dest_port, size, data = udp_segment(data)
                    print(f"UDP Segment: Src Port: {src_port}, Dest Port: {dest_port}, Length: {size}")
                    print(f"Data Size: {len(data)} bytes")

                # Other protocols
                else:
                    print(f"Other IPv4 Protocol: {proto}")
                    print(f"Data Size: {len(data)} bytes")
            else:
                print(f"Non-IPv4 Ethernet Frame with protocol: {eth_proto}")

    except KeyboardInterrupt:
        print("\nSniffer stopped. Total packets captured:", packet_count)

if __name__ == '__main__':
    main()

