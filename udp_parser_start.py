#!/usr/bin/env python3

# This program uses the hexdump module, provided as a separate python file.

import hexdump
import ipaddress
import select
import socket
import struct
import sys


def compute_checksum(buffer: bytes) -> int:
    """
    Compute the checksum over a sequence of bytes. Remember to padd an odd
    number of bytes with a 0-byte.

    Don't forget to take the binary inverse of the sum result, except when the
    result is 0xFFFF.

    This is your job, and you need it for the bTCP project anyway, so might as
    well do it here, right?

    Examples:
    >>> compute_checksum(b'\\xAB\\xCD')
    21554
    >>> compute_checksum(b'\\xAB\\xCD\\xEF')
    25905
    >>> compute_checksum(b'\\xFF\\xFF')
    65535
    >>> compute_checksum(b'\\x00\\x00')
    65535
    >>> compute_checksum(b'')
    0
    """
    # Signal nonsensical request (checksum of nothing?) with 0x0000
    if not buffer:
        return 0x0000

    checksum = 0x0000
    # IMPLEMENT HERE, REMOVE LINE ABOVE WHEN DONE
    return checksum


def verify_checksum(buffer: bytes):
    return compute_checksum(buffer) == 0xFFFF


def build_pseudo_header_prefix(src_ip, dst_ip, proto, length):
    """
    Build the TCP or UDP checksum pseudo header prefix bytes from required
    information. Note this does not yet include the TCP or UDP header itself.

    We have already implemented this for you, no need to change it.
    """
    return struct.pack("!4s4sBBH",
                       src_ip.packed, dst_ip.packed, 0, proto, length)


def parse_ipv4(packet):
    """
    Parse the IPv4 packet header, return the parsed header fields we want, the
    header in its entirety, and the IPv4 payload.

    This is your job.

    You do NOT have to handle any kind of datagram fragmentation or reassembly!

    For getting the header length, refer to the slides & recording of lecture 4
    Remember that the IHL field is in the 4 *least* significant bits of byte 0,
    and it contains the number of 4-byte *rows* in the header.
    """
    header = b''
    payload = b''
    (ttl, protocol, hdr_checksum, src, dst) = 0, 0, 0x0000, 0, 0
    # IMPLEMENT HERE, REMOVE LINES ABOVE WHEN DONE

    # we get the first byte, containing version and header length
    firstbyte = packet[:1]
    
    #we extract the version
    version = firstbyte >> 4
    
    #we extract the header length, the length is multiplication by 4
    header_length = (firstbyte & 15) * 4
    
    print(version, header_length)
    
    # IMPLEMENT TO HERE, DO NOT CHANGE LINES BELOW
    # Coerce the addresses into "IPv4Address" objects
    src_addr = ipaddress.IPv4Address(src)
    dst_addr = ipaddress.IPv4Address(dst)
    return src_addr, dst_addr, protocol, ttl, hdr_checksum, header, payload


def parse_udp(segment):
    """
    Parse the UDP segment header, return the parsed header fields, the header
    in its entirety, and UDP payload.

    Already implemented by us, use as inspiration for your own code.
    """
    header_length = 8
    # Slice header from segment
    header = segment[:header_length]
    # Slice payload from segment (don't need length to do so here, all
    # remaining bytes are payload)
    payload = segment[header_length:]
    # Use struct formatstring to parse the header as four unsigned shorts (H) in
    # network byte order (!).
    src_port, dst_port, udp_length, checksum = struct.unpack("!HHHH", header)
    # Compute data length by subtracting UDP header length (always 8 bytes)
    # from UDP length field.
    data_length = udp_length - 8
    return src_port, dst_port, udp_length, checksum, data_length, header, payload


def parse_tcp(segment):
    """
    Parse the TCP segment header, return the parsed header fields, the header
    in its entirety, and TCP payload.

    This is your job.
    """
    header = b''
    payload = b''
    (src_port, dst_port, seq_num, ack_num, flags, window, checksum) = 0, 0, 0, 0, 0x00, 0, 0x0000
    # IMPLEMENT HERE, REMOVE LINES ABOVE WHEN DONE

    # IMPLEMENT TO HERE, DO NOT CHANGE LINES BELOW
    return src_port, dst_port, seq_num, ack_num, flags, window, checksum, header, payload


def main():
    """
    Open two raw sockets, one for UDP/IP and one for TCP/IP, and loop over
    receiving IP packets from them and parse them as UDP or TCP, accordingly.

    You should only have to change the code where we have put "???", i.e. you
    have to pass the correct arguments to both socket-creating calls, and
    insert the correct protocol numbers to distinguish between TCP and UDP.

    Even though we have separate sockets for UDP and TCP, you are *required*
    to use the IP header's protocol field to decide between sending the
    segment to the parse_udp or parse_tcp functions.
    """
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    while True:
        ready_socks, _, _ = select.select([udp_sock, tcp_sock], [], [], 5)
        if not ready_socks:
            print("5 seconds passed without seeing UDP or TCP traffic", file=sys.stderr)
        for s in ready_socks:
            datagram, _ = s.recvfrom(65535)

            # IPv4 handling
            src_addr, dst_addr, protocol, ttl, ip_hdr_checksum, ip_header, segment = parse_ipv4(datagram)
            checksum_valid = verify_checksum(ip_header)
            dump_ipv4_to_console(src_addr, dst_addr, ttl, protocol, ip_hdr_checksum, checksum_valid)

            # We can actually *verify* checksum validity for both TCP and UDP
            # before looking at the protocol, because the pseudo headers are
            # identical and checksum verification doesn't require us to parse
            # it out of the header.
            transport_layer_checksum_valid = verify_checksum(
                build_pseudo_header_prefix(src_addr, dst_addr, protocol, len(segment))
                + segment)

            if protocol == 17: # USE UDP PROTOCOL NUMBER HERE
                # UDP handling
                (udp_src_port, udp_dst_port, udp_length, udp_checksum,
                 udp_data_length, udp_header, udp_payload) = parse_udp(segment)
                dump_udp_to_console(udp_src_port, udp_dst_port,
                                    udp_length, udp_data_length,
                                    udp_checksum, transport_layer_checksum_valid)
                dump_payload_to_console(udp_payload)

            elif protocol == 6: # USE TCP PROTOCOL NUMBER HERE
                # TCP handling
                (tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_flags,
                 tcp_window, tcp_checksum, tcp_header, tcp_payload) = parse_tcp(segment)
                dump_tcp_to_console(tcp_src_port, tcp_dst_port,
                                    tcp_seq_num, tcp_ack_num,
                                    tcp_flags, tcp_window,
                                    tcp_checksum, transport_layer_checksum_valid)
                dump_payload_to_console(tcp_payload)

            else:
                print("IPv4 datagram with protocol number {} received; skipping further processing.\n".format(
                      protocol))
                print("This should not happen with these sockets and correct parsing code!\n\n")


def dump_ipv4_to_console(src_addr, dst_addr, ttl, protocol, hdr_checksum, checksum_valid):
    """
    Dump IP header fields to console and state whether checksum verification
    has succeeded.

    Already implemented by us, no need to change.
    """
    print("""\nIP header:
    Src addr:    {}
    Dst addr:    {}
    TTL:         {:d}
    Protocol #:  {:d}
    Checksum:    0x{:04X}
    IP checksum {}
""".format(src_addr, dst_addr, ttl, protocol, hdr_checksum,
           "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface"))


def dump_udp_to_console(src_port, dst_port, length, data_length, checksum, checksum_valid):
    """
    Parse UDP segment and dump UDP information to console.

    Already implemented by us, no need to change.
    """

    print("""\nUDP header:
    Src port:    {:d}
    Dst port:    {:d}
    UDP length:  {:d}
    Checksum:    0x{:04X}
    UDP checksum {}

Data length: {:d}""".format(src_port, dst_port, length, checksum,
                            "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface",
                            data_length))


def dump_tcp_to_console(src_port, dst_port, seq_num, ack_num, flags, window, checksum, checksum_valid):
    """
    Parse TCP segment and dump IP & TCP information to console.

    Already implemented by us, no need to change.
    """
    print("""\nTCP header:
    Src port:    {:d}
    Dst port:    {:d}
    Seq num:     {:d}
    Ack num:     {:d}
    Flags:       {}
    Window:      {:d}
    Checksum:    0x{:04X}
    TCP checksum {}
""".format(src_port, dst_port, seq_num, ack_num, tcp_flags_str(flags), window, checksum,
           "valid" if checksum_valid else "invalid, unverified, or offloaded to sending interface"))


def dump_payload_to_console(payload):
    """
    Simple wrapper function to avoid code duplication for dumping payload data.

    Already implemented by us, no need to change.
    """
    print("Data:")
    if payload:
        hexdump.hexdump(payload)
    else:
        print("No data in segment")
    print("\n\n")


def tcp_flags_str(flags):
    """
    Turn 9 TCP flags bits into string listing the flags that are set in them.

    Already implemented by us, no need to change.
    """
    if not flags:
        return "None"
    mnemonics = list(reversed(['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']))
    flag_strs = []
    for i in range(9):
        if (flags >> i) & 0x1:
            flag_strs.append(mnemonics[i])
    return ', '.join(flag_strs)


if __name__ == "__main__":
    main()
