import socket
import struct
import binascii

rawsocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))

log_file = "packet_logs.txt"

def write_to_file(data):
    """Writes data to a log file."""
    with open(log_file, "a") as file:
        file.write(data + "\n")

def sniff():
    """Main packet sniffer loop."""
    print("[*] Sniffer started. Listening for packets...\n")
    write_to_file("[*] Sniffer started. Listening for packets...\n")
    while True:
        packet = rawsocket.recvfrom(2048)[0]
        ethsniff(packet)

def ethsniff(packet):
    """Parses the Ethernet header."""
    print("\n[+] NEW PACKET")
    write_to_file("\n[+] NEW PACKET")
    eth = struct.unpack('!6s6s2s', packet[:14])
    output = (f"\n--- Ethernet Header ---\n"
              f"Destination MAC Addr: {binascii.hexlify(eth[0])}\n"
              f"Source MAC Addr: {binascii.hexlify(eth[1])}\n"
              f"Next Higher Layer Protocol (EtherType): {binascii.hexlify(eth[2])}\n"
              f"----------------------------------------------------------------------------\n")
    print(output)
    write_to_file(output)

    ether_type = binascii.hexlify(eth[2])
    if ether_type == b'0800':
        ipsniff(packet[14:])
    elif ether_type == b'0806':
        arpsniff(packet[14:])
    else:
        write_to_file("[+] Not an IP or ARP packet")

def ipsniff(packet):
    """Parses the IP header."""
    ip = struct.unpack('!1s1s2s2s2s1s1s2s4s4s', packet[:20])
    version_ihl = int(binascii.hexlify(ip[0]), 16)
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_length = ihl * 4

    output = (f"--- IP Header ---\n"
              f"Version: {version}\n"
              f"IHL (Header Length): {ihl} ({ip_header_length} bytes)\n"
              f"Total Length: {int(binascii.hexlify(ip[2]), 16)}\n"
              f"TTL: {int(binascii.hexlify(ip[5]), 16)}\n"
              f"Next Higher Layer Protocol: {int(binascii.hexlify(ip[6]), 16)}\n"
              f"Source IP: {socket.inet_ntoa(ip[8])}\n"
              f"Destination IP: {socket.inet_ntoa(ip[9])}\n"
              f"----------------------------------------------------------------------------\n")
    print(output)
    write_to_file(output)

    protocol = int(binascii.hexlify(ip[6]), 16)
    if protocol == 6:
        tcpsniff(packet[ip_header_length:])
    elif protocol == 17:
        udpsniff(packet[ip_header_length:])

def arpsniff(packet):
    """Parses the ARP header."""
    arp = struct.unpack('!2s2s1s1s2s6s4s6s4s', packet[:28])
    output = (f"\n--- ARP Header ---\n"
              f"Protocol Type: {binascii.hexlify(arp[1])}\n"
              f"Hardware Length: {int(binascii.hexlify(arp[2]), 16)}\n"
              f"Protocol Length: {int(binascii.hexlify(arp[3]), 16)}\n"
              f"Opcode (1=Request | 2=Reply): {int(binascii.hexlify(arp[4]), 16)}\n"
              f"Sender MAC Addr: {binascii.hexlify(arp[5])}\n"
              f"Sender IP Addr: {socket.inet_ntoa(arp[6])}\n"
              f"Target MAC Addr: {binascii.hexlify(arp[7])}\n"
              f"Target IP Addr: {socket.inet_ntoa(arp[8])}\n"
              f"----------------------------------------------------------------------------\n")
    print(output)
    write_to_file(output)

def tcpsniff(packet):
    """Parses the TCP header."""
    tcp = struct.unpack('!HHLLBBHHH', packet[:20])
    source_port = tcp[0]
    dest_port = tcp[1]
    data_offset = (tcp[4] >> 4) * 4

    output = (f"\n--- TCP Header ---\n"
              f"Source Port: {source_port}\n"
              f"Destination Port: {dest_port}\n"
              f"Header Length: {data_offset} bytes\n"
              f"----------------------------------------------------------------------------\n")
    print(output)
    write_to_file(output)

    if len(packet) > data_offset:
        application_sniff(packet[data_offset:], "TCP", source_port, dest_port)

def udpsniff(packet):
    """Parses the UDP header."""
    udp = struct.unpack('!HHHH', packet[:8])
    source_port = udp[0]
    dest_port = udp[1]

    output = (f"\n--- UDP Header ---\n"
              f"Source Port: {source_port}\n"
              f"Destination Port: {dest_port}\n"
              f"Length: {udp[2]}\n"
              f"----------------------------------------------------------------------------\n")
    print(output)
    write_to_file(output)

    if len(packet) > 8:
        application_sniff(packet[8:], "UDP", source_port, dest_port)

def convert_to_ascii(data):
    """Converts raw data bytes to ASCII characters."""
    ascii_representation = []
    for byte in data:
        if 32 <= byte <= 126:
            ascii_representation.append(chr(byte))
        else:
            ascii_representation.append('.')
    return ''.join(ascii_representation)

def application_sniff(data, protocol, source_port, dest_port):
    """Parses application layer data."""
    output = f"\n--- Application Layer Data ({protocol}) ---\n"
    try:
        if source_port == 80 or dest_port == 80:
            output += "[HTTP]:\n" + data.decode('utf-8', errors='ignore')
        elif source_port == 53 or dest_port == 53:
            output += "[DNS]:\n" + decode_dns(data)
        else:
            output += f"[Raw Data]: {convert_to_ascii(data)}\n"
    except UnicodeDecodeError:
        output += f"Non-UTF-8 Data (ASCII Representation): {convert_to_ascii(data)}\n"
    print(output)
    write_to_file(output)

def decode_dns(data):
    """Decodes DNS queries and responses."""
    transaction_id = data[:2]
    flags = data[2:4]
    questions = data[4:6]
    answer_rrs = data[6:8]
    authority_rrs = data[8:10]
    additional_rrs = data[10:12]
    dns_body = data[12:]

    output = (f"Transaction ID: {binascii.hexlify(transaction_id)}\n"
              f"Flags: {binascii.hexlify(flags)}\n"
              f"Questions: {struct.unpack('!H', questions)[0]}\n"
              f"Answer RRs: {struct.unpack('!H', answer_rrs)[0]}\n"
              f"Authority RRs: {struct.unpack('!H', authority_rrs)[0]}\n"
              f"Additional RRs: {struct.unpack('!H', additional_rrs)[0]}\n"
              f"DNS Data: {convert_to_ascii(dns_body)}\n")
    write_to_file(output)
    return output

if __name__ == "__main__":
    try:
        sniff()
    except KeyboardInterrupt:
        print("\n[!] Stopping the sniffer.")
        write_to_file("\n[!] Stopping the sniffer.")
