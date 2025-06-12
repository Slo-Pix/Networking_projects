import socket
import struct
import binascii

rawsocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))

def sniff():
    print("[*] Sniffer started. Listening for packets...\n")
    while True:
        packet = rawsocket.recvfrom(2048)[0]
        ethsniff(packet)

def ethsniff(packet):
    print("\n[+] NEW PACKET")
    eth = struct.unpack('!6s6s2s', packet[:14])
    print("\n--- Ethernet Header ---")
    print("Destination MAC Addr:", binascii.hexlify(eth[0]))
    print("Source MAC Addr:", binascii.hexlify(eth[1]))
    print("Next Higher Layer Protocol (EtherType):", binascii.hexlify(eth[2]))
    print("----------------------------------------------------------------------------\n")
    ether_type = binascii.hexlify(eth[2])
    if ether_type == b'0800':
        ipsniff(packet[14:])
    elif ether_type == b'0806':
        arpsniff(packet[14:])
    else:
        print("[+] Not an IP or ARP packet")

def ipsniff(packet):
    ip = struct.unpack('!1s1s2s2s2s1s1s2s4s4s', packet[:20])
    print("--- IP Header ---")
    version_ihl = int(binascii.hexlify(ip[0]), 16)
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_length = ihl * 4

    print("Version:", version)
    print("IHL (Header Length):", ihl, f"({ip_header_length} bytes)")
    print("Total Length:", int(binascii.hexlify(ip[2]), 16))
    print("TTL:", int(binascii.hexlify(ip[5]), 16))
    print("Next Higher Layer Protocol:", int(binascii.hexlify(ip[6]), 16))
    print("Source IP:", socket.inet_ntoa(ip[8]))
    print("Destination IP:", socket.inet_ntoa(ip[9]))
    print("----------------------------------------------------------------------------\n")

    protocol = int(binascii.hexlify(ip[6]), 16)
    if protocol == 6:
        tcpsniff(packet[ip_header_length:])
    elif protocol == 17:
        udpsniff(packet[ip_header_length:])
    else:
        print("[+] Packet is not TCP or UDP")

def arpsniff(packet):
    arp = struct.unpack('!2s2s1s1s2s6s4s6s4s', packet[:28])
    print("\n--- ARP Header ---")
    print("Protocol Type:", binascii.hexlify(arp[1]))
    print("Hardware Length:", int(binascii.hexlify(arp[2]), 16))
    print("Protocol Length:", int(binascii.hexlify(arp[3]), 16))
    print("Opcode (1=Request | 2=Reply):", int(binascii.hexlify(arp[4]), 16))
    print("Sender MAC Addr:", binascii.hexlify(arp[5]))
    print("Sender IP Addr:", socket.inet_ntoa(arp[6]))
    print("Target MAC Addr:", binascii.hexlify(arp[7]))
    print("Target IP Addr:", socket.inet_ntoa(arp[8]))
    print("----------------------------------------------------------------------------\n")

def tcpsniff(packet):
    tcp = struct.unpack('!HHLLBBHHH', packet[:20])
    source_port = tcp[0]
    dest_port = tcp[1]
    data_offset = (tcp[4] >> 4) * 4
    print("\n--- TCP Header ---")
    print("Source Port:", source_port)
    print("Destination Port:", dest_port)
    print("Header Length:", data_offset, "bytes")
    print("----------------------------------------------------------------------------\n")
    if len(packet) > data_offset:
        application_sniff(packet[data_offset:], "TCP", source_port, dest_port)

def udpsniff(packet):
    udp = struct.unpack('!HHHH', packet[:8])
    source_port = udp[0]
    dest_port = udp[1]
    print("\n--- UDP Header ---")
    print("Source Port:", source_port)
    print("Destination Port:", dest_port)
    print("Length:", udp[2])
    print("----------------------------------------------------------------------------\n")
    if len(packet) > 8:
        application_sniff(packet[8:], "UDP", source_port, dest_port)

def convert_to_ascii(data):
    ascii_representation = []
    for byte in data:
        if 32 <= byte <= 126:
            ascii_representation.append(chr(byte))
        else:
            ascii_representation.append('.')
    return ''.join(ascii_representation)

def application_sniff(data, protocol, source_port, dest_port):
    print(f"\n--- Application Layer Data ({protocol}) ---")
    try:
        if source_port == 80 or dest_port == 80:
            print("[HTTP]:")
            print(data.decode('utf-8', errors='ignore'))
        elif source_port == 53 or dest_port == 53:
            print("[DNS]:")
            decode_dns(data)
        else:
            print("[Raw Data]:", convert_to_ascii(data))
    except UnicodeDecodeError:
        print("Non-UTF-8 Data (ASCII Representation):", convert_to_ascii(data))
    print("----------------------------------------------------------------------------\n")

def decode_dns(data):
    transaction_id = data[:2]
    flags = data[2:4]
    questions = data[4:6]
    answer_rrs = data[6:8]
    authority_rrs = data[8:10]
    additional_rrs = data[10:12]
    dns_body = data[12:]

    print("Transaction ID:", binascii.hexlify(transaction_id))
    print("Flags:", binascii.hexlify(flags))
    print("Questions:", struct.unpack('!H', questions)[0])
    print("Answer RRs:", struct.unpack('!H', answer_rrs)[0])
    print("Authority RRs:", struct.unpack('!H', authority_rrs)[0])
    print("Additional RRs:", struct.unpack('!H', additional_rrs)[0])
    print("DNS Data:", convert_to_ascii(dns_body))

if __name__ == "__main__":
    try:
        sniff()
    except KeyboardInterrupt:
        print("\n[!] Stopping the sniffer.")
