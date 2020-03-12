#!/usr/bin/env python3
# coding: utf-8

"""
Simple raw packet sniffer for learning
Actually supprt TCP & ICMP unpacking
"""

import struct
import socket
import binascii
import signal

colors = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m", "blank": "\033[0m"}


def ctrlc_handler(signum, frm):
    logger("Shutting down program...", "err")
    exit(0)


def formatmac(macAddr):
    return ':'.join(str(macAddr)[i:i+2] for i in range(0, 12, 2))


def logger(msg, msgtype=''):
    if msgtype == 'info':
        print(colors["yellow"] + "[*] " + colors["blank"] + msg)
    elif msgtype == 'err':
        print(colors["red"] + "[X] " + colors["blank"] + msg)
    elif msgtype == 'success':
        print(colors["green"] + "[+] " + colors["blank"] + msg)
    else:
        print(msg)


def unpackICMP(pkt):
    icmpHeader = pkt[0][34:38]
    icmp_hdr = struct.unpack("!BBH", icmpHeader)

    icmpType = icmp_hdr[0]
    icmpCode = icmp_hdr[1]
    icmpCRC = icmp_hdr[2]
    Data = pkt[0][38:]

    logger('''  ICMP Type : %d
  ICMP Code : %d
  CRC : %d
  Data = %s
    ''' % (icmpType, icmpCode, icmpCRC, Data))


def unpackTCP(pkt):
    tcpHeader = pkt[0][34:54]
    tcp_hdr = struct.unpack("!HH16s", tcpHeader)

    sourcePort = tcp_hdr[0]
    destPort = tcp_hdr[1]
    Data = pkt[0][54:]

    logger('''  Source port : %d
    Dest port : %d
    Data = %s
    ''' % (sourcePort, destPort, Data))


def main():
    signal.signal(signal.SIGINT, ctrlc_handler)
    count = 0

    # htons reference the type of packet we want to intercept here Internet Protocol Packet (IP) all are in
    # /usr/include/linux/if_ether.h
    logger("Creating RAW socket...", "info")
    try:
        rawsocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        logger("RAW socket created successfully !", "success")
    except:
        logger("Failed to create RAW socket!", "err")


    while True:
        pkt = rawsocket.recvfrom(65535)

        print(colors["yellow"] + "========== Packet n°%d ==========" % count + colors["blank"])

        #####################################################
        # Ethernet Info
        #####################################################
        ethHeader = pkt[0][:14]
        eth_hdr = struct.unpack("!6s6s2s", ethHeader)

        macSource = formatmac(binascii.hexlify(eth_hdr[0]))
        macDest = formatmac(binascii.hexlify(eth_hdr[1]))
        ethType = binascii.hexlify(eth_hdr[2])

        logger("Source ETH : %s Dest ETH : %s Type ETH : %s" % (macSource, macDest, ethType))

        #####################################################
        # IP Info
        #####################################################
        ipHeader = pkt[0][14:34]
        ip_hdr = struct.unpack("!BBH5sB2s4s4s", ipHeader)
        ipVersion = ip_hdr[0] >> 4
        ipHdrLen = ip_hdr[0] & 0x0f
        ipLen = ip_hdr[2]
        ipSource = socket.inet_ntoa(ip_hdr[6])
        ipDest = socket.inet_ntoa(ip_hdr[7])
        proto = ip_hdr[4]
        print('IP LENGTH = %d HEADER LENGTH = %d' % (ipLen, ipHdrLen))
        print("IP VERSION = %d" % ipVersion)
        logger("Source IP : %s Dest IP : %s Proto type : %s" % (ipSource, ipDest, proto))

        if proto == 1:
            logger("ICMP packet found ! Unpacking...", "info")
            unpackICMP(pkt)
            logger("ICMP information successfully retrieved !", "success")
        elif proto == 6:
            logger("TCP packet found ! Unpacking...", "info")
            unpackTCP(pkt)
            logger("TCP information successfully retrieved !", "success")
        else:
            print("No specific protocol detected !")

        #####################################################
        # TCP Info
        #####################################################

        count += 1


if __name__ == '__main__':
    main()

