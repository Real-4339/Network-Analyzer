import os
import logging

# from module import *
from scapy.all import rdpcap

from tcp_ip.yaml import Basic
from tcp_ip.packet import Packet
from tcp_ip.communications import *
from argparse import ArgumentParser
from tcp_ip.lib.lib import parse_file
from tcp_ip.statistics import Statistics


''' Global variables '''
logging.basicConfig(level=logging.NOTSET)

sample = 'trace_ip_nad_20_B.pcap' # eth-1.pcap eth-4.pcap trace-15.pcap trace-6.pcap

stats = Statistics()


def prepinac(protocol):

    root = os.path.abspath(os.path.dirname(__file__))
    parse_file(root)

    if protocol == 'TFTP':
        p = TFTPCom(packets, stats)
        p.print_result()

    elif protocol == 'ARP':
        p = ARPCom(packets, stats)
        p.print_result()

    elif protocol == 'ICMP':
        p = ICMPCom(packets, stats)
        p.print_result()
    
    elif protocol == 'RIP':
        p = RIPCom(packets, stats)
        p.print_result()
        
    else:
        p = TCPAll(protocol, packets, stats)
        p.print_result()
    #else:
    # p = Prepinac(protocol, packets)
    # p.parsePackets()
    # for flags in eval("Prepinac." + p.low).values():
    #     print(p.define(flags))

    # p.printAll()


def new_statistics():

    root = os.path.abspath(os.path.dirname(__file__))
    parse_file(root)

    my_packets = []

    for index, packet in enumerate(packets):
        # print("<-----Packet----->")
        p = Packet(packet, index+1, stats)
        my_packets.append(p)

        if p.L2 and p.L2.name == 'IPv4' and p.frame_num == 43:
            p.print_all()

    
    # basic_yaml = Basic(sample, root, my_packets, stats)


if __name__ == '__main__':

    print("Welcome to the PKS analyzer!")

    names = ['HTTP', 'HTTPS', 'TELNET', 'SSH', 'FTP-CONTROL', 'FTP-DATA', 'TFTP', 'ARP', 'ICMP', 'RIP']
    parser = ArgumentParser(description='Input HTTP, HTTPS, TELNET, SSH, FTP, TFTP, ARP, ICMP, RIP: ')
    pcap_file_parser = ArgumentParser(description='Input pcap file name: ')

    parser.add_argument('-p', '--protocol', metavar='', help='Analyze only chosen protocol', required=False)
    parser.add_argument('-f', '--file', metavar='', help='Analyze only chosen pcap file', required=False)
    args = parser.parse_args()

    sample = args.file + '.pcap' if args.file else sample

    samples_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'samples'))

    packets = rdpcap(samples_path + '/' + sample)

    if args.protocol:
        if args.protocol in names:
            prepinac(args.protocol)
        else:
            print("Error")
    else:
       new_statistics()
    