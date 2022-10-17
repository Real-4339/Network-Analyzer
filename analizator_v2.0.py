# Vadym Tilihuzov

from ruamel.yaml import YAML, scalarstring
from scapy.all import rdpcap
from argparse import ArgumentParser
from pprint import pprint
from module import *

import os

packets = rdpcap("vzory/trace-15.pcap")

def main():
    pcap_filename = 'vzory/trace-7.pcap'

    # dictoinary['pcap_name'] = "trace-27.pcap"

    yaml = YAML()
    file = open("PKS.yaml", "w")
    yaml.default_flow_style = False
    outputs = yaml.dump(dictoinary, file)
    file.close()

def prepinac(protocol):
    if protocol == 'TFTP':
        p = TFTP(protocol, packets)
        p.parsePackets()
        p.printAll()
        
    else:   
        p = Prepinac(protocol, packets)
        p.parsePackets()
        for flags in eval("Prepinac." + p.low).values():
            print(p.define(flags))
        p.printAll()

def statistics():
    ParseFile()
    stat = Statistics()
    start_statistics(stat)

    for index, packet in enumerate(packets):
        print("<-----Packet----->")
        p = Packet(packet, index+1)
        p.printAll()
        # if index == 10:
        #     break
    
    stat.printStatisctics()

if __name__ == '__main__':
    names = ['HTTP', 'HTTPS', 'TELNET', 'SSH', 'FTP-CONTROL', 'FTP-DATA', 'TFTP', 'ARP']
    parser = ArgumentParser(description='Input HTTP, HTTPS, TELNET, SSH, FTP, TFTP, ARP: ')
    parser.add_argument('-p', '--protocol', metavar='protocol', required=False)
    args = parser.parse_args()

    if args.protocol:
        if args.protocol in names:
            prepinac(args.protocol)
        else:
            print("Error")
    else:
        statistics()
    