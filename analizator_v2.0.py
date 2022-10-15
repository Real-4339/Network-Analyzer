# Vadym Tilihuzov

from ruamel.yaml import YAML, scalarstring
from scapy.all import rdpcap
from pprint import pprint
from module import *

import os

packets = rdpcap("vzory/trace-26.pcap")

def main():
	pcap_filename = 'vzory/eth-1.pcap'

    # dictoinary['pcap_name'] = "trace-27.pcap"

	yaml = YAML()
	file = open("PKS.yaml", "w")
	yaml.default_flow_style = False
	outputs = yaml.dump(dictoinary, file)
	file.close()

if __name__ == '__main__':
	
	stat = Statistics()
	start_statistics(stat)

	for index, packet in enumerate(packets):
		print("<-----Packet----->")
		p = Packet(packet, index+1)
		p.printAll()

	stat.printStatisctics()