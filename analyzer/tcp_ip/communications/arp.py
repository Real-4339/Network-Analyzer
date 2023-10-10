from ..packet import Packet
from .type import Com
from pprint import pprint


class ARPCom (Com):

    def __init__(self, packets, stat) -> None:
        '''
        :packets: list of Packet objects from pcap file
        :stats: Statistics object
        '''
        self.protocol = 'ARP'

        self.arp_unknown: dict[str, list[int, int]] = {}
        self.arp_false: dict[dict[str, list[int, int]]] = {}
        self.arp_true: dict[dict[str, list[int, int]]] = {}

        self.arp_true_yaml: list[Packet] = []
        self.arp_false_yaml: list[Packet] = []
        
        self.packets = packets
        self.stat = stat

        self._parse_packets()

    def _parse_packets(self) -> None:
        for index, packet in enumerate(self.packets):
            p = Packet(packet, index+1, self.stat)
            if p.L2 != None and p.L2.name == self.protocol:

                k1 = p.L2.src_ip + ' -> ' + p.L2.dst_ip
                k2 = p.L2.dst_ip + ' -> ' + p.L2.src_ip

                if k1 in self.arp_unknown:
                    self.arp_unknown[k1].append(p.frame_num)
                    self.arp_unknown[k1].append(p.L2.opcode)
                    self.arp_unknown[k1].append(p)                    
                elif k2 in self.arp_unknown:
                    self.arp_unknown[k2].append(p.frame_num)
                    self.arp_unknown[k2].append(p.L2.opcode)
                    self.arp_unknown[k2].append(p)
                else:
                    self.arp_unknown[k1] = [p.frame_num, p.L2.opcode, p]

        listOfComplete: list[list[str, int, int]] = []
        tmp = ''
        lupm = -1
        for k, v in self.arp_unknown.items():
            for ind, el in enumerate(v):
                if el == "REQUEST" and isinstance(tmp, str):
                    tmp = ind-1
                if el == "REPLY" and isinstance(tmp, int):
                    listOfComplete.append([k, tmp, ind+2])
                    tmp = ''
        
        ''' filling with complete '''
        for ind, a in enumerate(listOfComplete):
            if a[0] in self.arp_unknown:
                ppi = {a[0] : self.arp_unknown.get(a[0])[a[1]:a[2]]}
                self.arp_true[ind] = ppi

                del self.arp_unknown.get(a[0])[a[1]:a[2]]

        tmp = -1
        shift = 0
        ''' filling with incomplete '''
        for k, v in self.arp_unknown.items():
            for ind, el in enumerate(v):
                tmp += 1
                if tmp == 1:
                    ppi = {k : self.arp_unknown.get(k)[ind-1:ind+2]}
                    self.arp_false[shift] = ppi
                    shift += 1
                    tmp = -2

    def print_result(self) -> None:
        pprint('Complete communications: ')
        pprint(self.arp_true)
        pprint('Incomplete communications: ')
        pprint(self.arp_false)

    def to_yaml(self, data) -> dict:
        num_comm = {}
        packets = []

        data['complete_comms'] = []

        for k, v in self.arp_true.items():
            num_comm['number_comm'] = k
            packets = []

            for packet in v[0].values()[2::3]:
                packets.append(packet.get_packet())

            num_comm['packets'] = packets
            data['complete_comms'].append(num_comm)
        
        return data