from ..packet import Packet


class ARPCom:

    def __init__(self, packets, stat) -> None:
        '''
        :packets: list of Packet objects from pcap file
        :stats: Statistics object
        '''
        self.protocol = 'ARP'

        self.arp_unknown: dict[str, list[int, int]] = {}
        self.arp_false: dict[list[str, list[int, int]]] = {}
        self.arp_true: dict[list[str, list[int, int]]] = {}
        
        self.packets = packets
        self.stat = stat

        self._parse_packets()

    def _parse_packets(self) -> list[Packet]:
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
                self.arp_true[ind] = [ppi]
                del self.arp_unknown.get(a[0])[a[1]:a[2]]

        tmp = -1
        shift = 0
        ''' filling with incomplete '''
        for k, v in self.arp_unknown.items():
            for ind, el in enumerate(v):
                tmp += 1
                if tmp == 1:
                    ppi = {k : self.arp_unknown.get(k)[ind-1:ind+2]}
                    self.arp_false[shift] = [ppi]
                    shift += 1
                    tmp = -2