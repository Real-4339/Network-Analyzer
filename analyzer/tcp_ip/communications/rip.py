from ..packet import Packet
from pprint import pprint


class RIPCom:
    def __init__(self, packets, stat) -> None:
        '''
        :packets: list of Packet objects from pcap file
        :stats: Statistics object
        '''
        self.rip: list[Packet] = []
        self.packets = packets
        self.stat = stat

        self._parse_packet()

    def _parse_packet(self) -> None:
        for index, packet in enumerate(self.packets):
            p = Packet(packet, index+1, self.stat)
            if p.L2 != None and p.L2.name == "IPv4":
                if p.L2.protocol == "UDP":
                    if p.L3.protocol == "RIP":
                        self.rip.append(p)

    def print_result(self) -> None:
        pprint(self.rip)