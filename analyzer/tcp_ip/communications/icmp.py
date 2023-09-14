from ..packet import Packet
from pprint import pprint


class ICMPCom:

    def __init__(self, packets: list[Packet], stat: dict[str, int]) -> None:
        self.stat = stat
        
        self.icmp_unknown: dict = {}
        self.icmp_complete: dict = {}
        self.icmp_uncomplete: dict = {}

        self.packets = self._parse_packets(packets)

    def _parse_packets(self, packets: list) -> list[Packet]:
        
        arr = []
        
        for index, packet in enumerate(packets):
            p = Packet(packet, index+1, self.stat)
            if p.L2 != None and p.L2.name == 'ICMP':
                arr.append(p)

        return arr