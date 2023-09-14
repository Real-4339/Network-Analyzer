from ..packet import Packet
from pprint import pprint


class TCPAll:

    def __init__(self, protocol: str, packets: list, stat) -> None:

        self.incomplete: dict[str, list[Packet]] = {}
        self.complete: dict[str, list[Packet]] = {}
        self.flags: dict[str, list] = {}
        self.protocol = protocol
                
        self.packets = packets
        self.stat = stat

        self._parse_packets()
        self._get_results()

    def _parse_packets(self) -> None:
        for index, packet in enumerate(self.packets):
            p = Packet(packet, index+1, self.stat)
            if p.L3.protocol == self.protocol:
                
                k1 = p.L2.src_ip+':'+str(p.L3.src_port)+'->'+\
                p.L2.dst_ip+':'+str(p.L3.dst_port)

                k2 = p.L2.dst_ip+':'+str(p.L3.dst_port)+'->'+\
                p.L2.src_ip+':'+str(p.L3.src_port)
                
                if k1 in self.flags:
                    self.flags[k1].append(p.L3.flags)
                elif k2 in self.flags:
                    self.flags[k2].append(p.L3.flags)
                else:
                    self.flags[k1] = [p.L3.flags]
    
    def print_result(self) -> None:
        pprint('Incomplete: ')
        pprint(self.incomplete)
        pprint('Complete: ')
        pprint(self.complete)

    def _define(self, flags: list) -> bool:
        ...

    def _get_results(self) -> None:
        ...