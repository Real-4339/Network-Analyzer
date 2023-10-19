from tcp_ip.l3.tcp import TCPFlags
from ..packet import Packet
from .type import Com


class TCPSyn (Com):

    def __init__(self, packets: list, stat) -> None:
        '''
        :packets: list of packets that i get.
        :self.packets: list of packets, that have TCP.SYN flag in it. 
        '''
        self.stat = stat
        self.packets = self._parse_packets(packets)

    def _parse_packets(self, fpackets) -> list[Packet]:
        ''' Parse packets '''
        arr = []
        for index, packet in enumerate(fpackets):
            p = Packet(packet, index+1, self.stat)
            if p.L3 and p.L3.name == 'TCP' and TCPFlags.SYN == p.L3.flags[0]:
                arr.append(p)
        return arr
    
    def print_result(self) -> None:
        ''' Print results '''
        print('TCP SYN:')
        for packet in self.packets:
            print(packet.frame_num)
        print()
    