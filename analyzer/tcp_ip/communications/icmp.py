from ..packet import Packet
from pprint import pprint


class SingleICMP:
    def __init__(self, key, packet) -> None:
        self.packet: Packet = packet
        self.key: str = key

class Conversation:
    def __init__(self, key) -> None:
        '''
        :param key: key is ip_src -> ip_dst
        :param start_seq: start sequence number
        :param end_seq: end sequence number
        :param confirmed: True if was received a response, 
                          when sending a new packet, the value is set to False
        '''
        self.__key: str = key
        self.__start_seq: int = None
        self.__end_seq: int = None
        self.__confirmed: bool = False

        self.__packets: list[Packet] = []

    @property
    def key(self) -> str:
        return self.__key
    
    @property
    def start_seq(self) -> int:
        return self.__start_seq
    
    @property
    def end_seq(self) -> int:
        return self.__end_seq
    
    @property
    def packets(self) -> list[Packet]:
        return self.__packets
    
    def is_confirmed(self) -> bool:
        return self.__confirmed

    def add_packet(self, packet: Packet) -> None:
        self.__packets.append(packet)
        if packet.L3.sequence_number > self.end_seq:
            self.__end_seq = packet.L3.sequence_number
            self.__confirmed = False
        else:
            self.__confirmed = True

    def construct(self, packet) -> 'Conversation':
        self.__start_seq = packet.L3.sequence_number
        self.__end_seq = packet.L3.sequence_number
        self.__confirmed = False

        return self
    
    def __repr__(self) -> str:
        return f"Conversation({self.key}, {self.start_seq}, {self.end_seq})"
    
    def __eq__(self, o: 'Conversation') -> bool:
        if self.key == o.key and o.end_seq == self.end_seq:
            return True
        if self.key == o.key and o.end_seq == self.end_seq + 1:
            return True
        else:
            return False


class ICMPCom:

    def __init__(self, packets: list[Packet], stat: dict[str, int]) -> None:
        self.stat = stat
        
        self.icmp_complete: list[Conversation] = []
        self.icmp_incomplete: list[Conversation] = []
        self.icmp_unknown: list[Conversation] = []

        self.packets = self._parse_packets(packets)
        self.parse()

    def _parse_packets(self, packets: list) -> list[Packet]:
        
        arr = []
        
        for index, packet in enumerate(packets):
            p = Packet(packet, index+1, self.stat)
            if p.L2 != None and p.L2.name == 'ICMP':
                arr.append(p)

        return arr

    def _parse_icmp(self) -> None:
        for packet in self.packets:

            k1 = packet.L2.src_ip + ' -> ' + packet.L2.dst_ip
            k2 = packet.L2.dst_ip + ' -> ' + packet.L2.src_ip


            if packet.L3.identifier:
                
                convo = Conversation(k1).construct(packet)
                conv = Conversation(k2).construct(packet)

                if convo in self.icmp_unknown:
                    c = self.icmp_unknown[self.icmp_unknown.index(convo)]
                    c.add_packet(packet)
                    # self.icmp_unknown[self.icmp_unknown.index(Conversation(k1))] = c
                elif conv in self.icmp_unknown:
                    c = self.icmp_unknown[self.icmp_unknown.index(conv)]
                    c.add_packet(packet)
                    # self.icmp_unknown[self.icmp_unknown.index(Conversation(k2))] = c
                else:
                    self.icmp_unknown.append(convo)
            
            else:
                c = SingleICMP(k1, packet)
                self.icmp_incomplete.append(c)

    def _parse_icmp_complete(self) -> None:
        for convo in self.icmp_unknown:
            if convo.is_confirmed():
                self.icmp_complete.append(convo)
            else:
                self.icmp_incomplete.append(convo)

    def parse(self) -> None:
        self._parse_icmp()
        self._parse_icmp_complete()