from ..packet import Packet
from pprint import pprint


class SingleICMP:
    def __init__(self, key, packet) -> None:
        self.packet: Packet = packet
        self.key: str = key

    def __repr__(self) -> str:
        return f"SingleICMP({self.key} - {self.packet.frame_num})"

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

    def add_packet(self, packet: Packet) -> bool:
        
        if packet.L3.sequence_number > self.end_seq and self.__confirmed:
            self.__end_seq = packet.L3.sequence_number
            self.__packets.append(packet)
            self.__confirmed = False
            return True
        
        elif packet.L3.sequence_number == self.end_seq:
            self.__packets.append(packet)
            self.__confirmed = True
            return True
        
        return False

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

    def __init__(self, packets: list, stat: dict[str, int]) -> None:
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
            if p.L2 != None and p.L2.protocol == 'ICMP':
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

                    if convo in self.icmp_unknown[self.icmp_unknown.index(convo)+1:]:
                        for x in self.icmp_unknown[self.icmp_unknown.index(convo)+1:]:
                            if x == convo:
                                c = x
                                break
                    
                    if not c.add_packet(packet):
                        self.icmp_unknown.append(convo)
                
                elif conv in self.icmp_unknown:

                    c = self.icmp_unknown[self.icmp_unknown.index(conv)]
                    
                    if conv in self.icmp_unknown[self.icmp_unknown.index(conv)+1:]:
                        for x in self.icmp_unknown[self.icmp_unknown.index(conv)+1:]:
                            if x == conv:
                                c = x
                                break

                    if not c.add_packet(packet):
                        self.icmp_unknown.append(conv)
                
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

        del self.icmp_unknown

    def parse(self) -> None:
        self._parse_icmp()
        self._parse_icmp_complete()

    def print_result(self) -> None:
        print("ICMP\n-----------------")
        print("ICMP - complete")
        for convo in self.icmp_complete:
            print(convo)
        print("ICMP - incomplete")
        for convo in self.icmp_incomplete:
            print(convo)