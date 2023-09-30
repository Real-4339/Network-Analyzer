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


class FragmentedICMP:
    def __init__(self, key) -> None:
        self.key: str = key
        self.identification: int = None
        self.start_frame: int = None
        self.end_frame: int = None
        self.confirmed: bool = False
        self.packets: list[Packet] = []
        self.sum_of_data: int = 0
        self.corrupted: bool = False
    
    def _check(self, packet: Packet) -> None:
        '''
        If that is last packet, set confirmed to True
        '''
        if packet.L2.flags == ['NONE'] and packet.L2.protocol == 'ICMP':
            self.confirmed = True
            self.end_frame = packet.frame_num

    def construct(self, packet: Packet) -> 'FragmentedICMP':
        self.identification = packet.L2.identification
        self.start_frame = packet.frame_num
        self.end_frame = packet.frame_num
        self.confirmed = False
        self.packets.append(packet)
        self.sum_of_data += packet.L2.data_length

        return self

    def add_packet(self, packet: Packet) -> bool:
        '''
        If packet added, return True
        '''
        if packet.L2.fragment_offset == self.sum_of_data:
            self._check(packet)
            self.packets.append(packet)
            self.sum_of_data += packet.L2.data_length    
        else:
            self.corrupted = True
            self._check(packet)
            self.packets.append(packet)
            self.sum_of_data += packet.L2.data_length
    
    def __repr__(self) -> str:
        return f"FragmentedICMP(key: {self.key}, start: {self.start_frame}, end: {self.end_frame}, confirmed: {self.confirmed}, corrupted: {self.corrupted},\
        identification: {self.identification}, sum_of_data: {self.sum_of_data})"
    
    def __eq__(self, o: 'FragmentedICMP') -> bool:
        if self.key == o.key and o.identification == self.identification:
            return True
        return False


class ICMPCom:

    def __init__(self, packets: list, stat: dict[str, int]) -> None:
        self.stat = stat
        
        self.icmp_complete: list[Conversation] = []
        self.icmp_incomplete: list[Conversation] = []
        self.icmp_unknown: list[Conversation] = []
        self.fragmented: list[FragmentedICMP] = []

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

            if packet.L3:
                print(packet.L3.identifier, packet.frame_num, packet.L3.name)
        
            if packet.L3.identifier or 'DONT_FRAGMENT' in packet.L2.flags:

                convo = Conversation(k1).construct(packet)
                conv = Conversation(k2).construct(packet)

                if convo in self.icmp_unknown:
                    
                    c = self.icmp_unknown[self.icmp_unknown.index(convo)]
                    
                    for x in self.icmp_unknown[self.icmp_unknown.index(convo)+1:]:
                        if x == convo:
                            c = x
                            break
                
                    if not c.add_packet(packet):
                        self.icmp_unknown.append(convo)
                
                elif conv in self.icmp_unknown:

                    c = self.icmp_unknown[self.icmp_unknown.index(conv)]
                    
                    for x in self.icmp_unknown[self.icmp_unknown.index(conv)+1:]:
                        if x == conv:
                            c = x
                            break

                    if not c.add_packet(packet):
                        self.icmp_unknown.append(conv)
                
                else:
                    self.icmp_unknown.append(convo)
                
                fragmented = FragmentedICMP(k1).construct(packet)

                if fragmented in self.fragmented:
                    c = self.fragmented[self.fragmented.index(convo)]
                    c.add_packet(packet)
                else:
                    self.fragmented.append(fragmented)
            
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

        print("ICMP - parts")
        for convo in self.fragmented:
            if convo.confirmed:
                print(convo)