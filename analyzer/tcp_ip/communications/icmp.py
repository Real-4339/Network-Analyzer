from ..packet import Packet
from pprint import pprint
from .type import Com


class SingleICMP (Com):
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
        self.__identifier = None
        self.__start_frame: int = None
        self.__end_frame: int = None

        self.__start_seq_big: int = None
        self.__end_seq_big: int = None

        self.__start_seq_lit: int = None
        self.__end_seq_lit: int = None
        
        self.__confirmed: bool = False
        self.__packets: list[Packet] = []

    @property
    def key(self) -> str:
        return self.__key
    
    @property
    def identifier(self) -> int:
        return self.__identifier
    
    @property
    def start_frame(self) -> int:
        return self.__start_frame
    
    @property
    def end_frame(self) -> int:
        return self.__end_frame
    
    @property
    def start_seq_big(self) -> int:
        return self.__start_seq_big
    
    @property
    def end_seq_big(self) -> int:
        return self.__end_seq_big
    
    @property
    def start_seq_lit(self) -> int:
        return self.__start_seq_lit
    
    @property
    def end_seq_lit(self) -> int:
        return self.__end_seq_lit
    
    @property
    def packets(self) -> list[Packet]:
        return self.__packets
    
    def is_confirmed(self) -> bool:
        return self.__confirmed

    def add_packet(self, packet: Packet) -> bool:

        if self.end_seq_big + 1 == packet.L3.sequence_number_big and self.__confirmed:
            self.__end_seq_big = packet.L3.sequence_number_big
            self.__end_seq_lit = packet.L3.sequence_number_lit

            self.__end_frame = packet.frame_num
            self.__packets.append(packet)
            self.__confirmed = False
            return True

        elif self.end_seq_lit + 1 == packet.L3.sequence_number_lit and self.__confirmed:
            self.__end_seq_lit = packet.L3.sequence_number_lit
            self.__end_seq_big = packet.L3.sequence_number_big

            self.__end_frame = packet.frame_num
            self.__packets.append(packet)
            self.__confirmed = False
            return True
        
        elif packet.L3.sequence_number_big == self.end_seq_big:
            self.__end_frame = packet.frame_num
            self.__packets.append(packet)
            self.__confirmed = True
            return True
        
        elif packet.L3.sequence_number_lit == self.end_seq_lit:
            self.__end_frame = packet.frame_num
            self.__packets.append(packet)
            self.__confirmed = True
            return True
        
        return False

    def construct(self, packet) -> 'Conversation':
        self.__identifier = packet.L3.identifier

        self.__start_frame = packet.frame_num
        self.__end_frame = packet.frame_num

        self.__start_seq_big = packet.L3.sequence_number_big
        self.__end_seq_big = packet.L3.sequence_number_big

        self.__start_seq_lit = packet.L3.sequence_number_lit
        self.__end_seq_lit = packet.L3.sequence_number_lit
        
        self.__confirmed = False

        return self
    
    def __repr__(self) -> str:
        return f"Conversation({self.key}, identifier: {self.identifier}, \n\
        start seq (BE): {self.start_seq_big}, end seq (BE): {self.end_seq_big}, \n\
        start seq (LE): {self.start_seq_lit}, end seq (LE): {self.end_seq_lit},\n\
        start frame: {self.start_frame}, end frame: {self.end_frame})"
    
    def __eq__(self, o: 'Conversation') -> bool:

        if self.key == o.key and o.end_seq_big == self.end_seq_big and o.identifier == self.identifier:
            return True
        if self.key == o.key and o.end_seq_big == self.end_seq_big + 1 and o.identifier == self.identifier:
            return True
        if self.key == o.key and o.end_seq_lit == self.end_seq_lit and o.identifier == self.identifier:
            return True
        if self.key == o.key and o.end_seq_lit == self.end_seq_lit + 1 and o.identifier == self.identifier:
            return True
        else:
            return False


class FragmentedICMP:
    '''
    :param sum_of_data: sum of data length,
                        if sum_of_data == fragment_offset, then it is the last fragment
                        thats why if packet is not fragmented, he have sum_of_data == 0.
    :param confirmed: True if was received end fragment; False if not
    :param corrupted: True if was missing or corrupted fragment; False if not
    :param sequence_number: sequence number of first fragmented fragment, need for next validation of full conversation
    :param identifier: identifier of first fragmented fragment, need for next validation of full conversation
    '''
    def __init__(self, key) -> None:
        self.key: str = key
        self.identifier: int = None
        self.sequence_number_big: int = None
        self.sequence_number_lit: int = None

        self.start_frame: int = None
        self.end_frame: int = None
        self.confirmed: bool = False
        self.corrupted: bool = False
        self.identification: int = None

        self.packets: list[Packet] = []
        self.sum_of_data: int = -10
    
    def _check(self, packet: Packet) -> None:
        '''
        If that is last packet, set confirmed to True
        '''
        if 'MORE_FRAGMENTS' not in packet.L2.flags and packet.L2.fragment_offset == self.sum_of_data:
            self.confirmed = True

            packet.L3.sequence_number_big = self.sequence_number_big
            packet.L3.sequence_number_lit = self.sequence_number_lit

            packet.L3.identifier = self.identifier
            self.end_frame = packet.frame_num

        elif 'MORE_FRAGMENTS' not in packet.L2.flags and packet.L2.fragment_offset == 0:
            ''' For not fragmented packets '''
        
        elif 'MORE_FRAGMENTS' not in packet.L2.flags and packet.L2.fragment_offset != self.sum_of_data:
            self.confirmed = True
            self.corrupted = True

            packet.L3.sequence_number_big = self.sequence_number_big
            packet.L3.sequence_number_lit = self.sequence_number_lit
            
            packet.L3.identifier = self.identifier
            self.end_frame = packet.frame_num

    def construct(self, packet: Packet) -> 'FragmentedICMP':
        self.identification = packet.L2.identification
        self.start_frame = packet.frame_num
        self.end_frame = packet.frame_num
        self.confirmed = False
        self.packets.append(packet)
        self.sum_of_data = packet.L2.data_length

        if 'MORE_FRAGMENTS' in packet.L2.flags and packet.L2.fragment_offset == 0:
            self.sequence_number_big = packet.L3.sequence_number_big
            self.sequence_number_lit = packet.L3.sequence_number_lit

            self.identifier = packet.L3.identifier
        return self

    def add_packet(self, packet: Packet) -> None:
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
        return f"FragmentedICMP(key: {self.key}, start: {self.start_frame}, end: {self.end_frame}, confirmed: {self.confirmed}, \n\
        corrupted: {self.corrupted}, identification: {self.identification}, sum_of_data: {self.sum_of_data})"
    
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

    def _parse_pks(self, packets: list[Packet]) -> list[Packet]:
        for packet in self.packets:

            k1 = packet.L2.src_ip + ' -> ' + packet.L2.dst_ip
            k2 = packet.L2.dst_ip + ' -> ' + packet.L2.src_ip

            fragmented = FragmentedICMP(k1).construct(packet)

            if fragmented in self.fragmented:
                c = self.fragmented[self.fragmented.index(fragmented)]
                c.add_packet(packet)
            else:
                self.fragmented.append(fragmented)

            if 'MORE_FRAGMENTS' in packet.L2.flags:
                continue


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

    def _parse_icmp(self) -> None:
        for packet in self.packets:

            k1 = packet.L2.src_ip + ' -> ' + packet.L2.dst_ip
            k2 = packet.L2.dst_ip + ' -> ' + packet.L2.src_ip

            fragmented = FragmentedICMP(k1).construct(packet)

            if fragmented in self.fragmented:
                c = self.fragmented[self.fragmented.index(fragmented)]
                c.add_packet(packet)
            else:
                self.fragmented.append(fragmented)

            if 'MORE_FRAGMENTS' in packet.L2.flags:
                continue

            if packet.L3.identifier:

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
        
        print("\nICMP - incomplete")
        for convo in self.icmp_incomplete:
            print(convo)

        print("\nICMP - parts")
        for convo in self.fragmented:
            if convo.confirmed:
                print(convo)

    def to_yaml(self, data) -> dict:
        ...