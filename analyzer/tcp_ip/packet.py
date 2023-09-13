import logging

from tcp_ip.l1 import *
from tcp_ip.l2 import *
from tcp_ip.l3 import *
from tcp_ip.l4.type import L4


''' Global variables '''
LOGGER = logging.getLogger('Packet')


class Packet:
    def __init__(self, packet, frame_num: int) -> None:
        self.__hex = self.get_hex(packet)
        self.__frame_num = frame_num
        self._create_additional_info()

    def get_hex(self, packet) -> list[str]:
        data = bytes(packet).hex().upper()
        data = [data[i:i+2] for i in range(0, len(data), 2)]

        return data
    
    def list_to_str(self, hex: list[str]) -> str:
        return ''.join(hex)
    
    def _l1_type(self, hex: list[str]) -> L1:
        
        if self.list_to_str(hex[0:6]) == '01000C000000':
            hex = hex[26:]

        data = int(self.list_to_str(hex[12:14]), 16)

        if data <= 1500:
            if hex[14] == 'AA':
                return LLC_SNAP(hex)
            elif hex[14] == 'FF':
                return RAW(hex)
            else:
                return LLC(hex)
        else:
            return EthernetII(hex)

    def _l2_type(self, l1: L1, hex: list[str]) -> L2 | None:
        if (
            type(l1) == LLC_SNAP or 
            type(l1) == LLC or
            type(l1) == RAW
        ):
            return None
        
        if l1.type == 'IPv4':
            return IPv4(hex[14:])
        elif l1.type == 'IPv6':
            return IPv6(hex[14:])
        elif l1.type == 'ARP':
            return ARP(hex[14:])
        elif l1.type == 'LLDP':
            return LLDP(hex[14:])
        else:
            return None

    def _l3_type(self, l2: L2, hex: list[str]) -> L3 | None:
        if (
            type(l2) == LLDP or
            type(l2) == ECTP or
            type(l2) == IPv6 or
            type(l2) == ARP or
            l2 is None
        ):
            return None
        
        if l2.protocol == 'ICMP':
            return ICMP(hex[34:])
        elif l2.protocol == 'IGMP':
            return IGMP(hex[34:])
        elif l2.protocol == 'TCP':
            return TCP(hex[34:])
        elif l2.protocol == 'UDP':
            return UDP(hex[34:])
        elif l2.protocol == 'PIM':
            return PIM(hex[34:])
        else:
            return None

    def _l4_type(self, l3: L3, hex: list[str]) -> L4 | None:
        if (
            type(l3) == ICMP or
            type(l3) == IGMP or
            type(l3) == PIM or
            l3 is None
        ):
            return None
        
        return None
        # return L4(hex[34:])
    
    def _create_additional_info(self) -> None:
        self.__len_frame_pcap = len(self.__hex)
        self.__len_frame_medium = max(self.__len_frame_pcap + 4, 64)
    
        self._create_layers()

    def _create_layers(self) -> None:
        '''
        :L1: network access layer
        :L2: internet layer
        :L3: transport layer
        :L4: application layer
        :return: None
        '''
        self.__l1 = self._l1_type(self.__hex)
        self.__l2 = self._l2_type(self.__l1, self.__hex)
        self.__l3 = self._l3_type(self.__l2, self.__hex)
        self.__l4 = self._l4_type(self.__l3, self.__hex)

    def print_all(self) -> None:
        LOGGER.info(f"Frame num: {self.__frame_num}")
        LOGGER.info(f"Frame length: {self.__len_frame_pcap} bytes")
        LOGGER.info(f"Frame length (medium): {self.__len_frame_medium} bytes")
        
        self.print_beautiful_hex()

        self.__l1.print_all()
        LOGGER.info("----------------------------------------")

        if self.__l2 is not None:
            self.__l2.print_all()
            LOGGER.info("----------------------------------------")
        
        if self.__l3 is not None:
            self.__l3.print_all()
            LOGGER.info("----------------------------------------")
        
        if self.__l4 is not None:
            self.__l4.print_all()
            LOGGER.info("----------------------------------------")

    def print_beautiful_hex(self) -> None:

        hex_str = self.list_to_str(self.__hex)

        for i in range(0, len(hex_str), 32):
            LOGGER.info(f"{hex_str[i:i+32]}")
        LOGGER.info("----------------------------------------")