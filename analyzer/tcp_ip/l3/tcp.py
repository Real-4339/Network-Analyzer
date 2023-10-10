import logging

from .type import L3
from enum import Enum
from tcp_ip.lib import ListOfTCP


''' Global variables '''
LOGGER = logging.getLogger('TCP')


class TCPFlags(Enum):
    ACK: int = 0x010
    SYN: int = 0x002
    FIN: int = 0x001
    RST: int = 0x004
    PSH: int = 0x008
    URG: int = 0x020
    ECE: int = 0x040
    CWR: int = 0x080
    NS: int = 0x100
    RES1: int = 0x200


class TCP(L3):
    name = "TCP"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__src_port = int( self.list_to_str( hex[0:2] ), 16 )
        self.__dst_port = int( self.list_to_str( hex[2:4] ), 16 )

        self.__sequence_number = int( self.list_to_str( hex[4:8] ), 16 )
        self.__acknowledgment_number = int( self.list_to_str( hex[8:12] ), 16 )

        self.__header_length = ( int( self.list_to_str( hex[12:13] ), 16 ) >> 4 ) * 4

        self.__flags = self._get_flags()
        self.__window_size = int( self.list_to_str( hex[14:16] ), 16 )
        self.__checksum = self.list_to_str( hex[16:18] )
        self.__urgent_pointer = int( self.list_to_str( hex[18:20] ), 16 )

        self.__protocol = self.resolve_protocol()

    @property
    def src_port(self) -> int:
        return self.__src_port
    
    @property
    def dst_port(self) -> int:
        return self.__dst_port
    
    @property
    def sequence_number(self) -> int:
        return self.__sequence_number
    
    @property
    def acknowledgment_number(self) -> int:
        return self.__acknowledgment_number
    
    @property
    def flags(self) -> TCPFlags:
        return self.__flags
    
    @property
    def window_size(self) -> int:
        return self.__window_size
    
    @property
    def checksum(self) -> int:
        return self.__checksum
    
    @property
    def urgent_pointer(self) -> int:
        return self.__urgent_pointer
    
    @property
    def protocol(self) -> str:
        return self.__protocol
    
    @property
    def header_length(self) -> int:
        return self.__header_length
    
    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Source port: {self.src_port}")
        LOGGER.info(f"Destination port: {self.dst_port}")
        LOGGER.info(f"Sequence number: {self.sequence_number}")
        LOGGER.info(f"Acknowledgment number: {self.acknowledgment_number}")
        LOGGER.info(f"Header length: {self.header_length}")
        LOGGER.info(f"Flags: {self.flags}")
        LOGGER.info(f"Window size: {self.window_size}")
        LOGGER.info(f"Checksum: {self.checksum}")
        LOGGER.info(f"Urgent pointer: {self.urgent_pointer}")
        LOGGER.info(f"Protocol: {self.protocol}")

    def resolve_protocol(self) -> str:
        protocol = ListOfTCP.get(str(self.dst_port), None)
        if protocol is None:
            protocol = ListOfTCP.get(str(self.src_port), None)
        if protocol is None:
            return ''
        return protocol
    
    def _get_flags(self) -> TCPFlags:
        flags = []
        
        hex_value = int( self.list_to_str( self.hex[13:14] ), 16 )

        for flag in TCPFlags:
            if hex_value & flag.value == flag.value:
                flags.append(flag)

        return flags
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)
        data['src_port'] = self.src_port
        data['dst_port'] = self.dst_port
        data['app_protocol'] = self.protocol

        return data