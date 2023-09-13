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


class TCP(L3):
    name = "Transmission Control Protocol"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__source_port = int( self.list_to_str( hex[0:2] ), 16 )
        self.__destination_port = int( self.list_to_str( hex[2:4] ), 16 )

        self.__sequence_number = int(hex[4:8], 16)
        self.__acknowledgment_number = int(hex[8:12], 16)

        self.__flags = TCPFlags(int(hex[12:14], 16))
        self.__window_size = int(hex[14:16], 16)
        self.__checksum = hex[16:20]
        self.__urgent_pointer = int(hex[20:24], 16)

        self.__protocol = self.resolve_protocol()

    @property
    def source_port(self) -> int:
        return self.__source_port
    
    @property
    def destination_port(self) -> int:
        return self.__destination_port
    
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
    def protocol(self) -> str | None:
        return self.__protocol
    
    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Source port: {self.source_port}")
        LOGGER.info(f"Destination port: {self.destination_port}")
        LOGGER.info(f"Sequence number: {self.sequence_number}")
        LOGGER.info(f"Acknowledgment number: {self.acknowledgment_number}")
        LOGGER.info(f"Flags: {self.flags}")
        LOGGER.info(f"Window size: {self.window_size}")
        LOGGER.info(f"Checksum: {self.checksum}")
        LOGGER.info(f"Urgent pointer: {self.urgent_pointer}")
        LOGGER.info(f"Protocol: {self.protocol}")

    def resolve_protocol(self) -> str | None:
        protocol = ListOfTCP.get(str(self.destination_port), None)
        if protocol is None:
            protocol = ListOfTCP.get(str(self.source_port), None)

        return protocol