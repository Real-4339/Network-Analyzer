import logging

from .type import L3
from tcp_ip.lib import ListOfICMP


''' Global variables '''
LOGGER = logging.getLogger('ICMP')


class ICMP(L3):
    name = "ICMP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__identifier: int = None
        self.__sequence_number: int = None

        self.resolve_type(hex[0])

    @property
    def type(self) -> str:
        return self.__type
    
    @property
    def identifier(self) -> int:
        return self.__identifier
    
    @property
    def sequence_number(self) -> int:
        return self.__sequence_number
    
    @property
    def checksum(self) -> int:
        return self.__checksum

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Type: {self.type}")
        LOGGER.info(f"Identifier: {self.identifier}")
        LOGGER.info(f"Sequence number: {self.sequence_number}")

    def resolve_type(self, hex: str) -> None:
        icmp_hex = int(str(int(hex, 16)), 10)
        icmp_hex = '0' + str(icmp_hex) if icmp_hex < 10 else str(icmp_hex)
        
        self.__type = ListOfICMP.get(icmp_hex, 'Information Reply')

        if (self.__type == "Echo reply" or
            self.__type == "Echo request"):

            self.__identifier = int(self.list_to_str(self.hex[4:6]), 16)
            self.__sequence_number = int(self.list_to_str(self.hex[6:8]), 16)
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)
        data['icmp_type'] = self.type

        return data