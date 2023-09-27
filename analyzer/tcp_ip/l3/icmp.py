import logging

from .type import L3
from tcp_ip.lib import ListOfICMP


''' Global variables '''
LOGGER = logging.getLogger('ICMP')


class ICMP(L3):
    name = "ICMP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.resolve_type(hex[0])

        self.__identifier: int = None
        self.__sequence_number: int = None

    @property
    def type(self) -> str:
        return self.__type

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Type: {self.type}")

    def resolve_type(self, hex: str) -> None:
        self.__type = ListOfICMP.get(hex, 16)
        
        if (self.__type == "Echo reply" or
            self.__type == "Echo request"):
            self.__identifier = int(hex[4:6], 16)
            self.__sequence_number = int(hex[6:8], 16)
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)
        data['icmp_type'] = self.type

        return data