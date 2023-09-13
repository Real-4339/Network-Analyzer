import logging

from .type import L1
from tcp_ip.lib import ListOfEthernetII


''' Global variables '''
LOGGER = logging.getLogger('EthernetII')


class EthernetII(L1):
    name = "Ethernet II"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__type = self.resolve_type(hex[12:14])

    @property
    def type(self) -> str | None:
        return self.__type
    
    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Type: {self.type}")

    def resolve_type(self, type: list[str]) -> str | None:
        return ListOfEthernetII.get(self.list_to_str(type).replace(' ', ''))
