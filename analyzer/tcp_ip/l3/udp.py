import logging

from type import L3
from lib import ListOfUDP


''' Global variables '''
LOGGER = logging.getLogger('UDP')


class UDP(L3):
    name = "User Datagram Protocol"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__source_port = int( self.list_to_str( hex[0:2] ), 16 )
        self.__destination_port = int( self.list_to_str( hex[2:4] ), 16 )
        self.__length = int(hex[8:12], 16)
        self.__checksum = int(hex[12:16], 16)

    @property
    def source_port(self) -> int:
        return self.__source_port

    @property
    def destination_port(self) -> int:
        return self.__destination_port

    @property
    def length(self) -> int:
        return self.__length

    @property
    def checksum(self) -> str:
        return self.__checksum

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Source port: {self.source_port}")
        LOGGER.info(f"Destination port: {self.destination_port}")
        LOGGER.info(f"Length: {self.length}")
        LOGGER.info(f"Checksum: {self.checksum}")