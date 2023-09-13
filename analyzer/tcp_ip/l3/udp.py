import logging

from .type import L3
from tcp_ip.lib import ListOfUDP


''' Global variables '''
LOGGER = logging.getLogger('UDP')


class UDP(L3):
    name = "UDP"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__source_port = int( self.list_to_str( hex[0:2] ), 16 )
        self.__destination_port = int( self.list_to_str( hex[2:4] ), 16 )

        self.__protocol = self.resolve_protocol()

        self.__length = int( self.list_to_str( hex[4:6] ), 16 )
        self.__checksum = self.list_to_str( hex[6:8] )

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
    
    @property
    def protocol(self) -> str | None:
        return self.__protocol

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Source port: {self.source_port}")
        LOGGER.info(f"Destination port: {self.destination_port}")
        LOGGER.info(f"Length: {self.length}")
        LOGGER.info(f"Checksum: {self.checksum}")
        LOGGER.info(f"Protocol: {self.protocol}")

    def resolve_protocol(self) -> str | None:
        protocol = ListOfUDP.get(str(self.destination_port), None)
        if protocol is None:
            protocol = ListOfUDP.get(str(self.source_port), None)

        return protocol
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)
        data['src_port'] = self.source_port
        data['dst_port'] = self.destination_port
        data['app_protocol'] = self.protocol

        return data