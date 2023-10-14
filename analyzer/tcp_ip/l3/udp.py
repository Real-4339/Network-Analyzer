import logging

from .type import L3
from tcp_ip.lib import ListOfUDP


''' Global variables '''
LOGGER = logging.getLogger('UDP')


class UDP(L3):
    name = "UDP"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__src_port = int( self.list_to_str( hex[0:2] ), 16 )
        self.__dst_port = int( self.list_to_str( hex[2:4] ), 16 )

        self.__protocol = self.resolve_protocol()

        self.__length = int( self.list_to_str( hex[4:6] ), 16 )
        self.__checksum = self.list_to_str( hex[6:8] )

        self.__data_hex = hex[8:]

    @property
    def src_port(self) -> int:
        return self.__src_port

    @property
    def dst_port(self) -> int:
        return self.__dst_port

    @property
    def length(self) -> int:
        return self.__length

    @property
    def checksum(self) -> str:
        return self.__checksum
    
    @property
    def protocol(self) -> str | None:
        return self.__protocol
    
    @property
    def data_hex(self) -> list[str]:
        return self.__data_hex

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Source port: {self.src_port}")
        LOGGER.info(f"Destination port: {self.dst_port}")
        LOGGER.info(f"Length: {self.length}")
        LOGGER.info(f"Checksum: {self.checksum}")
        LOGGER.info(f"Protocol: {self.protocol}")

    def resolve_protocol(self) -> str:
        protocol = ListOfUDP.get(str(self.dst_port), None)
        if protocol is None:
            protocol = ListOfUDP.get(str(self.src_port), None)
        if protocol is None:
            return ''
        return protocol
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)
        data['src_port'] = self.src_port
        data['dst_port'] = self.dst_port
        if self.protocol != '':
            data['app_protocol'] = self.protocol

        return data