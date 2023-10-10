import logging

from .type import L2
from enum import Enum
from tcp_ip.lib import ListOfIPv4

from tcp_ip.statistics import Statistics


''' Global variables '''
LOGGER = logging.getLogger('IPv4')


class IPv4Flags(Enum):
    NONE = 0b000
    RESERVED = 0b100
    DONT_FRAGMENT = 0b010
    MORE_FRAGMENTS = 0b001

    @staticmethod
    def combine(hex: int) -> list['IPv4Flags']:
        flags = []

        for flag in IPv4Flags:
            if hex & flag.value == flag.value:
                flags.append(flag.name)
        if len(flags) > 1:
            flags.remove('NONE')
        return flags


class IPv4(L2):
    name = "IPv4"
    bitmask = 0b11100000

    def __init__(self, hex, stat: Statistics) -> None:
        super().__init__(self.name, hex)

        self.__version = int(self.hex[0], 16) >> 4
        self.__header_length = (int(self.hex[0], 16) & 0x0F) * 4  

        self.__dscp = int(self.hex[1], 16) >> 2
        self.__ecn = int(self.hex[1], 16) & 0x03
        self.__total_length = int(self.list_to_str(self.hex[2:4]).replace(' ', ''), 16)
        self.__identification = int(self.list_to_str(self.hex[4:6]).replace(' ', ''), 16)

        self.__flags = IPv4Flags.combine((int(self.hex[6], 16) & self.bitmask) >> 5)
        self.__fragment_offset = ( int(self.list_to_str(self.hex[6:8]).replace(' ', ''), 16) & 0x1FFF ) * 8
        
        self.__ttl = int(self.hex[8], 16)
        self.__protocol = self.resolve_protocol(self.hex[9])
        self.__header_checksum = self.list_to_str(self.hex[10:12]).replace(' ', '')

        self.__src_ip = self.get_ip(self.list_to_str(self.hex[12:16]))
        self.__dst_ip = self.get_ip(self.list_to_str(self.hex[16:20]))

        self.__data_length = self.__total_length - self.__header_length

        self._statistics = stat

        self._count_statistics()

    @property
    def version(self) -> int:
        return self.__version

    @property
    def header_length(self) -> int:
        return self.__header_length

    @property
    def dscp(self) -> int:
        return self.__dscp

    @property
    def ecn(self) -> int:
        return self.__ecn

    @property
    def total_length(self) -> int:
        return self.__total_length

    @property
    def identification(self) -> int:
        return self.__identification

    @property
    def flags(self) -> str:
        return self.__flags

    @property
    def fragment_offset(self) -> int:
        return self.__fragment_offset

    @property
    def ttl(self) -> int:
        return self.__ttl
    
    @property
    def protocol(self) -> str:
        return self.__protocol
    
    @property
    def header_checksum(self) -> str:
        return self.__header_checksum
    
    @property
    def src_ip(self) -> str:
        return self.__src_ip
    
    @property
    def dst_ip(self) -> str:
        return self.__dst_ip
    
    @property
    def data_length(self) -> int:
        return self.__data_length
    
    @property
    def statistics(self) -> dict[str, int]:
        return self._statistics.ip_sources
    
    def print_all(self) -> None:
        super().print_all()

        LOGGER.info(f"Version: {self.version}")
        LOGGER.info(f"Header length: {self.header_length}")
        LOGGER.info(f"DSCP: {self.dscp}")
        LOGGER.info(f"ECN: {self.ecn}")
        LOGGER.info(f"Total length: {self.total_length}")
        LOGGER.info(f"Identification: {self.identification}")
        LOGGER.info(f"Flags: {self.flags}")
        LOGGER.info(f"Fragment offset: {self.fragment_offset}")
        LOGGER.info(f"TTL: {self.ttl}")
        LOGGER.info(f"Protocol: {self.protocol}")
        LOGGER.info(f"Header checksum: {self.header_checksum}")
        LOGGER.info(f"Source IP address: {self.src_ip}")
        LOGGER.info(f"Destination IP address: {self.dst_ip}")

    def resolve_protocol(self, hex: str) -> str:
        res = ListOfIPv4.get(hex)
        if res is None:
            return ''
        return res
    
    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)

        data['src_ip'] = self.src_ip
        data['dst_ip'] = self.dst_ip
        data['id'] = self.identification
        data['flags_mf'] = 'MORE_FRAGMENTS' in self.flags
        data['frag_offset'] = self.fragment_offset
        
        return data
    
    def _count_statistics(self) -> None:
        ''' Count statistics '''
        if self.src_ip in self.statistics:
            self.statistics[self.src_ip] += 1
        else:
            self.statistics[self.src_ip] = 1