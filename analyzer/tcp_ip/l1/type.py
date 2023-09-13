import logging


''' Global variables '''
LOGGER = logging.getLogger('L1')


class L1:
    def __init__(self, name, hex) -> None:
        self.__name = name

        self.__dst_mac = self.list_to_str(hex[0:6])
        self.__src_mac = self.list_to_str(hex[6:12])

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def dst_mac(self) -> str:
        return self.__dst_mac
    
    @property
    def src_mac(self) -> str:
        return self.__src_mac

    def list_to_str(self, data: list[str]) -> str:
        return ''.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 1: {self.name}")
        LOGGER.info(f"Destination MAC: {self.dst_mac}")
        LOGGER.info(f"Source MAC: {self.src_mac}")

    def resolve_type(self, hex) -> str | None:
        ...