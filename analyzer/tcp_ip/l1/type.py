import logging


''' Global variables '''
LOGGER = logging.getLogger('L1')


class L1:
    def __init__(self, name, hex) -> None:
        self.__name = name

        self.__dst_mac = self.list_to_str(hex[0:6]).replace(' ', ':')
        self.__src_mac = self.list_to_str(hex[6:12]).replace(' ', ':')
        self.__type = None

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def dst_mac(self) -> str:
        return self.__dst_mac
    
    @property
    def src_mac(self) -> str:
        return self.__src_mac
    
    @property
    def type(self) -> str | None:
        return self.__type

    def list_to_str(self, data: list[str]) -> str:
        return ' '.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 1: {self.name}")
        LOGGER.info(f"Destination MAC: {self.dst_mac}")
        LOGGER.info(f"Source MAC: {self.src_mac}")

    def resolve_type(self, hex) -> str | None:
        ...

    def get_packet(self, data: dict) -> dict:
        data['frame_type'] = self.name
        data['src_mac'] = self.src_mac
        data['dst_mac'] = self.dst_mac
        if self.type:
            if self.name == 'IEEE 802.3 LLC':
                data['sap'] = self.type
            if self.name == 'IEEE 802.3 LLC & SNAP':
                data['pid'] = self.type

        return data