import logging


''' Global variables '''
LOGGER = logging.getLogger('L3')


class L3:
    def __init__(self, name, hex) -> None:
        self.__name = name
        self.__hex = hex
        self.__dst_port = ''
        self.__src_port = ''
        self.__protocol = ''
        self.__type = ''

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def hex(self) -> list[str]:
        return self.__hex
    
    @property
    def src_port(self) -> int:
        return self.__src_port
    
    @property
    def dst_port(self) -> int:
        return self.__dst_port
    
    @property
    def protocol(self) -> str:
        return self.__protocol
    
    @property
    def type(self) -> str:
        return self.__type

    def list_to_str(self, data: list[str]) -> str:
        return ''.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 3: {self.name}")

    def resolve_protocol(self, hex) -> str | None:
        ...

    def get_packet(self, data: dict) -> dict:
        data['protocol'] = self.name

        return data