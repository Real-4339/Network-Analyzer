import logging


''' Global variables '''
LOGGER = logging.getLogger('L2')


class L2:
    def __init__(self, name, hex) -> None:
        self.__name = name
        self.__hex = hex
        self.__src_ip = ''
        self.__dst_ip = ''
        self.__protocol = ''

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def hex(self) -> list[str]:
        return self.__hex
    
    @property
    def src_ip(self) -> str:
        return self.__src_ip
    
    @property
    def dst_ip(self) -> str:
        return self.__dst_ip
    
    @property
    def protocol(self) -> str:
        return self.__protocol

    def list_to_str(self, data: list[str]) -> str:
        return ' '.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 2: {self.name}")

    def resolve_protocol(self, hex) -> str | None:
        ...

    def get_ip(self, string: str) -> str | None:
        string = [str(int(string[i:i+2], 16)) for i in range(0, len(string), 3)]
        string = self.list_to_str(string).replace(' ', '.')
        return string
    
    def get_packet(self, data: dict) -> dict:
        data['ether_type'] = self.name

        return data