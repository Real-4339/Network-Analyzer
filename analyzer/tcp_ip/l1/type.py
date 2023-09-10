import logging


''' Global variables '''
LOGGER = logging.getLogger('L1')


class L1:
    def __init__(self, name, hex) -> None:
        self.__name = name

        self.__dst_mac = self.list_to_str(hex[0:6]).replace(" ", ":")
        self.__src_mac = self.list_to_str(hex[6:12]).replace(" ", ":")

    def list_to_str(self, data: list[str]) -> str:
        return ''.join(data)
    
    def print_all(self) -> None:
        ...

    def resolve_type(self, hex) -> str | None:
        ...