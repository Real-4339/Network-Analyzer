import logging


''' Global variables '''
LOGGER = logging.getLogger('L3')


class L3:
    def __init__(self, name, hex) -> None:
        self.__name = name
        self.__hex = hex

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def hex(self) -> list[str]:
        return self.__hex

    def list_to_str(self, data: list[str]) -> str:
        return ''.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 3: {self.name}")

    def resolve_protocol(self, hex) -> str | None:
        ...