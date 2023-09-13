import logging

from .type import L1


''' Global variables '''
LOGGER = logging.getLogger('Raw')


class RAW(L1):
    name = "IEEE 802.3 RAW"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__length = self.list_to_str(hex[12:14])
    
    @property
    def length(self) -> str:
        return str(int(self.__length, 16))
    
    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Length: {self.length}")