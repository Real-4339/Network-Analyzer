import logging

from type import L1
from lib import ListOfSAPs


''' Global variables '''
LOGGER = logging.getLogger('LLC')


class LLC(L1):
    name = "IEEE 802.3 LLC"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__length = self.list_to_str(hex[12:14])
        self.__type = self.resolve_type(hex[14])

    @property
    def length(self) -> str:
        return str(int(self.__length, 16))
    
    @property
    def type(self) -> str | None:
        return self.__type
    
    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Length: {self.length}")
        LOGGER.info(f"Type: {self.type}")

    def resolve_type(self, sap: str) -> str | None:
        return ListOfSAPs.get(sap)