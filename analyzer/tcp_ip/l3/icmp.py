import logging

from type import L3
from lib.lib import ListOfICMP


''' Global variables '''
LOGGER = logging.getLogger('ICMP')


class ICMP(L3):
    name = "ICMP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__type = self.resolve_type(hex[0])

    @property
    def type(self) -> str:
        return self.__type

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Type: {self.type}")

    def resolve_type(self, hex: str) -> str:
        return ListOfICMP.get(hex, 16)