import logging

from type import L3


''' Global variables '''
LOGGER = logging.getLogger('PIM')


class PIM(L3):
    name = "Protocol Independent Multicast"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

    def print_all(self) -> None:
        super().print_all()