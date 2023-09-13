import logging

from .type import L2


''' Global variables '''
LOGGER = logging.getLogger('IPv6')


class IPv6(L2):
    name = "IPv6"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

    def print_all(self) -> None:
        super().print_all()