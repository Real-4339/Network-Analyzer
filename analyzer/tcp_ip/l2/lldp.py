import logging

from .type import L2


''' Global variables '''
LOGGER = logging.getLogger('LLDP')


class LLDP(L2):
    name = "LLDP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

    def print_all(self) -> None:
        super().print_all()