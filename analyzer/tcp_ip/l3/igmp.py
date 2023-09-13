import logging

from .type import L3


''' Global variables '''
LOGGER = logging.getLogger('IGMP')


class IGMP(L3):
    name = "IGMP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

    def print_all(self) -> None:
        super().print_all()