import logging


from type import L2


''' Global variables '''
LOGGER = logging.getLogger('ECTP')


class ECTP(L2):
    name = "Ethernet Configuration Testing Protocol"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

    def print_all(self) -> None:
        super().print_all()