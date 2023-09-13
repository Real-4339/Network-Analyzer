import logging

from .type import L2


''' Global variables '''
LOGGER = logging.getLogger('ARP')


class ARP(L2):
    name = "ARP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__options = {
            1: "Request",
            2: "Reply",
        }

        self.__opcode = self.__options.get(int(self.hex[7], 16))

    @property
    def opcode(self) -> str:
        return self.__opcode

    def print_all(self) -> None:
        super().print_all()

        LOGGER.info(f"Opcode: {self.opcode}")
        LOGGER.info(f"Sender MAC address: {self.list_to_str(self.hex[8:14]).replace(' ', ':')}")
        LOGGER.info(f"Target MAC address: {self.list_to_str(self.hex[18:24]).replace(' ', ':')}")

        LOGGER.info(f"Sender IP address: {self.get_ip(self.list_to_str(self.hex[14:18]))}")
        LOGGER.info(f"Target IP address: {self.get_ip(self.list_to_str(self.hex[24:28]))}")