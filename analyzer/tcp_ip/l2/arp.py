import logging

from .type import L2


''' Global variables '''
LOGGER = logging.getLogger('ARP')


class ARP(L2):
    name = "ARP"

    def __init__(self, hex) -> None:
        super().__init__(self.name, hex)

        self.__options = {
            1: "REQUEST",
            2: "REPLY",
        }

        self.__opcode = self.__options.get(int(self.hex[7], 16))
        self.__src_ip = self.get_ip(self.list_to_str(self.hex[14:18]))
        self.__dst_ip = self.get_ip(self.list_to_str(self.hex[24:28]))

    @property
    def opcode(self) -> str:
        return self.__opcode
    
    @property
    def src_ip(self) -> str:
        return self.__src_ip
    
    @property
    def dst_ip(self) -> str:
        return self.__dst_ip

    def print_all(self) -> None:
        super().print_all()

        LOGGER.info(f"Opcode: {self.opcode}")
        LOGGER.info(f"Sender MAC address: {self.list_to_str(self.hex[8:14]).replace(' ', ':')}")
        LOGGER.info(f"Target MAC address: {self.list_to_str(self.hex[18:24]).replace(' ', ':')}")

        LOGGER.info(f"Sender IP address: {self.get_ip(self.list_to_str(self.hex[14:18]))}")
        LOGGER.info(f"Target IP address: {self.get_ip(self.list_to_str(self.hex[24:28]))}")

    def get_packet(self, data: dict) -> dict:
        data = super().get_packet(data)

        data['arp_opcode'] = self.opcode
        data['src_ip'] = self.src_ip
        data['dst_ip'] = self.dst_ip

        return data