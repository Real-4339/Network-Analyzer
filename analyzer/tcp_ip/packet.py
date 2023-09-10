import logging


''' Global variables '''
LOGGER = logging.getLogger('Packet')


class Packet:
    def __init__(self, packet, frame_num: int) -> None:
        self.__hex = self.get_hex(packet)
        self.__frame_num = frame_num

    def get_hex(self, packet) -> list[str]:
        data = bytes(packet).hex().upper()
        data = [data[i:i+2] for i in range(0, len(data), 2)]

        return data