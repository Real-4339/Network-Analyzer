import logging

from .type import L4
from typing import Union


''' Global variables '''
LOGGER = logging.getLogger('TFTP')


class TFTP(L4):
    name = "TFTP"

    def __init__(self, hex: list[str]) -> None:
        super().__init__(self.name, hex)

        self.__length = len(hex)

        self.__opcode = int( self.list_to_str( hex[0:2] ), 16 )
        self.__filename = NotImplemented
        self.__type = NotImplemented
        self.__block = NotImplemented

        self._create_additional_info()

    @property
    def opcode(self) -> int:
        return self.__opcode
    
    @property
    def filename(self) -> Union[str, NotImplemented]:
        return self.__filename
    
    @property
    def type(self) -> Union[str, NotImplemented]:
        return self.__type
    
    @property
    def block(self) -> Union[int, NotImplemented]:
        return self.__block
    
    def _create_additional_info(self) -> None:
        ''' Create additional info based on opcode '''

        len = self.__length - 9

        if self.opcode == 1:
            ''' 1 - Read request '''
            
            self.__type = bytes.fromhex(self.list_to_str(self.hex[len:-1])).decode('utf-8')
            self.__filename = bytes.fromhex(self.list_to_str(self.hex[2: len])).decode('utf-8')
        
        elif self.opcode == 2:
            ''' 2 - Write request '''
            self.__filename = bytes.fromhex(self.list_to_str(self.hex[2: len])).decode('utf-8')
            self.__type = bytes.fromhex(self.list_to_str(self.hex[len:-1])).decode('utf-8')

        elif self.opcode == 3:
            ''' 3 - Data '''
            self.__block = int(self.list_to_str(self.hex[2:4]), 16)
        elif self.opcode == 4:
            ''' 4 - Acknowledgment '''
            self.__block = int(self.list_to_str(self.hex[2:]), 16)
        elif self.opcode == 5:
            ''' 5 - Error '''
            self.__block = int(self.list_to_str(self.hex[2:]), 16)

    def print_all(self) -> None:
        super().print_all()
        LOGGER.info(f"Opcode: {self.opcode}")
        LOGGER.info(f"Filename: {self.filename}")
        LOGGER.info(f"Type: {self.type}")
        LOGGER.info(f"Block: {self.block}")