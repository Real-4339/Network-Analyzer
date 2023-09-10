from __future__ import annotations

import logging

from analyzer.tcp_ip.lib import lib


''' Global variables '''
LOGGER = logging.getLogger('L2')


class L2:
    def __init__(self, name, hex) -> None:
        self.__name = name
        self.__hex = hex

    @property
    def name(self) -> str:
        return self.__name
    
    @property
    def hex(self) -> list[str]:
        return self.__hex

    def list_to_str(self, data: list[str]) -> str:
        return ''.join(data)
    
    def print_all(self) -> None:
        LOGGER.info(f"Layer 2: {self.name}")

    def resolve_protocol(self, hex) -> str | None:
        ...