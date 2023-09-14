from ..packet import Packet
from pprint import pprint


class ICMPCom:

    def __init__(self, packets: list[Packet], stat: dict[str, int]) -> None:
        self.icmp_unknown: dict[str, list[int, int]] = {}
        self.icmp_false: dict[list[str, list[int, int]]] = {}
        self.icmp_true: dict[list[str, list[int, int]]] = {}
        
        self.packets = packets
        self.stat = stat

        self._parse_packets()

    def _parse_packets(self) -> None:
        ...