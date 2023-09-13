import logging


''' Global variables '''
LOGGER = logging.getLogger('Statistics')


class Statistics:

    def __init__(self) -> None:
        self.__ip_sources: dict[str, int] = {}

    @property
    def ip_sources(self) -> dict[str, int]:
        return self.__ip_sources
    
    def print_statistics(self) -> None:
        mval = max(self.__ip_sources.values())
        rad = [[k, v] for k, v in self.__ip_sources.items() if v == mval]

        LOGGER.info(f"Source IPv4 addresses: ")
        for key, value in self.__ip_sources.items():
            LOGGER.info(f"{key}: {value} packets")

        for i in rad:
            LOGGER.info(f"Address/es with the largest number of send packets: {i[0]}. Packets amount: ( {i[1]} )")

    def get_all_senders(self) -> list[dict[str, str]]:
        ipv4_senders = []
        for key, value in self.__ip_sources.items():
            ipv4_senders.append({'node': key, 'number_of_sent_packets': value})

        return ipv4_senders

    def get_max_send_packets_by(self) -> dict[str, str]:
        max_send_packets_by = {}
        
        if self.__ip_sources == {}:
            return max_send_packets_by 

        mval = max(self.__ip_sources.values())
        rad = [[k, v] for k, v in self.__ip_sources.items() if v == mval]

        for i in rad:
            max_send_packets_by['max_send_packets_by'] = i[0]

        return max_send_packets_by
