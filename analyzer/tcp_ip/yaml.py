import time

from ruamel.yaml import YAML
from tcp_ip.packet import Packet
from tcp_ip.statistics import Statistics
from tcp_ip.communications.type import Com


class Basic:
    def __init__(self, pcap_name: str, root_path: str, arr: list[Packet] = None, stat: Statistics = None) -> None:
        self.timestamp = time.strftime("%Y%m%d-%H%M%S")
        self.results_path = root_path + "/results/"
        
        self.root_path = root_path
        self.pcap_name = pcap_name
        self.packets = arr
        self.stat = stat

        self.data = self.create_data_to_dump()
        self.create_file()
    
    def create_data_to_dump(self) -> dict:
        data = {}
        data['name'] = 'PKS2023/24'
        data['pcap_name'] = self.pcap_name
        data['packets'] = []
        
        ''' Packets '''
        for packet in self.packets:
            data['packets'].append(packet.get_packet())

        ''' Statistics '''
        data['ipv4_senders'] = self.stat.get_all_senders()
        data['max_send_packets_by'] = self.stat.get_max_send_packets_by()
    
        return data

    def create_file(self) -> None:
        yaml = YAML()
        file = open(self.results_path + "PKS_" + self.timestamp + ".yaml", "w")
        yaml.default_flow_style = False
        outputs = yaml.dump(self.data, file) 
        file.close()


class Advanced(Basic):
    def __init__(self, pcap_name: str, root_path: str, filter:str, class_object: Com) -> None:
        
        self.filter = filter
        self.class_object = class_object

        super().__init__(pcap_name, root_path)
        
    def create_data_to_dump(self) -> dict:
        data = {}
        data['name'] = 'PKS2023/24'
        data['pcap_name'] = self.pcap_name
        data['filter_name'] = self.filter
        
        data = self.class_object.to_yaml(data)

        return data