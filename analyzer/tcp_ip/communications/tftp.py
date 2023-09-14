from ..packet import Packet
from pprint import pprint


class TFTPCom:

    def __init__(self, packets, stat) -> None:
        '''
        :tftp_sessions: list of lists, where each list is a session,
        with src_ip, src_port, dst_ip, dst_port
        :tftp: dict, with unique crafted key and values are numbers of frames
        :packets: list of Packet objects from pcap file
        :stats: Statistics object
        '''
        self.tftp: dict[str, list[int]] = {}
        self.tftp_sessions: list[list[str]] = []

        self.stats = stat

        self.packets = self.parse_packets(packets)
        self.start()

    def print_result(self) -> None:
        pprint(self.tftp)

    def print_other(self) -> None:
        pprint(self.tftp_sessions)

    def parse_packets(self, packets) -> list[Packet]:
        my_packets = []
        
        for index, packet in enumerate(packets):
            p = Packet(packet, index+1, self.stats)
            if p.L2 != None and p.L2.name == "IPv4":
                if p.L2.protocol == "UDP":
                    my_packets.append(p)
        
        return my_packets

    def start(self) -> None:
        ''' Main function '''

        ''' Find all starts of TFTP sessions '''
        for packet in self.packets:
            if packet.L3.protocol == "TFTP":
                self.tftp_sessions.append([packet.L2.src_ip, packet.L3.src_port, packet.L2.dst_ip])

        ''' Find dst ports for each session '''
        for packet in self.packets:
            for index, session in enumerate(self.tftp_sessions):
                if ( 
                packet.L2.src_ip == session[2] and
                packet.L3.dst_port == session[1] 
                ):
                    if packet.L3.src_port in self.tftp_sessions[index]:
                        continue
                    self.tftp_sessions[index].append(packet.L3.src_port)

        ''' Find all frames for each session '''     
        for packet in self.packets:
            for session in self.tftp_sessions:
                if (
                    (packet.L2.src_ip, packet.L3.src_port) == (session[0], session[1]) or
                    (packet.L2.src_ip, packet.L3.src_port) == (session[2], session[3])
                ):
                    
                    k1 = session[0]+':'+str(session[1])+'->'+session[2]+':'+str(session[3])
                    k2 = session[2]+':'+str(session[3])+'->'+session[0]+':'+str(session[1])

                    if k1 in self.tftp:
                        self.tftp[k1].append(packet.frame_num)
                    elif k2 in self.tftp:
                        self.tftp[k2].append(packet.frame_num)
                    else:
                        self.tftp[k1] = [packet.frame_num]