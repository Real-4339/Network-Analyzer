from tcp_ip.l3.tcp import TCPFlags
from ..packet import Packet
from pprint import pprint


class TCPAll:

    def __init__(self, protocol: str, packets: list, stat) -> None:
        '''
        :flags: dict with unique key for each conversation and
        list of lists with src_ip:port from who that flags, and flags,
        for example:
        '192.168.1.33:50014->147.175.1.18:80' : [
            [192.168.1.33:50014, <TCPFlags.ACK: 16>],
            [147.175.1.18:80, <TCPFlags.ACK: 16>, <TCPFlags.RST: 4>]
        ]
        '''
        self.flags: dict[str, list[list[str, TCPFlags]]] = {}
        self.incomplete: dict[str, list[Packet]] = {}
        self.complete: dict[str, list[Packet]] = {}
        self.protocol = protocol
        self.stat = stat

        self.packets = self._test_parse_packets(packets)
        self._get_results()

    def _parse_packets(self, fpackets) -> list[Packet]:
        ''' Parse packets and fill flags '''
        arr = []
        for index, packet in enumerate(fpackets):
            p = Packet(packet, index+1, self.stat)
            if p.L3 and p.L3.protocol == self.protocol:
                
                arr.append(p)

                k1 = p.L2.src_ip+':'+str(p.L3.src_port)+'->'+\
                p.L2.dst_ip+':'+str(p.L3.dst_port)

                k2 = p.L2.dst_ip+':'+str(p.L3.dst_port)+'->'+\
                p.L2.src_ip+':'+str(p.L3.src_port)
                
                if k1 in self.flags:
                    self.flags[k1].append(p.L2.src_ip+':'+str(p.L3.src_port))
                    self.flags[k1].append(p.L3.flags)
                elif k2 in self.flags:
                    self.flags[k2].append(p.L2.dst_ip+':'+str(p.L3.dst_port))
                    self.flags[k2].append(p.L3.flags)
                else:
                    self.flags[k1] = [p.L2.src_ip+':'+str(p.L3.src_port), p.L3.flags] 
        
        return arr

    def _define(self, flags: list[list[str, TCPFlags]]) -> bool:
        '''
        (FIN | ACK on both sides or FIN termination and RST or termination with RST only) 
        '''
        first_correct_fin_sum = 0
        second_correct_fin_sum = 0
        correct_syn_sum = 0
        is_new_convo = True
        first_host = ''
        second_host = ''
        host = ''
        
        for arr in flags:
            for flag in arr:
                if isinstance(flag, str):
                    host = flag
                    if first_host == '':
                        first_host = flag
                    if second_host == '' and first_host != flag:
                        second_host = flag
                    continue
                if is_new_convo:
                    if flag == TCPFlags.SYN:
                        correct_syn_sum += TCPFlags.SYN.value
                    if flag == TCPFlags.ACK:
                        correct_syn_sum += TCPFlags.ACK.value
                    if correct_syn_sum == TCPFlags.ACK.value*2 + TCPFlags.SYN.value*2:
                        is_new_conv = False
                else:
                    if host == first_host:
                        if flag == TCPFlags.FIN:
                            first_correct_fin_sum |= TCPFlags.FIN.value
                        if flag == TCPFlags.ACK:
                            first_correct_fin_sum |= TCPFlags.ACK.value
                        if flag == TCPFlags.RST:
                            first_correct_fin_sum |= TCPFlags.RST.value
                    elif host == second_host:
                        if flag == TCPFlags.FIN:
                            second_correct_fin_sum |= TCPFlags.FIN.value
                        if flag == TCPFlags.ACK:
                            second_correct_fin_sum |= TCPFlags.ACK.value
                        if flag == TCPFlags.RST:
                            second_correct_fin_sum |= TCPFlags.RST.value
        if (
            (first_correct_fin_sum & TCPFlags.FIN.value == TCPFlags.FIN.value and
            first_correct_fin_sum & TCPFlags.ACK.value == TCPFlags.ACK.value) or
            first_correct_fin_sum & TCPFlags.RST.value == TCPFlags.RST.value
        ) and (
            (second_correct_fin_sum & TCPFlags.FIN.value == TCPFlags.FIN.value and
            second_correct_fin_sum & TCPFlags.ACK.value == TCPFlags.ACK.value) or
            second_correct_fin_sum & TCPFlags.RST.value == TCPFlags.RST.value
        ):
            return True
        return False

    def _test_parse_packets(self, fpackets: list[Packet]) -> list[Packet]:
        arr = []
        for index, packet in enumerate(fpackets):
            p = Packet(packet, index+1, self.stat)
            if p.L3 and p.L3.protocol == self.protocol:
                
                arr.append(p)
        
                k1 = p.L2.src_ip+':'+str(p.L3.src_port)+'->'+\
                p.L2.dst_ip+':'+str(p.L3.dst_port)

                k2 = p.L2.dst_ip+':'+str(p.L3.dst_port)+'->'+\
                p.L2.src_ip+':'+str(p.L3.src_port)
                
                if k1 in self.flags:
                    self.flags[k1].append(p.L3.flags)
                elif k2 in self.flags:
                    self.flags[k2].append(p.L3.flags)
                else:
                    self.flags[k1] = [p.L3.flags]

        return arr
    
    def _test_define(self, flags: list[list[TCPFlags]]) -> bool:
        is_new_conv = True
        correct_fin_sum = 0
        correct_syn_sum = 0

        for flah in flags:
            for flahosik in flah:
                if is_new_conv:
                    if flahosik == TCPFlags.SYN:
                        correct_syn_sum += TCPFlags.SYN.value
                    if flahosik == TCPFlags.ACK:
                        correct_syn_sum += TCPFlags.ACK.value

                    if correct_syn_sum == TCPFlags.ACK.value*2 + TCPFlags.SYN.value*2:
                        is_new_conv = False

                else:
                    if flahosik == TCPFlags.FIN:
                        correct_fin_sum |= TCPFlags.FIN.value
                    elif flahosik == TCPFlags.ACK:
                        correct_fin_sum |= TCPFlags.ACK.value
                    elif flahosik == TCPFlags.RST:
                        correct_fin_sum |= TCPFlags.RST.value
        
        return correct_fin_sum == (TCPFlags.FIN.value | TCPFlags.ACK.value) or correct_fin_sum & TCPFlags.RST.value == TCPFlags.RST.value
        
    def _get_results(self) -> None:
        ''' Fill complete and incomplete '''

        for key, value in self.flags.items():
            if self._test_define(value):
                self.complete[key] = []
                for p in self.packets:
                    
                    k1 = p.L2.src_ip+':'+str(p.L3.src_port)+'->'+\
                    p.L2.dst_ip+':'+str(p.L3.dst_port)

                    k2 = p.L2.dst_ip+':'+str(p.L3.dst_port)+'->'+\
                    p.L2.src_ip+':'+str(p.L3.src_port)
                    
                    if k1 == key or k2 == key:
                        self.complete[key].append(p)
            else:
                self.incomplete[key] = []
                for p in self.packets:
 
                    k1 = p.L2.src_ip+':'+str(p.L3.src_port)+'->'+\
                    p.L2.dst_ip+':'+str(p.L3.dst_port)

                    k2 = p.L2.dst_ip+':'+str(p.L3.dst_port)+'->'+\
                    p.L2.src_ip+':'+str(p.L3.src_port)
                    
                    if k1 == key or k2 == key:
                        self.incomplete[key].append(p)

    def print_result(self) -> None:
        pprint('Incomplete: ')
        pprint(self.incomplete)
        pprint('Complete: ')
        pprint(self.complete)

    def to_yaml(self, data) -> dict:

        data['complete_comms'] = []
        ind = 0
        for key, value in self.complete.items():
            num_comm = {}
            packets = []

            num_comm['num_comm'] = ind
            num_comm['src_comm'] = key.split('->')[0]
            num_comm['dst_comm'] = key.split('->')[1]

            for p in value:
                packets.append(p.get_packet())

            num_comm['packets'] = packets
            data['complete_comms'].append(num_comm)
            ind += 1

        data['partial_comms'] = []

        ind = 0
        for key, value in self.incomplete.items():
            num_comm = {}
            packets = []

            num_comm['num_comm'] = ind

            for p in value:
                packets.append(p.get_packet())

            num_comm['packets'] = packets
            data['partial_comms'].append(num_comm)
            ind += 1

        return data