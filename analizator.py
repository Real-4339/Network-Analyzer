# Vadym Tilihuzov

from ruamel.yaml import YAML, scalarstring
from scapy.all import rdpcap
from pprint import pprint
import os

dictoinary = {"name" : "PKS2022/23",
              "pcap_name" : "",
              "packets" : []
              }

packets = rdpcap("vzory/trace-27.pcap")

def print_hex(x):
    shift = 0
    dst: str = ''
    
    for ind, s in enumerate(x):
        if ind % 2:
            if shift == 15:
                dst += x[ind-1]+s
                dst += '\n'
                shift = 0
                continue
            dst += x[ind-1]+s+" "
            shift += 1
            
    return dst

def print_mac(x):
    x = str(x)
    dest = ''
    source = ''
    shift = 0
    for ind, s in enumerate(x):
        if ind == 23:
            source += s
            shift += 1
            break
        elif ind > 11:
            if shift % 2 == 0:
                source += s
                shift += 1
            else:
                source += s + ':'
                shift += 1
        
        elif ind == 11:
            dest += s
            shift += 1 

        else:
            if shift % 2 == 0:
                dest += s
                shift += 1
            else:
                dest += s + ':'
                shift += 1

    # print("\n" + dest + " :dest")
    # print(source + " :source")
    dst = [dest, source]
    return dst

def print_l2(x):
    ISL = x[0] + x[1] + x[2] + x[3] + x[4] + x[5] + x[6] + x[7] + x[8] + x[9] + x[10] + x[11]

    eth = {  "0200" : "XEROX", "0201" : "PUP",
             "0800" : "IPv4", "0801" : "X.75",
             "0805" : "X.25", "0806" : "ARP",
             "8035" : "Reverse ARP", "809B" : "AppleTalk",
             "80F3" : "AppleTalk AARP","8100" : "802.1Q",
             "8137" : "Novell IPX", "86DD" : "IPv6",
             "880B" : "PPP", "8847" : "MPLS",
             "8848" : "MPLS with up",
             "8863" : "Discovery Stage",
             "8864" : "Session Stage"}

    # LLC & SNAP
    PIDs = {
    '2000': 'CDP',
    '2004': 'DTP',
    '010b': 'PVSTP+',
    '809b': 'AppleTalk',
    }

    # LLC
    sap = {"00" : "Null SAP",
           "02" : "Individual",
           "03" : "Group",
           "06" : "IP",
           "0e" : "Network Management",
           "42" : "STP",
           "4e" : "MMS",
           "5e" : "ISI IP",
           "7e" : "X.25 PLP",
           "8e" : "Active Station",
           "aa" : "SNAP",
           "e0" : "IPX",
           "f0" : "NETBIOS",
           "f4" : "LAN",
           "fe" : "ISO",
           "ff" : "Global DSAP"}

    if ISL == "01000c000000":
        _eth = x[24+52] + x[25+52] + x[26+52] + x[27+52]

        et2 = int(_eth, 16)
        _PIDs = x[40+52] + x[41+52] + x[42+52] + x[43+52]
        raw = x[28+52] + x[29+52] + x[30+52] + x[31+52]
        _sap = x[28+52] + x[29+52]
    
    else:
        _eth = x[24] + x[25] + x[26] + x[27]

        et2 = int(_eth, 16)
        _PIDs = x[40] + x[41] + x[42] + x[43]
        raw = x[28] + x[29] + x[30] + x[31]
        _sap = x[28] + x[29]
    

    if _eth in eth or et2 > 1500:
        return "ETHERNET II"
    elif raw == "ffff": 
        return "IEEE 802.3 RAW"
    elif raw == "aaaa":
        dst = [PIDs.get(_PIDs), "IEEE 802.3 LLC & SNAP"]
        return dst
    else:
        dst = [sap.get(_sap), "IEEE 802.3 LLC"]
        return dst

def print_bytes(x):
    return len(x)//2

def put_into_dict(x, index):
    global dictoinary

    len_frame_pcap = print_bytes(x)
    len_frame_medium = len_frame_pcap+4
    dst = print_l2(x)
    if type(dst) == str:
        frame_type = dst
    else:
        sap_pid = dst[0]
        frame_type = dst[1]

    dst = print_mac(x)
    dst_mac = dst[0]
    src_mac = dst[1]
    hexa_frame = print_hex(x)

    pid = sap = None
    if frame_type == 'IEEE 802.3 LLC & SNAP':
        pid = sap_pid
    if frame_type == 'IEEE 802.3 LLC':
        sap = sap_pid

    dictoinary['packets'].append({
        k: v for k, v in {
              "frame_number" : index,
              "len_frame_pcap" : len_frame_pcap,
              "len_frame_medium" : len_frame_medium,
              "frame_type" : frame_type,
              "src_mac" : src_mac,
              "dst_mac" : dst_mac,
              "sap" : sap,
              "pid" : pid,
              "hexa_frame" : scalarstring.LiteralScalarString(hexa_frame)}.items() if v != None
    })

def main(x, index):
    kk = bytes(x)
    kk = kk.hex()

    put_into_dict(kk, index)

def start():
    for index, a in enumerate(packets):
        main(a, index)

if __name__ == '__main__':



    # start()
    # dictoinary['pcap_name'] = "trace-27.pcap"

    # yaml = YAML()
    # file = open("PKS.yaml", "w")
    # yaml.default_flow_style = False
    # outputs = yaml.dump(dictoinary, file)
    # file.close()

    # for pack in os.listdir("vzory"):
    #     packets = rdpcap("vzory/" + pack)
    #     for index, a in enumerate(packets):
    #         main(a, index)
    #     dictoinary['pcap_name'] = pack

    #     yaml = YAML()
    #     file = open("PKS.yaml", "w")
    #     yaml.default_flow_style = False
    #     outputs = yaml.dump(dictoinary, file)
    #     file.close()
    #     os.system("python validator.py -s ./schemas/schema-task-1.yaml -d PKS.yaml")

# pprint(dictoinary)
# print(dictoinary)