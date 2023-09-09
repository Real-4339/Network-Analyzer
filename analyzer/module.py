from __future__ import annotations

import os.path

from typing import TypeVar
from pprint import pprint
from enum import Enum


# GLOBALS
StatisticsT = TypeVar("StatisticsT", bound="Statistics")
stat: StatisticsT

ListOfEthernetII: dict[str, str] = {}

# LLC & SNAP
ListOfPIDs: dict[str, str] = {}

# LLC
ListOfSaps: dict[str, str] = {}

ListOfIPv4: dict[str, str] = {}

ListOfUDP: dict[str, str] = {}

ListOfTCP: dict[str, str] = {}

ListOfICMP: dict[str, str] = {}

# FUNCTIONS

def ParseFile():
  Names = ['ListOfEthernetII', 'ListOfPIDs',
           'ListOfSaps', 'ListOfIPv4', 'ListOfUDP',
           'ListOfTCP', 'ListOfICMP'] # HACK: hardcode
  key = ''
  value = ''
  shift = -1

  pwd = os.path.dirname(os.path.abspath(__file__))
  file_path = os.path.join(pwd, 'protocols' , 'set.txt')

  try:
    file = open(file_path, 'r')
  except FileNotFoundError:
    print("File not found")
    exit(1)
  lines = file.readlines() # list

  for line in lines:
    if line[0] == "#":
      shift += 1
      continue

    index = line.find(' ')

    key = line[0:index]
    value = line[index+1:len(line)-1]

    eval(Names[shift])[key] = value

  file.close()
  
def start_statistics(s):
  global stat
  stat = s

def getHex(packet):

  data = bytes(packet).hex().upper()
  data = [data[i:i+2] for i in range(0, len(data), 2)]

  return data

def getIP(string: str):
  string = [str(int(string[i:i+2], 16)) for i in range(0, len(string), 3)]
  string = listToString(string).replace(' ', '.')
  return string

def listToString(s):
  str1 = " "     
  return (str1.join(s))

def L1Type(hexy):
  
  if listToString(hexy[0:6]).replace(" ", "") == "01000C000000":
    hexy = hexy[26:]

  data = int(listToString(hexy[12:14]).replace(" ", ""), 16)

  if (data) < 1500:
    if(listToString(hexy[14]).replace(" ", "") == "AA"):
      return LLC_SNAP(hexy)

    elif(listToString(hexy[14]).replace(" ", "") == "FF"):
      return RAW(hexy)

    else:
      return LLC(hexy)
  else:
    return EthernetII(hexy)

def L2Type(s, hexy):
  if type(s) == LLC_SNAP or type(s) == LLC or type(s) == RAW:
    return None

  if s.type == "IPv4":
    return IPv4(hexy[14:])
  if s.type == "IPv6":
    return IPv6(hexy[14:] )
  if s.type == "ARP":
    return ARP(hexy[14:])
  if s.type == "LLDP":
    return LLDP(hexy[14:])

def L3Type(s, hexy):
  if type(s) == IPv6 or type(s) == ARP or type(s) == LLDP or type(s) == ECTP or s == None:
    return None

  if s.protocol == "ICMP":
    return ICMP(hexy[34:])
  if s.protocol == "IGMP":
    return IGMP(hexy[34:])
  if s.protocol == "TCP":
    return TCP(hexy[34:])
  if s.protocol == "UDP":
    return UDP(hexy[34:])
  if s.protocol == "PIM":
    return PIM(hexy[34:])

def L4Type(s, hexy):
  if type(s) == ICMP or type(s) == IGMP or type(s) == PIM or s == None:
    return None

  ...

# CLASSES

class Packet:
  def __init__(self, packet, frame_number):
    self.hexy = getHex(packet)
    self.frame_number = frame_number
    self.Content()

  def Content(self):
    self.len_frame_pcap = len(self.hexy)
    self.len_frame_medium = max(self.len_frame_pcap+4, 64)

    self.struct()

  def struct(self):
    """
    :L1: network access
    :L2: internet
    :L3: transport
    :L4: application
    :return: None or class
    """
    self.L1 = L1Type(self.hexy) 
    self.L2 = L2Type(self.L1, self.hexy)
    self.L3 = L3Type(self.L2, self.hexy)
    # self.L4 = L4Type(self.L3, self.hexy)

  def printAll(self):
    print(self.hexy, self.frame_number, self.len_frame_pcap,
          self.len_frame_medium)
    
    # call printAll from others classes
    if self.L1:
      self.L1.printAll()
    if self.L2:
      self.L2.printAll()
    if self.L3:
      self.L3.printAll()
    # if self.L4:
    #   self.L4.printAll()


class L1:
  def __init__(self, name, hexy):
    # getting MAC address
    self.name = name

    self.srcmac = listToString(hexy[6:12]).replace(" ", ":")
    self.destmac = listToString(hexy[0:6]).replace(" ", ":")

  def printAll(self):
    print(self.name, self.srcmac, self.destmac)


class LLC_SNAP(L1):
  name = "IEEE 802.3 LLC & SNAP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.lenght = listToString(hexy[12:14]).replace(" ", "")
    self.type = self.resolveType(hexy)

  def printAll(self):
    print(self.name, self.srcmac, self.destmac, self.type, "llc&snap")

  def resolveType(self, hexy):
    PID = listToString(hexy[20:22]).replace(" ", "")
    return ListOfPIDs.get(PID)


class LLC(L1):
  name = "IEEE 802.3 LLC"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.lenght = listToString(hexy[12:14]).replace(" ", "")
    self.type = self.resolveType(hexy)

  def printAll(self):
    print(self.name, self.srcmac, self.destmac, self.type, "llc")

  def resolveType(self, hexy):
    SAP = listToString(hexy[14]).replace(" ", "")
    return ListOfSaps.get(SAP)


class RAW(L1):
  name = "IEEE 802.3 RAW"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.lenght = listToString(hexy[12:14]).replace(" ", "")

  def printAll(self):
    print(self.name, self.srcmac, self.destmac, "raw")

  def resolveType(self, hexy):
    pass


class EthernetII(L1):
  name = "ETHERNET II"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.type = self.resolveType(hexy)

  def printAll(self):
      print(self.name, self.srcmac, self.destmac, self.type, "eth")

  def resolveType(self, hexy):
    EtherType = listToString(hexy[12:14]).replace(" ", "")
    return ListOfEthernetII.get(EtherType)


class L2:
  def __init__(self, name, hexy):
    self.name = name
    self.hexy = hexy

  def printAll(self):
    print(self.name)

# ! frag_offset
class IPv4(L2):
  name = "IPv4"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.ihl = int(listToString(self.hexy[0])[2])*4
    self.protocol = self.resolveProtocol()
    self.src_ip = getIP(listToString(self.hexy[12:16]))
    self.dst_ip = getIP(listToString(self.hexy[16:20]))
    self.id = int(listToString(self.hexy[4:6]).replace(' ', ''), 16)
    flages = str(bin(int(listToString(self.hexy[6:8]).replace(' ', ''), 16)))[2:]
    if len(flages) < 16:
      st = '0'
      diff = 16 - len(flages)
      flages = st*diff + flages
    self.flags_mf = flages[2]
    # print(flages[4:])
    # print(flages)
    self.frag_offset = int(flages[4:],16)

  def resolveProtocol(self):
    return ListOfIPv4.get(self.hexy[9])
   
  def printAll(self):
    print (self.name, "\nihl:", self.ihl, "protocol:", self.protocol, 
          '\nid:', self.id, 'flag_mf:', self.flags_mf, 'flag_offset:', self.frag_offset)
    
    # printing out IP addresses 
    print ('IP src.addr: ', self.src_ip)
    print ('IP dst.addr: ', self.dst_ip)

    # counting statistic
    if self.src_ip in stat.IPSources:
      stat.IPSources[self.src_ip] += 1
    else:
      stat.IPSources[self.src_ip] = 1


class IPv6(L2):
  name = "IPv6"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)
  
  def printAll(self):
    print (self.name)


class ARP(L2):
  name = "ARP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)
    self.options = {1: 'Request',
                    2: 'Reply' }
    self.opcode = self.options.get(int(listToString(self.hexy[7:8]), 16))
  
  def printAll(self):
    print (self.name)
    print (self.opcode)

    print ('Sender MAC Address', listToString(self.hexy[8:14]).replace(' ', ':'))
    print ('Target MAC Address', listToString(self.hexy[18:24]).replace(' ', ':'))

    print ('Sender IP Address', getIP(listToString(self.hexy[14:18])))
    print ('Target IP Address', getIP(listToString(self.hexy[24:28])))


class ECTP(L2):
  name = "ECTP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

  def printAll(self):
    print (self.name)


class LLDP(L2):
  name = "LLDP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

  def printAll(self):
    print (self.name)


class L3:
  def __init__(self, name, hexy):
    self.name = name
    self.hexy = hexy

  def printAll(self):
    print(self.name)


class TCPFlags(Enum):
  ACK: int     = 0x010
  SYN: int     = 0x002
  FIN: int     = 0x001
  RST: int     = 0x004


class TCP(L3):
  name = "TCP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)
    self.flags: list[int] = []
    flager = int(listToString(hexy[12:14]).replace(' ', ''), 16)

    self.srcPort = int( listToString( self.hexy[0:2] ).replace(' ', ''), 16 )
    self.dstPort = int( listToString( self.hexy[2:4] ).replace(' ', ''), 16 )
    
    for flag in TCPFlags:
      if (flager&flag.value) == flag.value:
        self.flags.append(flag)

    self.protocol = self.resolveProtocol()

  def resolveProtocol(self):
    protocol = ListOfTCP.get(str(self.dstPort))
    if not protocol:
      protocol = ListOfTCP.get(str(self.srcPort))

    return protocol

  def printAll(self):
    print (self.name)
    # printing ports
    print ('src.port:', self.srcPort)
    print ('dst.port:', self.dstPort)
    print ('protocol:', self.protocol)
    print(self.flags)

# !
class UDP(L3):
  name = "UDP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.srcPort = int( listToString( self.hexy[0:2] ).replace(' ', ''), 16 )
    self.dstPort = int( listToString( self.hexy[2:4] ).replace(' ', ''), 16 )

    self.protocol = self.resolveProtocol()

  def resolveProtocol(self):
    protocol = ListOfUDP.get(str(self.dstPort))
    if not protocol:
      protocol = ListOfUDP.get(str(self.srcPort))

    return protocol

  def printAll(self):
    print (self.name)
    # printing ports
    print ('src.port: ', self.srcPort)
    print ('dst.port: ', self.dstPort)
    print ('protocol:', self.protocol) 

# !
class ICMP(L3):
  name = "ICMP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

    self.type = self.resolveType()

  def resolveType(self):
    type = ListOfICMP.get(listToString(self.hexy[0]), 16)
    if type:
      return type  
    return "type not specified in def file"

  def printAll(self):
    print (self.name)
    print (self.type)

# !
class IGMP(L3):
  name = "IGMP"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

  def printAll(self):
    print (self.name)

# !
class PIM(L3):
  name = "PIM"

  def __init__(self, hexy):
    super().__init__(self.name, hexy)

  def printAll(self):
    print (self.name)


class L4:
  def __init__(self, name, hexy):
    self.name = name
    self.hexy = hexy

  def printAll(self):
    print(self.name)


class Statistics:

  IPSources = {}

  def printStatisctics(self):
    #calculations
    mval = max(self.IPSources.values())
    rad = [[k,v] for k, v in self.IPSources.items() if v == mval]
    
    print('Source IPv4 Addresses:')
    for ip, count in self.IPSources.items():
      print (ip, ":", count)

    for c in rad:
      print(f'Address/es with the largest number of send packets: {c[0]}. Packets amount: {c[1]}.')


class Prepinac:
  ParseFile()

  http: dict[str, str] = {}
  https: dict[str, str] = {}
  telnet: dict[str, str] = {}
  ssh: dict[str, str] = {}
  ftp_control: dict[str, str] = {}
  ftp_data: dict[str, str] = {}


  def __init__(self, protocol, packets):
    if protocol == 'FTP-CONTROL' or protocol == 'FTP-DATA':
      self.protocol = protocol[0:3] + '_' + protocol[4:]
      self.low = self.protocol.lower()
      self.protocol = protocol
    else:
      self.protocol = protocol
      self.low = self.protocol.lower()
    self.packets = packets

  def parsePackets(self):
    
    for index, packet in enumerate(self.packets):
      p = Packet(packet, index+1)
      if p.L3.protocol == self.protocol:
        
        k1 = p.L2.src_ip+':'+str(p.L3.srcPort)+'->'+\
        p.L2.dst_ip+':'+str(p.L3.dstPort)

        k2 = p.L2.dst_ip+':'+str(p.L3.dstPort)+'->'+\
        p.L2.src_ip+':'+str(p.L3.srcPort)
        
        if k1 in eval("Prepinac." + self.low):
          eval("Prepinac." + self.low)[k1].append(p.L3.flags)
        elif k2 in eval("Prepinac." + self.low):
          eval("Prepinac." + self.low)[k2].append(p.L3.flags)
        else:
          eval("Prepinac." + self.low)[k1] = [p.L3.flags]

  def printAll(self):
    pprint(eval("Prepinac." + self.low))

  def define(self, flags):
    shift = -1
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
          
    return correct_fin_sum == (TCPFlags.FIN.value | TCPFlags.ACK.value | TCPFlags.RST.value)
          

class TFTP:
  ParseFile()

  tftp: dict[str, str] = {}
  list_of_tftp_ports: list[str] = []

  def __init__(self, protocol, packets):
    self.protocol = protocol
    self.packets = packets
    

  def parsePackets(self):
    for index, packet in enumerate(self.packets):
      p = Packet(packet, index+1)
      if p.L2 != None and p.L2.name == "IPv4":
        if p.L2.protocol == "UDP":
          if p.L3.protocol == "TFTP":
            self.list_of_tftp_ports.append([p.L2.src_ip, p.L3.srcPort, p.L2.dst_ip])

    for index, packet in enumerate(self.packets):
      p = Packet(packet, index+1)
      if p.L2 != None and p.L2.name == "IPv4":
        if p.L2.protocol == "UDP":
          for ind, a in enumerate(self.list_of_tftp_ports):
            if p.L2.src_ip == a[2] and p.L3.dstPort == a[1]:
              if p.L3.srcPort in self.list_of_tftp_ports[ind]:
                continue 
              self.list_of_tftp_ports[ind].append(p.L3.srcPort)

    for index, packet in enumerate(self.packets):
      p = Packet(packet, index+1)
      if p.L2 != None and p.L2.name == "IPv4":
        if p.L2.protocol == "UDP":
          for a in self.list_of_tftp_ports:
            if (p.L2.src_ip, p.L3.srcPort) == (a[0], a[1]) or (p.L2.src_ip, p.L3.srcPort) == (a[2], a[3]):

              k1 = a[0]+':'+str(a[1])+'->'+a[2]+':'+str(a[3])
              k2 = a[2]+':'+str(a[3])+'->'+a[0]+':'+str(a[1])

              if k1 in self.tftp:
                self.tftp[k1].append(p.frame_number)
              elif k2 in self.tftp:
                self.tftp[k2].append(p.frame_number)
              else:
                self.tftp[k1] = [p.frame_number]

  def printAll(self):
    pprint(self.tftp)

  def printALL(self):
    pprint(self.list_of_tftp_ports)