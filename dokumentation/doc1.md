# ![Icon

Description automatically generated](images/Aspose.Words.756015a3-f724-49d4-9346-b9e8b62e9be3.001.jpeg)
#
#
#
# <a name="content"></a>**Computer and Communication Networks**
`		 `Task 1: Network communication analyzer
#
#
#
#




Made by Vadym Tilihuzov

2022/2023

Instructor - Ing. Lukáš Mastiľak
#
# **Content**
- [Content](#content)
- [Block design (concept) of the solution functionionality and the proposed mechanism for analyzing protocols on different layers.](#xa749fa6c1f507617449555ca1e757840e607404)
  - [Introduction](#introduction)
  - [Capabilities](#capabilities)
  - [Architecture](#architecture)
  - [Output](#output)
- [Implementation](#implementation)
  - [Preprocessing](#preprocessing)
  - [Core processes](#core-processes)
    - [Packet class](#packet-class)
    - [Layers](#layers)
    - [Statistics](#statistics)
  - [Filter communication](#filter-communication)
  - [Output](#output-1)
- [Statistics](#statistics-1)
- [Example of external file structure for specifying protocols to be analyzed.](#x3ef9a6e166cb3d4bdeecf4fdcaa656d6000a72f)
- [The choice of the implementation environment](#x885167568bc49e38b5d51271caf5228726f5bd9)
- [Summary](#summary)
  - [Used libraries](#used-libraries)
  - [Used tools](#used-tools)
  - [Used sources](#used-sources)










-----
# <a name="xa502470d874f75933b334752c2a8c61d3b3770e"></a>**Block design (concept) of the solution functionionality and the proposed mechanism for analyzing protocols on different layers.**
## <a name="introduction"></a>**Introduction**
The main goal of the project is to create a tool for analyzing network protocols on different layers. The tool is designed like wireshark for school PKS (computer and communicative networks) subject. The tool is written in Python 3.11. How to start program is described in the [README.md](C:\Users\vadti\README.md) file.
## <a name="capabilities"></a>**Capabilities**
There are two main capabilities of the tool. The first one is to analyze all pcap file and give ipv4 statistics, the ref: *Wireshark -> Statistics -> IPv4 Statistics -> Source and Destination Addresses*. Second one is to analyze only one protocol.
All output is in yaml format and saved in analyzer/results directory.
## <a name="architecture"></a>**Architecture**
The tool is divided into three main parts:

1. **Preprocessing** - this part is responsible for validation of input arguments, loading my library, reading pcap file and calling the right analyzer.
1. **Core processes** - this part is responsible for creating a list of packets. Each packet is an object of class Packet which contains all information about the packet. Based on the input arguments, the two situations can occur, the first one is to analyze all protocols, the second one is to analyze only one protocol. In the second case, the tool will call one of the analyzers, which will analyze only one protocol.
1. **Output** - this part is responsible for creating yaml output and saving it to the file. In the end will be created an instance of module tcp\_ip.yaml which will create yaml output. Based on diffuculty of output.
## <a name="output"></a>**Output**
The output is in yaml format and saved in analyzer/results directory. The output name is of ("%Y%m%d-%H%M%S") format. If protocol filter is used, the output will specify the protocol name.
# <a name="implementation"></a>**Implementation**
Here is a activity diagram of the tool. It shows how the tool works. And now ill describe each part of the tool.

Activity diagram
## <a name="preprocessing"></a>**Preprocessing**
There are only two things to pay attention to here. The first one is to parse protocols file. That file consists of all protocols which can be analyzed. It have hex or decimal number and name of protocol. My library is responsible for parsing this file, with parse\_file function. And saving all that information.

And last thing are classes of **communications** module. They are blackbox classes that is responsible for analyzing a specified protocol. They are called from main.py file.
## <a name="core-processes"></a>**Core processes**
Lets break Packet class object. Here is a container diagram with flowchart in it, describing how it works.

Packet class
### <a name="packet-class"></a>**Packet class**
**class** Packet {
`    `Layers create();
`    `void print\_all();
`    `dict get\_packet();
}

This class is responsible for creating a packet object. It takes a packet from pcap file and creates a packet object. Each layer has its own abstract class Layer. This class is responsible for creating a layer object. Each layer has its own class. For example, Ethernet class is responsible for creating an object of class Ethernet. This class is also responsible for printing all information about packet and creating a dictionary of packet. This dictionary is used for creating yaml output.
### <a name="layers"></a>**Layers**
**abstract** **class** Layer {
`    `void print\_all();
`    `Union[String,None] resolve\_type(hex);
`    `dict get\_packet();
}

To create next layer, the previous layer must be created. For example, to create IPv4 layer, the Ethernet layer must be created.
So if layer 2 isnt created, the layer 3 cant be created.
### <a name="statistics"></a>**Statistics**
**class** Statistics {
`    `void print\_statistics();
`    `list[dict[str, str]] get\_all\_senders();
`    `list[str] get\_max\_send\_packets\_by();
}

Object type Packet needs a Statistics object. This object is responsible for creating statistics of ipv4. It creates a dict of all senders and count of packets.
## <a name="filter-communication"></a>**Filter communication**
**class** Com {
`    `dict to\_yaml();
}

This is abstract class of all filter communications. In the main.py file is created one of the filter communication class. This class is responsible filtering out packets looking for specified protocol. For example, if the protocol is ARP, the ARPCom class is created. This class is responsible for filtering out packets looking for ARP protocol.

**class** ARPCom extends Com {
`    `**private** void \_parse\_packets();
`    `void print\_result();
`    `dict to\_yaml();
}

Filter Container
## <a name="output-1"></a>**Output**
I have Basic and Advanced output classes. The second one extends the first one. The first one is responsible for creating basic yaml output. For all protocols. It have main logic.

**class** Basic {
`    `dict create\_data\_to\_dump();
`    `void create\_file();
}

Basic class as the next one gets already parsed list of packets. It creates a dictionary and go throw all packets, calles their get\_packet function that returns a dictionary of packet. And then it creates a yaml output.

**class** Advanced extends Basic {
`    `dict create\_data\_to\_dump();
}

The difference between Basic and Advanced class is that the second one gets an instance of Com communication and calls its to\_yaml function. This function returns a dictionary. And then it creates a yaml output.
# <a name="statistics-1"></a>**Statistics**
Its a global class that saves statistics of all packets. All packets saves their information to this class. And then, at the end output class puts this information to the yaml output.
# <a name="x0be0d6805d31c350b1594b0bd1c1aa6854f5559"></a>**Example of external file structure for specifying protocols to be analyzed.**
#ListOfEthernetII
0200 XEROX
0201 PUP
0800 IPv4
...
#ListOfIPv4
01 ICMP
02 IGMP
...

I use that file for parsing protocols. It is in analyzer/protocols/set.txt file. It is parsed by my library.
# <a name="x885167568bc49e38b5d51271caf5228726f5bd9"></a>**The choice of the implementation environment**
I use Python 3.11. I use it because I have experience with it. I use it for school and for my personal projects. I use it for writing scripts and for writing web applications. It also easier to create programs with Py.
# <a name="summary"></a>**Summary**
The idea to create own tool for analyzing network protocols on different layers is very interesting. I have learned a lot of new things. Too bad that only the yaml output that we are forced to do cannot be changed. I would add/change a couple of things there. But I understand that its easier to control and check them for specified schema.
## <a name="used-libraries"></a>**Used libraries**
- **scapy** - for reading pcap file and creating packets
- **argparse** - for parsing input arguments
- **ruamel.yaml** - for creating yaml output
## <a name="used-tools"></a>**Used tools**
- **vscode** - for writing code
- **wireshark** - for testing and debugging
- **git** - for version control
## <a name="used-sources"></a>**Used sources**
- **TFTP Guide** - http://www.tcpipguide.com/free/t\_TFTPDetailedOperationandMessaging-3.htm
- **The Task** - https://github.com/fiit-ba/pks-course/tree/main/202324/assignments/1\_network\_communication\_analyzer
