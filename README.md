# The pcap-network analyzer for PKS

## Prerequisites

LINUX:

- python 3.10+ and python3-pip
```bash
apt install python3 python3-pip
```

- all requirements from requirements.txt
```bash
pip install -r requirements.txt
```

Windows:

https://www.digitalocean.com/community/tutorials/install-python-windows-10

## Usage
Basic read of pcap file.
```bash
python3 analyzer
```

Will be used default pcap file, trace_ip_nad_20_B.pcap.
All pcap files are stored in samples directory.

You can specify the pcap file using the command option -f/--file.
Without extension
```bash
python3 analyzer -f eth-8
```

You can also filter the pcap based on protocol.
```bash
python3 analyzer -p ARP
```

You can get help.
```bash
python3 analyzer/ -h
```

## Author
[Vadym Tilihuzov](https://github.com/Real-4339), STU FIIT

## License
Distributed under the Apache License 2.0. See `LICENSE` for more information.