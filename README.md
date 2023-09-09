# The validator for PKS network analyzer

## Getting started

Simple tool for validation of the correct YAML syntax output from the network analyzer.

## Prerequisites

LINUX:

- python 3.6+ and python3-pip
```bash
apt install python3 python3-pip
```

- Before starting, install all independecies.
```bash
pip install -r requirements.txt
```

Windows:

https://www.digitalocean.com/community/tutorials/install-python-windows-10

## Usage

You can get help.
```bash
python3 analyzer -h
```

You can use default schema and output.
```bash
python3 analyzer
```

You can specify the schema using the command option -s/--schema.
```bash
python3 analyzer -s ~/fiit/pks/schemas/schema.yaml
```

You can specify the yaml output using the command -d/--data.
```bash
python3 analyzer -s ~/fiit/pks/data/pks-task1.yaml -d PKS_.yaml
```

## Authors
Vadym Tilihuzov, STU FIIT

## Acknowledgment
[Kristian Kostal](https://scholar.google.sk/citations?user=6b4HfA4AAAAJ&hl=sk), STU FIIT

[Pavol Helebrandt](https://scholar.google.sk/citations?user=xdloWxEAAAAJ&hl=en), STU FIIT

## License
Distributed under the Apache License 2.0. See `LICENSE` for more information.