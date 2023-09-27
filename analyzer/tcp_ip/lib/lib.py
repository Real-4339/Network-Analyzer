import logging
import os.path


''' Global variables '''
LOGGER = logging.getLogger('Library')

''' Ethernet II '''
ListOfEthernetII: dict[str, str] = {}

''' LLC & SNAP '''
ListOfPIDs: dict[str, str] = {}

''' LLC '''
ListOfSaps: dict[str, str] = {}

ListOfIPv4: dict[str, str] = {}

ListOfUDP: dict[str, str] = {}

ListOfTCP: dict[str, str] = {}

ListOfICMP: dict[str, str] = {}


def parse_file(project_root: str) -> None:
    names = ['ListOfEthernetII', 'ListOfPIDs',
           'ListOfSaps', 'ListOfIPv4', 'ListOfUDP',
           'ListOfTCP', 'ListOfICMP']
    
    file_path = os.path.join(project_root, 'protocols', 'set.txt')
    
    try:
        with open(file_path, 'r') as file:
            name = ''
            for line in file:
                if line.startswith('#'):
                    name = line[1:].strip()
                    continue

                if name in names:
                    globals()[name][line.split()[0]] = ' '.join(line.split()[1:])
                else:
                    LOGGER.error(f'Unknown name: {name}')
                    continue
    except FileNotFoundError:
        LOGGER.error(f'File not found: {file_path}')
        return
    except Exception as e:
        LOGGER.error(f'Error: {e}')
        return
    finally:
        file.close()