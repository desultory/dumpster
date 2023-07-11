"""
Attempts to parse the system protocols file.
This is typically located at /etc/protocols.
Each line contains the protocol name, protocol number, and protocol aliases separated by whitespace.
"""

from zen_custom import class_logger


@class_logger
class ProtocolParser:
    def __init__(self, protocols_file='/etc/protocols', *args, **kwargs):
        self.protocols_file = protocols_file
        self.protocols = {}
        self.parse_protocols_file()

    def parse_protocols_file(self):
        """
        Parses the protocols file and stores the results in a dictionary
        where each key is the protocol number, and the value is the protocol alias
        """
        with open(self.protocols_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                line = line.strip()
                if not line:
                    continue
                protocol_name = line.split()[0]
                protocol_number = line.split()[1]
                self.protocols[protocol_number] = protocol_name

    def __str__(self):
        """
        Outputs the protocols dictionary as a string, formatted like:
            Protocol number: protocol alias
        """
        out_str = ''
        for protocol_number, protocol_aliases in self.protocols.items():
            out_str += f'{protocol_number}: {protocol_aliases}\n'
        return out_str
