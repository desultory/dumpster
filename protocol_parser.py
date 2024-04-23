"""
Attempts to parse the system protocols file.
This is typically located at /etc/protocols.
Each line contains the protocol name, protocol number, and protocol aliases separated by whitespace.
"""

__version__ = "1.0.0"

from zenlib.logging import loggify


@loggify
class ProtocolParser:
    def __init__(self, protocols_file='/etc/protocols', *args, **kwargs):
        self.protocols_file = protocols_file
        self.protocols = {}
        self.parse_protocols_file()

    def parse_protocols_file(self):
        """ Parses the protocols file and stores the results in the self.protocols dict.
        The dict keys are the protocol numbers, and the values are the protocol aliases. """
        with open(self.protocols_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                line = line.strip()
                if not line:
                    continue
                protocol_name = line.split()[0]
                protocol_number = line.split()[1]
                self.logger.debug("Adding protocol %s with number %s", protocol_name, protocol_number)
                self.protocols[protocol_number] = protocol_name

    def __str__(self):
        out_str = ''
        for protocol_number, protocol_aliases in self.protocols.items():
            out_str += f'{protocol_number}: {protocol_aliases}\n'
        return out_str
