__version__ = "1.0.0"

from zenlib.logging import loggify


def parse_protocols(protocol_file="/etc/protocols"):
    """Parses the protocols file and returns a dict
       where the keys are the protocol numbers,
       values are the protocol names."""
    protocols = {}
    with open(protocol_file, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            line = line.strip()
            if not line:
                continue
            protocol_name = line.split()[0]
            protocol_number = line.split()[1]
            protocols[protocol_number] = protocol_name
    return protocols


@loggify
class ProtocolParser:
    PROTOCOLS = {}

    def __init__(self, protocols_file="/etc/protocols", *args, **kwargs):
        self.protocols_file = protocols_file
        if protocols := ProtocolParser.PROTOCOLS.get(protocols_file):
            self.protocols = protocols
        else:
            self.protocols = parse_protocols(protocols_file)
            ProtocolParser.PROTOCOLS[protocols_file] = self.protocols

    def __str__(self):
        out_str = ""
        for protocol_number, protocol_aliases in self.protocols.items():
            out_str += f"{protocol_number}: {protocol_aliases}\n"
        return out_str
