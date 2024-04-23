"""
Attempts to parse the system service file.
This is typically located at /etc/services
Each line contains the service name, then the port and protocol type like:
    http            80/tcp          www     # WorldWideWeb HTTP
"""

__version__ = "0.0.1"


from zenlib.logging import loggify


@loggify
class ServiceParser:
    def __init__(self, service_file='/etc/services', *args, **kwargs):
        self.service_file = service_file
        self.services = {}
        self.parse_service_file()

    def parse_service_file(self):
        """
        Parses the service file and stores the results in self.services
        where each key is the protocol, which contains another dictionary where the key is the port
        and the value is the service name.
        Service names are all lower case.
        """
        with open(self.service_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                line = line.strip()
                if not line:
                    continue
                service = line.split()[0]
                port = line.split()[1].split('/')[0]
                protocol = line.split()[1].split('/')[1]
                if protocol not in self.services:
                    self.services[protocol] = {}
                self.logger.debug("Adding service: %s %s/%s", service, port, protocol)
                self.services[protocol][port] = service.lower()

    def __str__(self):
        """
        Returns a string representation of the services dict like:
            {service}\t\t{port}/{protocol}
        """
        out_str = ''
        for protocol, values in self.services.items():
            for port, service in values.items():
                out_str += f"{service}\t\t{port}/{protocol}\n"
        return out_str
