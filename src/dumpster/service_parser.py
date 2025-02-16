__version__ = "1.0.0"


from zenlib.logging import loggify


def parse_service_file(service_file="/etc/services"):
    """Parses the service file and returns a dict
    where the key is the protocol port,
    and the value is the service name"""
    services = {}
    with open(service_file, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            line = line.strip()
            if not line:
                continue
            service = line.split()[0]
            port = line.split()[1].split("/")[0]
            protocol = line.split()[1].split("/")[1]
            if protocol not in services:
                services[protocol] = {}
            services[protocol][port] = service.lower()
    return services


@loggify
class ServiceParser:
    SERVICES = {}

    def __init__(self, service_file="/etc/services", *args, **kwargs):
        self.service_file = service_file
        if services := ServiceParser.SERVICES.get(service_file):
            self.services = services
        else:
            self.services = parse_service_file(service_file)
            ServiceParser.SERVICES[service_file] = self.services

    def __str__(self):
        out_str = ""
        for protocol, values in self.services.items():
            for port, service in values.items():
                out_str += f"{service}\t\t{port}/{protocol}\n"
        return out_str
