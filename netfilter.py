"""
Dumpster reads netfilter logs, parses them, and then acts on them.

"""

__version__ = "0.0.3"

from zen_custom import class_logger, threaded, thread_wrapped, add_thread
from queue import Queue
from signal import signal, SIGUSR1
from time import sleep
from os.path import isfile, exists
from protocol_parser import ProtocolParser
from service_parser import ServiceParser

import tomllib
import re


@class_logger
class NetFilterLogLine:
    """Parses a Netfilter log line"""
    NF_Parameters = {'IN': 'Input interface',
                     'OUT': 'Output interface',
                     'MAC': 'MAC addresses',
                     'SRC': 'Source IP address',
                     'DST': 'Destination IP address',
                     'L3_LEN': 'Length of packet',
                     'TOS': 'Type of service',
                     'PREC': 'Precedence',
                     'TTL': 'Time to live',
                     'ID': 'Identification',
                     'PROTO': 'Protocol',
                     'SPT': 'Source port',
                     'DPT': 'Destination port',
                     'L4_LEN': 'Length of layer 4 portion'}

    NF_Flags = {'ACK': 'TCP Acknowledgement',
                'FIN': 'TCP Finish',
                'SYN': 'TCP Synchronize',
                'RST': 'TCP Reset',
                'PSH': 'TCP Push',
                'URG': 'TCP Urgent',
                'ECE': 'TCP ECN-Echo',
                'ECT': 'TCP ECN-Capable Transport',
                'CWR': 'TCP Congestion Window Reduced',
                'CE': 'TCP Congestion Experienced',
                'DF': "Don't fragment",
                }

    _MAC_special = {'multicast': '01:00:5e'}

    def __init__(self, line, protocols=None, services=None, aliases=None, *args, **kwargs):
        if not protocols:
            protocols = ProtocolParser(logger=self.logger).protocols
        self.protocols = protocols
        if not services:
            services = ProtocolParser(logger=self.logger).services
        self.services = services

        self.raw_line = line.strip()
        self.aliases = aliases
        self.log_type = "forward"  # Default to forward
        self.parse_line()

    def parse_line(self):
        """Parses the raw line"""
        self.logger.debug("Parsing line: %s" % self.raw_line)
        # Start by splitting the line using the "IN=" portion
        if ' IN=' not in self.raw_line:
            raise ValueError("Unable to process line as a netfilter line, missing 'IN=': %s" % self.raw_line)

        pre_in = self.raw_line.split("IN=")[0]
        self._parse_pre_in(pre_in)

        self.parse_flags()

        # Parse the packet based on the parameters
        for param in self.NF_Parameters.keys():
            # Don't parse length here
            if "_LEN" in param:
                continue
            # Search for the parameter by looking for " {param}={value} "
            re_pattern = r' %s=([\S]+)\s?' % param
            match = re.search(re_pattern, self.raw_line)
            if match:
                if param == 'MAC':
                    self._parse_mac(match.group(1))
                if param == 'PROTO':
                    # Check if the protocol is a number
                    if match.group(1).isdigit():
                        self.PROTO = self.protocols[match.group(1)]
                    else:
                        self.PROTO = match.group(1)
                else:
                    setattr(self, param, match.group(1))
            else:
                if param == 'IN':
                    self.logger.debug("Input parameter not found, setting type to 'outbound'")
                    self.log_type = 'outbound'
                elif param == 'OUT':
                    self.logger.debug("Output parameter not found, setting type to 'inbound'")
                    self.log_type = 'inbound'
                elif param in ('SPT', 'DPT'):
                    if self.PROTO in ('TCP', 'UDP'):
                        raise ValueError("Port is unset when it should be set: %s" % self.raw_line)
                    else:
                        self.logger.debug("Port is missing but protocol is not TCP or UDP, setting to '0'")
                        setattr(self, param, '0')
                else:
                    self.logger.warning("Unable to find parameter: %s" % param)
                    setattr(self, param, None)

    def parse_flags(self):
        """
        Parses netfilter flags from self.raw_line
        """
        self.logger.debug("Parsing flags: %s" % self.raw_line)
        for flag in self.NF_Flags.keys():
            flag_re = r'\s%s[\s|$]' % flag
            if re.search(flag_re, self.raw_line):
                setattr(self, flag, True)
            else:
                setattr(self, flag, False)

    def _parse_mac(self, mac):
        """
        Parses the MAC address based on how nftables logs it
        SRCMAC:DSTMAC:TYPE
        ex. AA:BB:CC:DD:EE:FF:AA:BB:CC:DD:EE:FF:08:00
        08:00 = ipv4
        """
        self.logger.debug("Parsing MAC address: %s" % mac)
        src_re = r'[0-9a-fA-F:]{18}([a-fA-F0-9]{2}(?:\:[a-fA-F0-9]{2}){5})'
        dst_re = r'([a-fA-F0-9]{2}(?:\:[a-fA-F0-9]{2}){5})'

        self.SRC_MAC = re.search(src_re, mac).group(1)
        self.DST_MAC = re.search(dst_re, mac).group(1)

    def _parse_pre_in(self, pre_in):
        """Parses the pre-IN portion of the line"""
        self.logger.debug("Parsing pre-IN portion: %s" % pre_in)

        # Split the pre-in portion around the 'kernel:' portion
        front, back = pre_in.split(" kernel: ")
        self.log_statement = back.strip()

        # The hostname should be the last portion of the front
        hostname = front.split(" ")[-1]
        self.hostname = hostname.strip()

        # Get the timestamp by removing the hostname from the front
        self.timestamp = front.replace(hostname, "").strip()

    def _display_mac(self, mac):
        """
        Formats a MAC address to be diplayed.
        Special mac types such as multicast take precedence over aliases.
        """
        # If the MAC is a multicast, then return the special string
        for name, prefix in self._MAC_special.items():
            if mac.startswith(prefix):
                return f"{name}{mac.replace(prefix,'').replace(':00', '')}"

        if mac in self.aliases.get('mac_name').keys():
            return f"@{self.aliases.get('mac_name').get(mac)}"

        return mac

    def _display_ip(self, ip):
        """
        Formats an IP address to be displayed.
        If an alias exists, displays that alias with a @ in front of it.
        """
        if ip in self.aliases.get('ip_name').keys():
            return f"@{self.aliases.get('ip_name').get(ip)}"

        return ip

    def _display_port(self, port, proto):
        """
        Formats a port to be displayed.
        If a service defintion exists, displays that service with a @ in front of it.
        """
        proto = proto.lower()
        if proto in self.services and port in self.services[proto]:
            return f"@{self.services[proto][port]}"
        return port

    def __str__(self):
        """ Returns a string representation of the object"""
        log_type = f"<{self.log_type}>".ljust(10, ' ')
        src_mac_alias = self._display_mac(self.SRC_MAC)
        src_ip_alias = self._display_ip(self.SRC)
        src_port_alias = self._display_port(self.SPT, self.PROTO)
        src_str = f"({src_mac_alias}) {src_ip_alias}:{src_port_alias} ".ljust(46, ' ')

        proto_str = f"-{self.PROTO}->".ljust(8, ' ')

        dst_mac_alias = self._display_mac(self.DST_MAC)
        dst_ip_alias = self._display_ip(self.DST)
        dst_port_alias = self._display_port(self.DPT, self.PROTO)
        dst_str = f"({dst_mac_alias}) {dst_ip_alias}:{dst_port_alias} ".ljust(46, ' ')

        flags = ""

        for flag in self.NF_Flags.keys():
            if getattr(self, flag):
                flags += f"{self.NF_Flags[flag]}, "
        flags = flags.rstrip(" ,")

        return f"[{self.timestamp}] {log_type} {self.hostname}: {src_str} {proto_str} {dst_str} <{flags}>"


@add_thread('watch', 'watch_logs', 'Thread for reading the log file')
@class_logger
class NetfilterLogReader:
    """Reads Netfilter logs, parses into a Queue"""
    def __init__(self, config_file='config.toml', *args, **kwargs):
        signal(SIGUSR1, self._reload_files)
        self.config_file = config_file
        self.read_config()
        # Get the protocol config from the protocol file
        self.protocols = ProtocolParser(self.config['source_files'].get('protocol_file'), logger=self.logger).protocols
        # Get the service config from the service file
        self.services = ServiceParser(self.config['source_files'].get('service_file'), logger=self.logger).services

        self.log_items = Queue()

    def read_config(self):
        """
        Reads the config file.
        """
        self.logger.info("Reading config file: %s" % self.config_file)
        with open(self.config_file, 'rb') as f:
            self.config = tomllib.load(f)
        self.log_files = self.config['log_files']

    @thread_wrapped('watch')
    def watch_logs(self):
        """Watches the log files"""
        for log_file in self.log_files.values():
            self._watch_log(log_file)

        # Wait for log threads to join before restarting
        for thread, exception in self._threads:
            thread.join()
            while not exception.empty():
                self.logger.error(exception.get())

    @threaded
    def _watch_log(self, log_file):
        """Reads the log file, parses it, and puts it in the queue"""
        if not exists(log_file) or not isfile(log_file):
            self.logger.error("Log file does not exist: %s" % log_file)
            return

        with open(log_file, 'r') as f:
            self.logger.info("Watching log file: %s" % f.name)
            while not self._stop_processing_watch.is_set():
                line = f.readline()
                if line:
                    try:
                        log_item = NetFilterLogLine(line, protocols=self.protocols, services=self.services, aliases=self.config['aliases'], logger=self.logger, _log_init=False)
                        self.log_items.put(log_item)
                        self.logger.debug("Added log line to queue: %s" % log_item)
                    except ValueError as e:
                        self.logger.error(e)
                else:
                    sleep(0.5)
        self.logger.info("Closed log file: %s" % log_file)

    def _reload_files(self, *args, **kwargs):
        """ Reloads watched log files """
        self.logger.info("Detected reload signal, reloading config file")
        self.stop_watch_thread()
        self.start_watch_thread()
