__version__ = "1.0.0"
from datetime import datetime
from enum import Enum
from hashlib import sha256
from re import findall, search
from types import new_class

from zenlib.types import validatedDataclass


class BadNFTLineError(Exception):
    def __init__(self, line, message="Invalid Netfilter line"):
        self.line = line
        self.message = message

    def __str__(self):
        return f"{self.message}: {self.line}"


class NF_FLAGS(Enum):
    ACK = "TCP Acknowledgement"
    FIN = "TCP Finish"
    SYN = "TCP Synchronize"
    RST = "TCP Reset"
    PSH = "TCP Push"
    URG = "TCP Urgent"
    ECE = "TCP ECN-Echo"
    ECT = "TCP ECN-Capable Transport"
    CWR = "TCP Congestion Window Reduced"
    CE = "TCP Congestion Experienced"
    DF = "Don't fragment"


class NF_STRS(Enum):
    IN = "Input interface"
    OUT = "Output interface"
    MAC = "MAC addresses"
    SRC = "Source IP address"
    DST = "Destination IP address"
    PROTO = "Protocol"


class NF_INTS(Enum):
    L3_LEN = "Length of packet"
    TOS = "Type of service"
    PREC = "Precedence"
    TTL = "Time to live"
    ID = "Identification"
    SPT = "Source port"
    DPT = "Destination port"
    L4_LEN = "Length of layer 4 portion"
    WINDOW = "TCP Window size"
    RES = "Reserved bits"


class LogType(Enum):
    FORWARD = "forward"
    INBOUND = "inbound"
    OUTBOUND = "outbound"


def make_netfilter_base():
    """Creates a base class for Netfilter flags"""
    nft_bools = {flag: False for flag in NF_FLAGS.__members__}
    nft_strs = {param: None for param in NF_STRS.__members__}
    nft_ints = {param: None for param in NF_INTS.__members__}

    nft_attrs = nft_bools | nft_strs | nft_ints

    def exec_body_callback(ns):
        ns.update(nft_attrs)
        ns["__annotations__"] = {k: bool for k in nft_bools}
        ns["__annotations__"] |= {k: str for k in nft_strs}
        ns["__annotations__"] |= {k: int for k in nft_ints}

    return new_class("NetFilterBaseMixin", exec_body=exec_body_callback)


NetFilterBaseMixin = make_netfilter_base()


def get_flags(raw_line):
    for flag in NF_FLAGS.__members__:
        flag_re = r"\s%s[\s|$]" % flag
        if search(flag_re, raw_line):
            yield flag


def get_parameters(raw_line):
    for param in NF_INTS.__members__ | NF_STRS.__members__:
        if "_LEN" in param:
            continue  # Length parameters are parsed separately
        re_pattern = r" %s=([\S]+)\s?" % param
        if s := search(re_pattern, raw_line):
            match = s.group(1)
            if match is None:
                yield param, None
            elif match.startswith("0x"):
                yield param, int(match, 16)
            else:
                yield param, match


class MacAddress:
    @staticmethod
    def from_logline(mac_section):
        nft_line_mac_re = r"([a-fA-F0-9]{2}(?:\:[a-fA-F0-9]{2}){5})"
        macs = findall(nft_line_mac_re, mac_section)
        if len(macs) == 2:
            return tuple(MacAddress(mac) for mac in macs)
        raise ValueError("Unable to parse MAC addresses: %s" % mac_section)

    def __init__(self, mac):
        self.mac = mac

    @property
    def mac(self):
        return self._mac

    @mac.setter
    def mac(self, mac):
        """Match macs with or without separators"""
        mac_re = r"^(?:[0-9A-Fa-f]{2}[:-]?){5}[0-9A-Fa-f]{2}$"
        if not search(mac_re, mac):
            raise ValueError("Invalid MAC address: %s" % mac)
        self._mac = mac

    def __str__(self):
        return str(self.mac)

    def __repr__(self):
        return f"MacAddress({self.mac})"


@validatedDataclass
class NetFilterLogLine(NetFilterBaseMixin):
    line: str
    log_type: LogType = LogType.FORWARD
    log_statement: str = None  # The portion of the line before the packet information
    hostname: str = None
    _timestamp: str = None
    src_mac: MacAddress = None
    dst_mac: MacAddress = None
    _mac: str = None


    @property
    def timestamp(self) -> str:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, ts):
        try:
            self._timestamp = int(ts)
        except ValueError:
            current_year = datetime.now().year
            self._timestamp = int(datetime.strptime(f"{current_year} {ts}", "%Y %b %d %H:%M:%S").timestamp())

    @property
    def MAC(self) -> str:
        return self._mac

    @MAC.setter
    def MAC(self, macs):
        self.src_mac, self.dst_mac = MacAddress.from_logline(macs)
        self._mac = macs

    @property
    def hash(self):
        return sha256(self.line.encode()).hexdigest()

    def __post_init__(self):
        """Parses the raw line"""
        self.line = self.line.strip()
        self.logger.debug("Parsing line: %s" % self.line)
        # Start by splitting the line using the "IN=" portion
        if " IN=" not in self.line:
            raise BadNFTLineError(self.line, "Unable to process line as a netfilter line, missing ' IN='")

        self.parse_pre_in()

        for flag in get_flags(self.line):
            setattr(self, flag, True)

        for param, value in get_parameters(self.line):
            setattr(self, param, value)

        for param in ["src_mac", "dst_mac", ("IN", "OUT")]:
            if isinstance(param, tuple):
                if not any([getattr(self, p) for p in param]):
                    raise BadNFTLineError(self.line, "Log line missing required parameter: %s" % param)
            elif not getattr(self, param):
                raise BadNFTLineError(self.line, "Log line missing required parameter: %s" % param)

        if self.IN == self.OUT:
            raise BadNFTLineError(self.line, "IN and OUT interfaces are the same")

        if getattr(self, "IN") and not getattr(self, "OUT"):
            self.log_type = LogType.INBOUND
        elif getattr(self, "OUT") and not getattr(self, "IN"):
            self.log_type = LogType.OUTBOUND

    def parse_pre_in(self):
        """Parses the pre-IN portion of the line"""
        pre_in = self.line.split("IN=")[0]
        if " kernel: " not in pre_in:
            raise BadNFTLineError(self.line, "Unable to parse pre-IN portion, missing ' kernel: '")

        # Split the pre-in portion around the 'kernel:' portion
        front, back = pre_in.split(" kernel: ")
        self.log_statement = back.strip()

        # The hostname should be the last portion of the front
        hostname = front.split(" ")[-1]
        self.hostname = hostname.strip()

        # Get the timestamp by removing the hostname from the front
        self.timestamp = front.replace(hostname, "").strip()
