from enum import Enum
from functools import wraps
from inspect import signature
from json import loads

from nftables import Nftables
from zenlib.logging import loggify
from zenlib.util import colorize

from .errors import NFTError, NFTSetItemExists

DUMPSTER_CHAINS = {"input": {"hook": "input", "priority": 10, "chain_type": "filter", "policy": "accept"}}


class ChainTypes(Enum):
    FILTER = "filter"
    NAT = "nat"
    ROUTE = "route"


class ChainOptions(Enum):
    priority = "prio"
    hook = "hook"
    chain_type = "type"
    device = "device"
    policy = "policy"


class SetTypes(Enum):
    IP4 = "ipv4_addr"
    IP6 = "ipv6_addr"
    ETHER = "ether_addr"
    PROTO = "inet_proto"
    PORT = "inet_service"
    MARK = "mark"
    IFNAME = "ifname"


class SetOptions(Enum):
    """type is required"""

    policy = "policy"
    flags = "flags"
    timeout = "timeout"
    comment = "comment"
    elements = "eleme"
    gc_interval = "gc_interval"
    auto_merge = "auto_merge"


class RuleOptions(Enum):
    comment = "comment"
    handle = "handle"


def get_default_args(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        has_table, has_family = False, False
        params = dict(signature(method).parameters)
        params.pop("self")
        # Iterate through args
        for i, arg in enumerate(params):
            if i >= len(args):
                break  # Break if out of arg range
            if not args[i]:
                continue
            match arg:
                case "family":
                    has_family = True
                case "table":
                    has_table = True
                case _:
                    pass

        if not has_table and not kwargs.get("table"):
            kwargs["table"] = self.dumpster_table
        if not has_family and not kwargs.get("family"):
            kwargs["family"] = self.dumpster_family
        return method(self, *args, **kwargs)

    return wrapper


@loggify
class DumpsterRules:
    def __init__(self, dumpster_table="dumpster", dumpster_family="inet", *args, **kwargs):
        self.nft = Nftables()
        self.nft.set_json_output(1)
        self.dumpster_table = dumpster_table
        self.dumpster_family = dumpster_family
        self.init_nftables()

    def init_nftables(self):
        """Initializes the dumpster table and chains"""
        self.add_table()
        for chain_name, chain_args in DUMPSTER_CHAINS.items():
            self.add_chain(chain_name, **chain_args)
        self.add_set("dumpster_blackhole", timeout=15 * 60, comment="15 minute timeout")
        self.add_set("dumpster_blackhole_alt", comment="Blackhole backup")
        self.add_rule(
            [
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": "@dumpster_blackhole",
                    }
                },
                {"counter": None},
                {"log": {"prefix": "Dumpster Blackhole: "}},
                {"drop": None},
            ],
            chain_name="input",
            comment="Blackhole IPs for 15 minutes",
        )

        self.add_rule(
            [
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": "@dumpster_blackhole_alt",
                    }
                },
                {"counter": None},
                {"log": {"prefix": "Dumpster Blackhole: "}},
                {"drop": None},
            ],
            chain_name="input",
            comment="Backup chain for blackhole rotation,",
        )

    @property
    def ruleset(self):
        return self.run_cmd("list ruleset")

    @property
    def tables(self):
        raw_tables = self.run_cmd("list tables")
        tables = {}
        for table in raw_tables:
            data = table["table"]
            if data["family"] not in tables:
                tables[data["family"]] = {}
            tables[data["family"]][data["name"]] = data["handle"]
        return tables

    @property
    def chains(self):
        """Gets all chains for the dumpster table"""
        raw_chains = self.run_cmd(f"list table {self.dumpster_family} {self.dumpster_table}")
        chains = {}
        for chain in raw_chains:
            for item_type, item in chain.items():
                if item_type != "chain":
                    continue
                chains[item["name"]] = {
                    "handle": item["handle"],
                    "type": item.get("type"),
                    "hook": item.get("hook"),
                    "priority": item.get("priority"),
                    "policy": item.get("policy"),
                }
        return chains

    @get_default_args
    def get_rules(self, family=None, table=None, chain=None):
        """Gets rules from the input, output, and forward dumpster chains"""
        chain = chain or "input"
        rules = {}
        for raw_rule in self.run_cmd(f"list chain {family} {table} {chain}"):
            for item_type, item in raw_rule.items():
                if item_type != "rule":
                    continue
                rules[item["handle"]] = item
        return rules

    @get_default_args
    def add_rule(self, expression, table=None, family=None, chain_name=None, **kwargs):
        args = {"family": family, "table": table, "chain": chain_name, "expr": expression}
        for opt_arg in RuleOptions:
            if value := kwargs.pop(opt_arg.name, None):
                args[opt_arg.value] = value
        if kwargs:
            self.logger.warning(f"[{family}:{table}] Unused rule options: {kwargs}")

        for rule in self.get_rules(family, table, chain_name).values():
            # Checks if the match (first arg of the expression) is already in the chain
            if rule["expr"][0] == expression[0]:
                return self.logger.warning(
                    f"[{family}:{table}:{chain_name}] Rule already exists in: {colorize(rule, 'yellow')}"
                )

        self.run_cmd({"nftables": [{"add": {"rule": args}}]})
        self.logger.info(f"[{family}:{table}:{chain_name}] Rule added: {colorize(args, 'green')}")

    def blackhole(self, ip):
        try:
            self.add_to_set("dumpster_blackhole", ip)
            self.logger.info(f"Blackholed IP: {colorize(ip, 'red')}")
        except NFTSetItemExists as e:
            self.logger.info(f"[{colorize(e.expires, 'yellow')}s] Updating blackholed IP: {colorize(ip, 'red')}")
            self.add_to_set("dumpster_blackhole_alt", ip, exist_ok=True)
            self.remove_from_set("dumpster_blackhole", ip)
            self.add_to_set("dumpster_blackhole", ip, timeout=e.expires + 15 * 60)
            self.remove_from_set("dumpster_blackhole_alt", ip)

    @get_default_args
    def remove_from_set(self, set_name, element, table=None, family=None):
        if set_name not in self.get_sets(table, family):
            return self.logger.warning(f"[{family}:{table}] Set does not exist: {colorize(set_name, 'yellow')}")
        self.run_cmd(f"destroy element {family} {table} {set_name} {{{element}}}")
        self.logger.debug(f"[{family}:{table}:{set_name}] Element removed from set: {colorize(element, 'red')}")

    @get_default_args
    def add_to_set(self, set_name, element, table=None, family=None, timeout=None, exist_ok=False):
        set_items = self.get_set_elements(set_name, table, family)
        if element in set_items:
            if exist_ok:
                return self.logger.warning(f"[{family}:{table}:{set_name}] Element already exists in set: {element}")
            raise NFTSetItemExists(set_name, element, set_items[element])
        if timeout:
            if isinstance(timeout, int):
                timeout = f"{timeout}s"
            cmd = f"add element {family} {table} {set_name} {{{element} timeout {timeout}}}"
        else:
            cmd = f"add element {family} {table} {set_name} {{{element}}}"
        self.run_cmd(cmd)
        self.logger.debug(f"[{family}:{table}:{set_name}] Element added to set: {colorize(element, 'green')}")

    @get_default_args
    def get_set_elements(self, set_name, table=None, family=None):
        if set_name not in self.get_sets(table, family):
            return self.logger.warning(f"[{family}:{table}] Set does not exist: {set_name}")
        set_info = self.run_cmd(f"list set {family} {table} {set_name}")[0]["set"]
        if "elem" not in set_info:
            return {}
        elements = {}
        for elem in set_info["elem"]:
            if isinstance(elem, dict):
                for element_type, data in elem.items():
                    if element_type != "elem":
                        self.logger.warning(f"[{family}:{table}:{set_name}] Non-elemnt type found in set: {elem}")
                        continue
                    elements[data["val"]] = data.get("expires")
            else:
                elements[elem] = None
        return elements

    @get_default_args
    def get_sets(self, table=None, family=None):
        raw_sets = self.run_cmd(f"list sets table {family} {table}")
        return [set["set"]["name"] for set in raw_sets]

    @get_default_args
    def add_set(self, set_name, table=None, family=None, **kwargs):
        set_type = SetTypes.__members__[kwargs.get("type", "ip4").upper()].value
        args = {"family": family, "table": table, "name": set_name, "type": set_type}
        for opt_arg in SetOptions:
            if value := kwargs.pop(opt_arg.name, None):
                args[opt_arg.value] = value
        if kwargs:
            self.logger.warning(f"[{family}:{table}] Unused set options: {colorize(kwargs, 'red')}")
        self.run_cmd({"nftables": [{"add": {"set": args}}]})
        self.logger.info(f"[{family}:{table}] Set created: {colorize(set_name, 'green')}")

    @get_default_args
    def add_chain(self, chain_name=None, table=None, family=None, **kwargs):
        kwargs["chain_type"] = ChainTypes.__members__[kwargs.get("type", "filter").upper()].value
        kwargs["priority"] = kwargs.get("priority", 200)
        kwargs["hook"] = kwargs.get("hook", "input")
        kwargs["policy"] = kwargs.get("policy", "accept")
        args = {"family": family, "table": table, "name": chain_name}
        for opt_arg in ChainOptions:
            if value := kwargs.get(opt_arg.name):
                args[opt_arg.value] = value

        if self.chains.get(chain_name):
            return self.logger.warning(f"[{family}:{table}] Chain already exists: {colorize(chain_name, 'yellow')}")

        self.run_cmd({"nftables": [{"add": {"chain": args}}]})
        self.logger.info(f"[{family}:{table}] Chain created: {colorize(chain_name, 'green')}")

    @get_default_args
    def add_table(self, table=None, family=None):
        if self.tables.get(family, {}).get(table):
            return self.logger.warning(f"[{family}] Table already exists: {colorize(table, 'yellow')}")
        self.run_cmd(f"add table {family} {table}")
        self.logger.info(f"[{family}] Table created: {colorize(table, 'green')}")

    def run_cmd(self, cmd):
        if isinstance(cmd, dict):
            if not self.nft.json_validate(cmd):
                raise NFTError(cmd, "Invalid JSON")
            ret, output, err = self.nft.json_cmd(cmd)
        else:
            ret, output, err = self.nft.cmd(cmd)
        if ret != 0:
            raise NFTError(cmd, err)
        if not output:
            return
        return loads(output)["nftables"][1:]
