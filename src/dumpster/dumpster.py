"""
Uses the netfilter module to parse logged packets, acts on them.
"""

__version__ = "0.1.0"

from asyncio import Event, create_task, sleep
from tomllib import load

from zenlib.logging import loggify
from zenlib.util import colorize

from .dumpster_db import DumpsterDB
from .dumpster_rules import DumpsterRules
from .errors import LogLineExists
from .nft_line import NetFilterLogLine
from .nft_log_reader import NetfilterLogReader

DEFAULT_REPEAT_PERIOD = 300  # track blocked IPs for 5 minutes
DEFAULT_REPEAT_COUNT = 3  # block IPs that have been blocked 3 times in the repeat period
DEFAULT_TIMEOUT = 900  # block IPs for 15 minutes
DEFAULT_BAD_IP_THRESHOLD = 25  # block IPs that have been blocked 25 times in the repeat period
DEFAULT_SCAN_DIRECTIONS = ["INBOUND"]


@loggify
class Dumpster:
    def __init__(
        self,
        config_file="config.toml",
        repeat_period=DEFAULT_REPEAT_PERIOD,
        repeat_count=DEFAULT_REPEAT_COUNT,
        timeout=DEFAULT_TIMEOUT,
        bad_ip_threshold=DEFAULT_BAD_IP_THRESHOLD,
        scan_directions=DEFAULT_SCAN_DIRECTIONS,
        *args,
        **kwargs,
    ):
        self.log_readers = {}
        self.repeat_period = repeat_period
        self.repeat_count = repeat_count
        self.bad_ip_threshold = bad_ip_threshold
        self.timeout = timeout
        self.scan_directions = scan_directions
        self.load_config(config_file)
        self._started = Event()
        self.db = DumpsterDB(db_path=self.config.get("db_file"), logger=self.logger)
        self.nft = DumpsterRules(timeout=self.timeout, logger=self.logger)
        self.nft.block(self.db.get_bad_ips())
        self.logger.info(f"Dumpster initialized: {self}")

    def load_config(self, config):
        with open(config, "rb") as f:
            self.config = load(f)

        for log, path in self.config["log_files"].items():
            self.log_readers[log] = NetfilterLogReader(path, logger=self.logger)

        self.config["db_file"] = self.config.get("db_file", "dumpster.sqlite")

        for attr in ["repeat_period", "repeat_count", "timeout", "scan_directions", "bad_ip_threshold"]:
            if value := self.config.get(attr):
                self.logger.info(f"[{attr}] Setting from config: {value}")
                setattr(self, attr, value)

    async def run(self):
        for log_reader in self.log_readers.values():
            create_task(log_reader.watch_log())
        while True:
            await self.process_log_queue()
            await sleep(0.1)

    async def handle_log_item(self, log_item: NetFilterLogLine):
        self.logger.debug("Handling log item: %s", log_item)
        try:
            self.db.insert_logline(log_item)
        except LogLineExists as e:
            if self._started.is_set():
                return self.logger.warning(e)
            return self.logger.debug(e)
        recent_drops = len(self.db.get_from_ip(log_item.SRC, self.repeat_period))
        self.logger.info(
            "[%s(%s)] %s:%s -> %s:%s",
            log_item.log_type.name,
            colorize(recent_drops, "red"),
            log_item.SRC,
            log_item.SPT,
            log_item.DST,
            log_item.DPT,
        )
        if recent_drops >= self.bad_ip_threshold:
            self.logger.warning("Permanently blocking: %s", colorize(log_item.SRC, "red"))
            self.nft.block(log_item.SRC)
            self.db.insert_bad(log_item.SRC)
        elif self.db.is_timed_out(log_item.SRC):
            # If it's already timed out, and droppped again, extend the timeout
            self.nft.time_out(log_item.SRC, self.timeout)
        elif log_item.log_type.name in self.scan_directions and recent_drops >= self.repeat_count:
            # If it's a new offender, and has been dropped enough times, time it out
            self.nft.time_out(log_item.SRC, self.timeout)
            # Log the first time it's timed out
            self.db.insert_timeout(log_item.SRC)
        else:
            self.logger.debug("Allowing: %s", log_item)

        if not self._started.is_set():
            self._started.set()
            self.logger.info("Processed initial log items.")

    async def process_log_queue(self):
        """Reads the items from all log_reader's log_items queue
        Processes them with handle_log_items until empty."""
        for log_reader in self.log_readers.values():
            while not log_reader.log_items.empty():
                await self.handle_log_item(await log_reader.log_items.get())
            while not log_reader.invalid_log_items.empty():
                self.db.insert_invalid(await log_reader.invalid_log_items.get())
        if self.db.uncommitted_writes.is_set():
            self.db.commit()

    def __str__(self):
        str_args = ["timeout", "repeat_period", "repeat_count", "bad_ip_threshold", "scan_directions"]
        return f"Dumpster({', '.join([f'{arg}={getattr(self, arg)}' for arg in str_args])}, log_readers={', '.join(self.log_readers)}, config={self.config})"
