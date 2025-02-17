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
DEFAULT_BLACKHOLE_TIMEOUT = 900  # block IPs for 15 minutes


@loggify
class Dumpster:
    def __init__(
        self,
        config_file="config.toml",
        repeat_period=DEFAULT_REPEAT_PERIOD,
        repeat_count=DEFAULT_REPEAT_COUNT,
        blackhole_timeout=DEFAULT_BLACKHOLE_TIMEOUT,
        *args,
        **kwargs,
    ):
        self.log_readers = {}
        self.repeat_period = repeat_period
        self.repeat_count = repeat_count
        self.blackhole_timeout = blackhole_timeout
        self.load_config(config_file)
        self._started = Event()
        self.db = DumpsterDB(db_path=self.config.get("db_file"), logger=self.logger)
        self.nft = DumpsterRules(blackhole_timeout=self.blackhole_timeout, logger=self.logger)
        self.logger.info(f"Dumpster initialized: {self}")

    def load_config(self, config):
        with open(config, "rb") as f:
            self.config = load(f)

        for log, path in self.config["log_files"].items():
            self.log_readers[log] = NetfilterLogReader(path, logger=self.logger)

        self.config["db_file"] = self.config.get("db_file", "dumpster.sqlite")

        if repeat_period := self.config.get("repeat_period"):
            self.repeat_period = repeat_period
        if repeat_count := self.config.get("repeat_count"):
            self.repeat_count = repeat_count
        if blackhole_timeout := self.config.get("blackhole_timeout"):
            self.blackhole_timeout = blackhole_timeout

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
        if log_item.log_type.name != "INBOUND":
            return
        if self.db.is_blackholed(log_item.SRC):
            # If it's already blackholed, and droppped again, extend the timeout
            self.nft.blackhole(log_item.SRC, self.blackhole_timeout)
        elif recent_drops >= self.repeat_count:
            # If it's a new offender, and has been dropped enough times, blackhole it
            self.nft.blackhole(log_item.SRC, self.blackhole_timeout)
            self.db.insert_blackhole(log_item.SRC)

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
        return f"Dumpster(blackhole_timeout={self.blackhole_timeout}, repeat_period={self.repeat_period}, repeat_count={self.repeat_count}, log_readers={', '.join(self.log_readers)}, config={self.config})"
