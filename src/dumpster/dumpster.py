"""
Uses the netfilter module to parse logged packets, acts on them.
"""

__version__ = "0.1.0"

from asyncio import create_task, sleep
from tomllib import load

from zenlib.logging import loggify
from zenlib.util import colorize

from .nft_log_reader import NetfilterLogReader
from .nft_line import NetFilterLogLine
from .dumpster_rules import DumpsterRules
from .dumpster_db import DumpsterDB
from .errors import LogLineExists


@loggify
class Dumpster:
    def __init__(self, config_file="config.toml", *args, **kwargs):
        self.log_readers = {}
        self.load_config(config_file)
        self.db = DumpsterDB(db_path=self.config.get('db_file'), logger=self.logger)
        self.nft = DumpsterRules(logger=self.logger)

    def load_config(self, config):
        with open(config, "rb") as f:
            self.config = load(f)

        for log, path in self.config["log_files"].items():
            self.log_readers[log] = NetfilterLogReader(path, logger=self.logger)

        self.config["db_file"] = self.config.get("db_file", "dumpster.sqlite")

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
            return self.logger.warning(e)
        recent_drops = len(self.db.get_from_ip(log_item.SRC))
        self.logger.info("[%s(%s)] %s:%s -> %s:%s", log_item.log_type.name, colorize(recent_drops, "red"),
                         log_item.SRC, log_item.SPT,
                         log_item.DST, log_item.DPT)
        if log_item.log_type.name != "INBOUND":
            return
        if recent_drops > 2:
            self.nft.blackhole(log_item.SRC)

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
