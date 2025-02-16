__version__ = "0.0.3"

from asyncio import Queue, sleep, get_event_loop
from os.path import exists, isfile
from signal import SIGUSR1, signal

from zenlib.logging import loggify

from .nft_line import NetFilterLogLine, BadNFTLineError
from .protocol_parser import ProtocolParser
from .service_parser import ServiceParser


@loggify
class NetfilterLogReader:
    """Reads Netfilter logs, parses into the log_items Queue
    self.protocols is an instance of ProtocolParser which maps protocol numbers to names
    self.services is an instance of ServiceParser which maps port numbers to names

    SIGUSR1 will reload the log file
    """

    def __init__(self, log_file, *args, **kwargs):
        signal(SIGUSR1, self._reload_files)
        self.log_file = log_file
        self.log_items = Queue()
        self.invalid_log_items = Queue()
        self.protocols = ProtocolParser(logger=self.logger).protocols
        self.services = ServiceParser(logger=self.logger).services

    def run(self):
        get_event_loop().run_until_complete(self.watch_log())

    async def watch_log(self):
        """Reads the log file, parses it, and puts it in the queue"""
        if not exists(self.log_file) or not isfile(self.log_file):
            raise FileNotFoundError("Log file does not exist: %s" % self.log_file)

        with open(self.log_file, "r") as f:
            self.logger.info("Watching log file: %s" % f.name)
            while True:
                if line := f.readline():
                    if line.strip() == "":
                        self.logger.debug("Skipping empty line")
                        continue
                    try:
                        log_item = NetFilterLogLine(line, logger=self.logger)
                        await self.log_items.put(log_item)
                        self.logger.debug("Added log line to queue: %s" % log_item)
                    except BadNFTLineError as e:
                        self.logger.error(e)
                        await self.invalid_log_items.put(e.line)
                else:
                    await sleep(0.1)
        self.logger.info("Closed log file: %s" % self.og_file)

    def _reload_files(self, *args, **kwargs):
        """Reloads watched log files"""
        self.logger.info("Detected reload signal, reloading config file")
