"""
Uses the netfilter module to parse logged packets,
acts on them.
"""

__version__ = '0.0.2'

from netfilter import NetfilterLogReader
from zen_custom import class_logger
from cmd import Cmd


@class_logger
class Dumpster(Cmd):
    def __init__(self, *args, **kwargs):
        self.log_reader = NetfilterLogReader(logger=self.logger)
        super().__init__(*args, **kwargs)

    def do_start(self, arg):
        """Start the netfilter log reader."""
        self.log_reader.start_watch_thread()

    def do_stop(self, arg):
        """Stop the netfilter log reader."""
        self.log_reader.stop_watch_thread()

    def do_quit(self, arg):
        """Quit the dumpster."""
        return True

    def postloop(self):
        """Clean up the dumpster."""
        if self.log_reader.threads['watch'].is_alive():
            self.log_reader.stop_watch_thread()

    def do_readlog(self, arg):
        """Read the netfilter log."""
        while not self.log_reader.log_items.empty():
            print(self.log_reader.log_items.get())
