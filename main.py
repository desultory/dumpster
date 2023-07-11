#!/usr/bin/env python3

from dumpster import NetfilterLogReader
import logging
from time import sleep


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(20)

    reader = NetfilterLogReader(logger=logger)
    reader.start_watch_thread()
    try:
        while True:
            if not reader.log_items.empty():
                print(reader.log_items.get())
            else:
                sleep(0.5)
    except KeyboardInterrupt:
        reader.stop_watch_thread()
        exit(0)
