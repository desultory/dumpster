#!/usr/bin/env python3

from dumpster import Dumpster
import logging


if __name__ == '__main__':
    logger = logging.getLogger()
    logfile_handler = logging.FileHandler('dumpster.log')
    logfile_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)-42s | %(message)s'))
    logger.addHandler(logfile_handler)
    logger.setLevel(logging.DEBUG)

    dumpster = Dumpster(logger=logger)
    dumpster.run()

