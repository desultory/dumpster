#!/usr/bin/env python3

from dumpster import Dumpster
import logging


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(20)

    dumpster = Dumpster()
    try:
        dumpster.cmdloop()
    except KeyboardInterrupt:
        dumpster.do_stop('')
        logger.info('Dumpster stopped')
