#!/usr/bin/env python3

from . import Dumpster
from zenlib.util import get_kwargs
from asyncio import run


def main():
    args = [{"flags": ["config_file"], "help": "Path to the configuration file"}]
    kwargs = get_kwargs(package='dumpster', description="NFTables log parser", arguments=args)
    dumpster = Dumpster(**kwargs)
    run(dumpster.run())

if __name__ == '__main__':
    main()

