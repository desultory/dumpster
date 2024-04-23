#!/usr/bin/env python3

from dumpster import Dumpster
from zenlib.util import get_kwargs
from asyncio import run


if __name__ == '__main__':
    kwargs = get_kwargs(package='dumpster', description="NFTables log parser")

    dumpster = Dumpster(**kwargs)
    run(dumpster.run())

