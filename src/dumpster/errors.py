from zenlib.util import colorize


class LogLineExists(Exception):
    pass


class NFTError(Exception):
    def __init__(self, cmd, err):
        self.cmd = cmd
        self.err = err

    def __str__(self):
        return f"Error running command: {self.cmd}\n{self.err}"

class NFTSetItemExists(Exception):
    def __init__(self, set_name, item, expires=0):
        self.set_name = set_name
        self.item = item
        self.expires = expires

    def __str__(self):
        return f"[{self.set_name}] item already exists: {colorize(self.item, "yellow")}"
