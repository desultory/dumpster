class LogLineExists(Exception):
    pass


class NFTError(Exception):
    def __init__(self, cmd, err):
        self.cmd = cmd
        self.err = err

    def __str__(self):
        return f"Error running command: {self.cmd}\n{self.err}"

class NFTSetItemExists(Exception):
    pass
