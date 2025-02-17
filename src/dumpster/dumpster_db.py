from sqlite3 import connect
from time import time
from asyncio import Event

from zenlib.logging import loggify

from .errors import LogLineExists


@loggify
class DumpsterDB:
    def __init__(self, db_path, *args, **kwargs):
        self.db_path = db_path
        self.conn = connect(db_path)
        self.uncommitted_writes = Event()
        self.cursor = self.conn.cursor()
        self.logger.info(f"Opened database: {self.db_path}")
        self.create_table()

    def create_table(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dumpster (
                id TEXT PRIMARY KEY,
                hostname TEXT,
                in_dev TEXT,
                out_dev TEXT,
                src TEXT,
                src_mac TEXT,
                dst TEXT,
                dst_mac TEXT,
                spt INTEGER,
                dpt INTEGER,
                direction TEXT,
                timestamp TEXT,
                line TEXT
            );
            """
        )
        self.cursor.execute("CREATE TABLE IF NOT EXISTS invalid (logline TEXT PRIMARY KEY, time TEXT);")
        self.conn.commit()

    def get_from_ip(self, ip, max_age=300):
        """ Returns all loglines that have the given IP as the source """
        current_time = time()
        return self.cursor.execute("SELECT * FROM dumpster WHERE src = ? AND timestamp > ?;", (ip, current_time - max_age)).fetchall()

    def insert_invalid(self, logline):
        self.logger.debug(f"Adding invalid logline to database:\n{logline}")
        self.cursor.execute("INSERT INTO invalid VALUES (?, ?);", (str(logline), time()))
        self.uncommitted_writes.set()

    def insert_logline(self, logline):
        """Checks that the hash doesn't already exist in the database before inserting"""
        self.logger.log(5, f"Checking if hash exists in database: {logline.hash}")
        if self.cursor.execute("SELECT * FROM dumpster WHERE id = ?;", (logline.hash,)).fetchone():
            raise LogLineExists(f"Hash already exists in the database: {logline.hash}")

        self.logger.debug(f"Adding logline to database:\n{logline}")
        self.cursor.execute(
            "INSERT INTO dumpster VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                logline.hash,
                logline.hostname,
                logline.IN,
                logline.OUT,
                logline.SRC,
                str(logline.src_mac),
                logline.DST,
                str(logline.dst_mac),
                logline.SPT,
                logline.DPT,
                logline.log_type.value,
                logline.timestamp,
                logline.line,
            ),
        )
        self.uncommitted_writes.set()

    def commit(self):
        self.logger.debug(f"[{self.db_path}] Committing changes to database.")
        self.conn.commit()
        self.uncommitted_writes.clear()

    def close(self):
        self.commit()
        self.conn.close()
        self.logger.info(f"Closed connection to {self.db_path}")
