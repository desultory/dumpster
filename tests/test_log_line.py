from unittest import TestCase, main

from dumpster import NetFilterLogLine

spam_traffic = "Dec 28 22:16:18 hostname kernel: [2794371.848017] Dropped input traffic: IN=wan OUT= MAC=aa:bb:cc:dd:ee:ff:ff:ee:dd:cc:bb:aa:08:00 SRC=1.2.3.4 DST=4.3.2.1 LEN=48 TOS=0x00 PREC=0x00 TTL=113 ID=1609 DF PROTO=TCP SPT=51004 DPT=37888 WINDOW=64240 RES=0x00 SYN URGP=0 "

def get_processing_time(func):
    from time import time
    def wrapper(*args, **kwargs):
        start = time()
        result = func(*args, **kwargs)
        end = time()
        return result, end - start
    return wrapper

@get_processing_time
def generate_spam(count=100):
    from random import randint, choice, random
    from string import ascii_lowercase
    mac_chars = "0123456789ABCDEF"
    for i in range(count):
        timestamp = f"Dec {randint(1, 31)} {randint(0, 23)}:{randint(0, 59)}:{randint(0, 59)}"
        hostname = ''.join(choice(ascii_lowercase) for _ in range(10))
        uptime = f"[{random()}]"
        log_type = choice(["Dropped", "Accepted", "Forwarded"])
        interfaces = ["eth0", "eth1", "wan", "lan"]
        IN = interfaces.pop(interfaces.index(choice(interfaces)))
        OUT = choice(interfaces)
        MAC = ':'.join(choice(mac_chars) + choice(mac_chars) for _ in range(12)) + ":08:00"
        SRC = f"{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}"
        DST = f"{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}"
        LEN = randint(200, 1500)
        TOS = f"0x{randint(0, 255):02x}"
        PREC = f"0x{randint(0, 255):02x}"
        TTL = randint(64, 128)
        ID = randint(0, 65535)
        PROTO = choice(["TCP", "UDP", "ICMP"])
        SPT = randint(1024, 65535)
        DPT = randint(1024, 65535)
        WINDOW = randint(0, 65535)
        RES = f"0x{randint(0, 255):02x}"
        URGP = randint(0, 255)

        yield f"{timestamp} {hostname} kernel: {uptime} {log_type} traffic: IN={IN} OUT={OUT} MAC={MAC} SRC={SRC} DST={DST} LEN={LEN} TOS={TOS} PREC={PREC} TTL={TTL} ID={ID} PROTO={PROTO} SPT={SPT} DPT={DPT} WINDOW={WINDOW} RES={RES} URGP={URGP} "


class TestLogLine(TestCase):
    def test_basic_line(self):
        log_line = NetFilterLogLine("time host kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:00:00 SRC=")
        self.assertEqual(log_line.IN, "eth0")
        self.assertEqual(log_line.OUT, None)
        self.assertEqual(log_line.log_type.name, "INBOUND")

    def test_random_traffic(self):
        log_line = NetFilterLogLine(spam_traffic)
        self.assertEqual(log_line.IN, "wan")
        self.assertEqual(log_line.OUT, None)
        self.assertEqual(log_line.SRC, "1.2.3.4")
        self.assertEqual(log_line.DST, "4.3.2.1")
        self.assertEqual(log_line.PROTO, "TCP")
        self.assertEqual(log_line.TTL, 113)
        self.assertEqual(log_line.ID, 1609)
        self.assertEqual(log_line.DF, True)
        self.assertEqual(log_line.SYN, True)
        self.assertEqual(log_line.WINDOW, 64240)
        self.assertEqual(log_line.RES, 0)
        self.assertEqual(log_line.PREC, 0)
        self.assertEqual(log_line.TOS, 0)
        self.assertEqual(log_line.SPT, 51004)
        self.assertEqual(log_line.DPT, 37888)
        self.assertEqual(log_line.log_type.name, "INBOUND")
        self.assertEqual(log_line.hostname, "hostname")
        self.assertEqual(log_line.timestamp, "Dec 28 22:16:18")
        self.assertEqual(log_line.log_type.name, "INBOUND")
        self.assertEqual(log_line.log_statement, "[2794371.848017] Dropped input traffic:")

    def test_spam_traffic(self):
        """ This should be able to process 10k lines per second"""
        count = 10000
        spam_lines, runtime = generate_spam(count)
        lines, runtime = get_processing_time(lambda: [NetFilterLogLine(line) for line in spam_lines])()
        time_per_line = runtime / count
        print("Took", time_per_line, "seconds per line")
        self.assertLess(time_per_line, 0.0001, "Took too long to process a single line: " + str(time_per_line))

if __name__ == '__main__':
    main()
