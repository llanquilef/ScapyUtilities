from dotenv import load_dotenv
from scapy.all import (
    sr
)
from scapy.layers.inet import IP, TCP
from logger import Logger

logger = Logger()
logger.get_logger()
logger.setLevel()
load_dotenv()


class Scanner():
    def __init__(self, dst_addr: str):
        self.dst_addr = dst_addr if dst_addr else None

    # Scan Range Of Ports
    def scan_range_ports(self):
        PORTS = [22, 440, 441, 442, 443, 80]
        ans, unans = sr(IP(dst=self.dst_addr)/TCP(sport=666,
                                                  dport=[p for p in PORTS],
                                                  flags="S"
                                                  ))
        return ans, unans

    def summary(self):
        ans, unans = self.scan_range_ports()
        print(ans.summary(lambda s, r: r.sprintf("%TCP.flags% \t %TCP.sport%")))

    def summary_flags(self):
        ans, unans = self.scan_range_ports()
        election = input("""
        What flags do you need to see: \n"
        ****** RA type: RA ****** \n
        ****** SA type: SA ******
        """)
        if election == 'RA':
            print(ans.summary(lfilter=lambda s, f:
                              f.sprintf("%TCP.flags%") == "RA",
                              ))
        elif election == 'SA':
            print(ans.summary(lfilter=lambda s, f:
                              f.sprintf("%TCP.flags%") == "SA"))
        else:
            print("Invalid option")


def main():
    try:
        SCANNER = Scanner(dst_addr="192.168.1.1")
        options: dict = {
            1: SCANNER.scan_range_ports,
            2: SCANNER.summary,
            3: SCANNER.summary_flags
        }
        for option, function in options.items():
            if function:
                function()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
