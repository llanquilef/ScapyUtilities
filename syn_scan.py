import argparse
from dotenv import load_dotenv
from scapy.all import (
    sr
)
from scapy.layers.inet import IP, TCP
from dict import dict_configuration
from logger import setup_logger

load_dotenv()


class Scanner():
    def __init__(self):
        self.logger = setup_logger()
        self.parser_args = argparse.ArgumentParser(
            description="IP Scanner over TCP Protocol"
            )
        self.parser_args.add_argument(
            dict_configuration["scanner"][1]["command"],
            dict_configuration["scanner"][1]["reference"],
            dict_configuration["scanner"][1]["type"],
            dict_configuration["scanner"][1]["help"]
            )
        self.parser_args.add_argument(
            dict_configuration["scanner"][2]["command"],
            dict_configuration["scanner"][2]["reference"],
            dict_configuration["scanner"][2]["type"],
            dict_configuration["scanner"][2]["help"]
            )
        self.args = vars(self.parser_args.parse_args())

    # Scan Range Of Ports
    def scan_range_ports(self):
        """ PORT SCANNER """
        self.logger.info("Scanning....")
        ans, unans = sr(IP(dst=self.args.get("dst"))/TCP(
            sport=666, dport=self.args.get("ports")),
            flags="S"
            )
        self.logger.info("Ports in review: %s", self.args.get("ports"))
        return ans, unans

    def summary(self):
        ans, unans = self.scan_range_ports()
        self.logger.info(
            ans.summary(lambda s, r: r.sprintf("%TCP.flags% \t %TCP.sport%"))
            )

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
    scanner = Scanner()
    scanner.scan_range_ports()


if __name__ == "__main__":
    main()
