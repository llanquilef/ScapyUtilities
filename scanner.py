import argparse
from typing import Any
from scapy.all import (
    sr1
)
from scapy.layers.inet import IP, TCP
from dotenv import load_dotenv
from dict import dict_configuration
from logger import setup_logger

load_dotenv()


class Scanner():
    """ SCANNER """
    def __init__(self):
        self.logger = setup_logger()

    def syn_scan(self, dst: str, dport: int):
        """ SYN SCANNER """
        try:
            self.logger.info("Starting Syn Scan")
            scan = sr1(IP(dst=dst)/TCP(dport=dport, flags="S"))
            return scan
        except TypeError as e:
            print(e)

    def parser(self) -> dict[str, Any]:
        """ PARSER TOOL """
        try:
            parser = argparse.ArgumentParser(
                description="SYN Scanner for specific ports"
                )
            parser.add_argument(
                dict_configuration["syn_scan"][1]["command"],
                dict_configuration["syn_scan"][1]["reference"],
                type=dict_configuration["syn_scan"][1]["type"],
                help=dict_configuration["syn_scan"][1]["help"]
                )
            parser.add_argument(
                dict_configuration["syn_scan"][4]["command"],
                dict_configuration["syn_scan"][4]["reference"],
                type=dict_configuration["syn_scan"][4]["type"],
                help=dict_configuration["syn_scan"][4]["help"],
                )
            args = vars(parser.parse_args())
            return args
        except argparse.ArgumentError as e:
            print(e)


def main():
    """ MAIN FUNCTION """
    try:
        scanner = Scanner()
        args = scanner.parser()
        scanner.syn_scan(dst=args.get('dst'),
                         dport=args.get('ports'))
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
