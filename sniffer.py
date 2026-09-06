""" SNIFFER """
import sys
import argparse
from dict import dict_configuration
from scapy.all import (
    sniff
    )
from logger import Logger


class Sniffer():
    """ SNIFFER """
    def __init__(self):
        pass

    def sniffer(self, ifaces: str, count: int, filter: str):
        """ SNIFFER """
        sniffing = sniff(filter=filter, iface=ifaces,
                         prn=lambda pkt: pkt.show(), count=count)
        return sniffing

    def parser(self):
        """ PARSER """
        parser = argparse.ArgumentParser(
            description="Sniffer TCP and UDP for specifics IP's"
            )
        try:
            parser.add_argument(
                dict_configuration["sniffer"][1]["command"],
                dict_configuration["sniffer"][1]["reference"],
                type=dict_configuration["sniffer"][1]["type"],
                choices=dict_configuration["sniffer"][1]["choices"],
                default=dict_configuration["sniffer"][1]["default"],
                help=dict_configuration["sniffer"][1]["help"]
                )

            parser.add_argument(
                dict_configuration["sniffer"][2]["command"],
                dict_configuration["sniffer"][2]["reference"],
                type=str,
                nargs="+",
                help="Interfaces that you need to scan")

            parser.add_argument(
                dict_configuration["sniffer"][3]["command"], 
                dict_configuration["sniffer"][3]["reference"],
                type=dict_configuration["sniffer"][3]["type"],
                help=dict_configuration["sniffer"][3]["help"])

            args = parser.parse_args()
            return vars(args)

        except argparse.ArgumentError as e:
            print(e)
            sys.exit(1)


def main():
    """ MAIN FUNCTION """
    logger = Logger()
    logger.get_logger()
    logger.setLevel()
    try:
        sniffer = Sniffer()
        args = sniffer.parser()
        sniffer.sniffer(filter=args.get('filter'),
                        ifaces=args.get('ifaces'),
                        count=args.get('count'),
                        )
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
