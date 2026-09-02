import argparse
from scapy.all import (
    sniff
    )
from logger import Logger


class Sniffer():
    def __init__(self):
        pass

    def sniffer(self, ifaces: str,
                count: int, filter: str):
        """ SNIFFER """
        sniffing = sniff(filter=filter, iface=[i for i in ifaces],
                         prn=lambda pkt: pkt.show(), count=count)
        return sniffing

    def parser(self):
        """ PARSER """
        parser = argparse.ArgumentParser(description="Sniffer TCP and UDP for specifics IP's")
        try:
            parser.add_argument("-f", "--filter",
                                type=str,
                                choices=["udp", "tcp", "icmp", "arp"],
                                default="",
                                help="Filter for your report: TCP, UDP, ICMP"
                                )

            parser.add_argument("-i", "--ifaces", type=str, nargs="+",
                                help="Interfaces that you need to scan")

            parser.add_argument("-c", "--count", type=int,
                                help="How many packets you want to review"
                                )
            return parser
        except argparse.ArgumentError as e:
            print(e)

    def dict_parser(self):
        try:
            parser = self.parser()
            args = parser.parse_args()
            return vars(args)
        except Exception as e:
            print(e)


def main():
    """ MAIN FUNCTION """
    logger = Logger()
    logger.get_logger()
    logger.setLevel()
    try:
        sniffer = Sniffer()
        args = sniffer.dict_parser()
        print(args)
        sniffer.sniffer(filter=args.get('filter'),
                        ifaces=args.get('ifaces'),
                        count=args.get('count'),
                        )
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
