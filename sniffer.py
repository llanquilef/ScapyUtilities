""" SNIFFER """
import sys
import logging
import argparse
from dict import dict_configuration
from scapy.all import (
    sniff
    )


class Sniffer():
    """ SNIFFER """
    def __init__(self):
        self.logger = logging.getLogger(__class__.__name__)
        formatter = logging.Formatter("""
                                      %(asctime)s - %(levelname)s - %(message)s - %(processName)s
                                      """)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def sniffer(self, ifaces: str, count: int, filter: str):
        """ SNIFFER """
        self.logger.info("Sniffing...")
        sniffing = sniff(filter=filter, iface=ifaces,
                         prn=lambda pkt: pkt.show(), count=count)
        self.logger.info("Finished Sniffing...")
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
            self.logger.error("Parsing Error: %s", e)
            sys.exit(1)

    def store(self):
        args = self.parser()
        if args is None:
            self.logger.warning("")
        pkts = self.sniffer(ifaces=args.get('ifaces'),
                            count=args.get('count'),
                            filter=args.get('filter')
                            )
        results = {
            "tcp_ip": [],
            "udp_ip": []
        }
        self.logger.info("Storing Results...")
        for pkt in pkts:
            
            if "IP" and "TCP" in pkt:
                results["tcp_ip"].append(pkt)
                self.logger.info("TCP Packets: %s", results)
            elif "IP" and "UDP" in pkt:
                results["udp_ip"].append(pkt)
                self.logger.info("UDP Packets: %s", results)


def main():
    """ MAIN FUNCTION """
    sniffer = Sniffer()
    sniffer.store()


if __name__ == "__main__":
    main()
