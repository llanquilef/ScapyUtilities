""" SNIFFER """
import argparse
from dict import dict_configuration
from scapy.all import (
    sniff
    )
from logger import setup_logger


class Sniffer():
    """ SNIFFER """
    def __init__(self):
        self.logger = setup_logger()
        self.logger.info("Start of Run...")
        self.parser = argparse.ArgumentParser(
            description="Sniffer TCP and UDP for specifics IP's"
            )
        self.parser.add_argument(
            dict_configuration["sniffer"][1]["command"],
            dict_configuration["sniffer"][1]["reference"],
            type=dict_configuration["sniffer"][1]["type"],
            choices=dict_configuration["sniffer"][1]["choices"],
            default=dict_configuration["sniffer"][1]["default"],
            help=dict_configuration["sniffer"][1]["help"]
            )

        self.parser.add_argument(
            dict_configuration["sniffer"][2]["command"],
            dict_configuration["sniffer"][2]["reference"],
            type=str,
            nargs="+",
            help="Interfaces that you need to scan"
            )

        self.parser.add_argument(
            dict_configuration["sniffer"][3]["command"], 
            dict_configuration["sniffer"][3]["reference"],
            type=dict_configuration["sniffer"][3]["type"],
            help=dict_configuration["sniffer"][3]["help"]
            )
        self.args = vars(self.parser.parse_args())

    def sniffer(self):
        """ SNIFFER """
        self.logger.info("Sniffing...")
        sniffing = sniff(filter=self.args.get("filter"),
                         iface=self.args.get("iface"),
                         count=self.args.get("count"),
                         prn=lambda pkt: pkt.show()
                         )
        self.logger.info("Finished Sniffing...")
        return sniffing

    def store(self):
        if self.args is None:
            self.logger.warning("Args is a None Type Value")
        pkts = self.sniffer()
        results = {
            "tcp": [],
            "udp": []
        }
        self.logger.info("Storing Results...")
        for pkt in pkts:
            if "IP" and "TCP" in pkt:
                results["tcp"].append(pkt)
                self.logger.info("TCP Packets: %s", results)
            elif "IP" and "UDP" in pkt:
                results["udp"].append(pkt)
                self.logger.info("UDP Packets: %s", results)


def main():
    """ MAIN FUNCTION """
    sniffer = Sniffer()
    sniffer.store()


if __name__ == "__main__":
    main()
