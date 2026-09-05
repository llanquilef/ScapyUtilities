""" SNIFFER """
from typing import Any
import sys
import argparse
from scapy.all import (
    sniff
    )
from logger import Logger


dict_configuration: dict[str, Any] = {
    "sniffer": {
        1: {
            "command": "-f",
            "reference": "--filter",
            "type": str,
            "choices": ["", "tcp", "udp", "icmp"],
            "default": "",
            "help": "Filter for your report: TCP, UDP, ICMP, ("" -> Stands for general)"
            },
        2: {
            "command": "-i",  # ifaces
            "reference": "--dst",
            "type": str,
            "nargs": "+",
            "help": "How many packets you want to review"
        },
        3: {
            "command": "-c",
            "reference": "--count",
            "type": int,
            "help": "How many packets you want to review" 
        }
    },
    "scanner": {
        1: {
            "command": "-ip",
            "type": str,
            "help": "IP Address Destiny"
        },
        2: {
            "command": "-p",
            "reference": "--ports",
            "type": int,
            "help": "Ports to review"
        }
    },
    "packet_creator": {
        1: {
            "command": "-t",
            "reference": "--ttl",
            "type": int,
            "default": 10,
            "required": True
        },
        2: {
            "command": "-d",
            "reference": "--dst",
            "type": str,
            "required": True
        },
        3: {
            "command": "-s",
            "reference": "--src",
            "type": str,
            "required": True,
        },
        4: {
            "command": "-f",
            "reference": "--flags",
            "choices": ["MF", "evil"],
            "type": str,
            "default": None,
            "required": False
        }
    },
    "syn_scan": {
        1: {
            "command": "-i",
            "reference": "--dst",
            "type": str,
            "help": "Direction Port For Scanning"
        },
        2: {
            "command": "-sp",
            "reference": "--sport",
            "type": int,
            "help": "Source Port"
        },
        3: {
            "command": "-dp",
            "reference": "--dports",
            "type": int,
            "nargs": "+",
            "help": "Direction Port For Scanning"
        }
    }
}


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

            parser.add_argument("-i", "--ifaces", type=str, nargs="+",
                                help="Interfaces that you need to scan")

            parser.add_argument("-c", "--count", type=int,
                                help="How many packets you want to review"
                                )
            return parser
        except argparse.ArgumentError as e:
            print(e)
            sys.exit(1)

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
