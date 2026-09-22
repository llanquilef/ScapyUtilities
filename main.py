from typing import Any
from sniffer import Sniffer
from scanner import Scanner
from package_manager import PacketManager
import argparse



class Init():
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="")

    def loop(self):
        for key, configuration in dict_configuration.items():
            if key == 'sniffer':
                parser = self.parser
                parser.add_argument(
                    configuration["sniffer"][1]["command"],
                    configuration["sniffer"][1]["reference"],
                    type=configuration["sniffer"][1]["type"],
                    default=configuration["sniffer"][1]["default"],
                    choices=configuration["sniffer"][1]["choices"]
                    )
                parser.add_argument(
                    configuration["sniffer"][2]["command"],
                    configuration["sniffer"][2]["reference"],
                    type=configuration["sniffer"][2]["type"],
                    nargs=configuration["sniffer"][2]["nargs"],
                    help=configuration["sniffer"][2]["help"]
                )
                args = vars(parser.parse_args())
                sniffer = Sniffer()
                sniffer.sniffer(
                    filter=args.get('filter'),
                    ifaces=args.get('ifaces'),
                    count=args.get('count')
                                )
            elif key == 'scanner':
                parser = self.parser
                parser.add_argument(
                    configuration["scanner"][2]["command"],
                    type=configuration["scanner"][2]["type"],
                    default=configuration["scanner"][2]["default"],
                    choices=configuration["scanner"][2]["choices"]
                )
                args = vars(parser.parse_args())
                scanner = Scanner()
                scanner.syn_scan(
                    dst=args.get('dst'),
                    dport=args.get('ports')
                )
            elif key == 'packet_creator':
                parser = self.parser
                parser.add_argument(
                    configuration["packet_creator"][1]["command"],
                    configuration["packet_creator"][1]["reference"],
                    type=configuration["packet_creator"][1]["type"],
                    default=configuration["packet_creator"][1]["default"],
                    required=configuration["packet_creator"][1]["required"]
                )
                parser.add_argument(
                    configuration["packet_creator"][2]["command"],
                    configuration["packet_creator"][2]["reference"],
                    type=configuration["packet_creator"][2]["type"],
                    required=configuration["packet_creator"][2]["required"]
                )
                parser.add_argument(
                   configuration["packet_creator"][3]["command"],
                   configuration["packet_creator"][3]["reference"],
                   type=configuration["packet_creator"][3]["type"],
                   required=configuration["packet_creator"][3]["required"]
                )
                parser.add_argument(
                    configuration["packet_creator"][4]["command"],
                    configuration["packet_creator"][4]["reference"],
                    type=configuration["packet_creator"][4]["choices"],
                    choices=configuration["packet_creator"][4]["type"],
                    default=configuration["packet_creator"][4]["default"],
                )
                args = vars(parser.parse_args())
                package_creator = PacketManager()
                package_creator.create_packet(dst=args.get('dst'))

            elif key == "syn_scan":
                parser = self.parser
                parser.add_argument(
                    configuration["syn_scan"][1]["command"],
                    configuration["syn_scan"][1]["reference"],
                    type=configuration["syn_scan"][1]["type"],
                    help=configuration["syn_scan"][1]["help"]
                )
                parser.add_argument(
                    configuration["syn_scan"][2]["command"],
                    configuration["syn_scan"][2]["reference"],
                    type=configuration["syn_scan"][2]["type"],
                    help=configuration["syn_scan"][2]["help"]
                )
                parser.add_argument(
                    configuration["syn_scan"][3]["command"],
                    configuration["syn_scan"][3]["reference"],
                    type=configuration["syn_scan"][3]["type"],
                    nargs=configuration["syn_scan"][3]["nargs"],
                    help=configuration["syn_scan"][3]["help"]
                )
                args = vars(parser.parse_args())
                scan = Scanner()
                scan.syn_scan(dst=args.get('dst'), dport=args.get('dports'))

            else:
                print("Invalid option")


def main():
    """ MAN FUNCTON """
    init = Init()
    init.loop()


if __name__ == "__main__":
    main()
