""" SCAPY """
import argparse
import sys
from typing import Any
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import (send,
                       conf,
                       hexdump,
                       RawVal
                       )
from dotenv import load_dotenv
from sniffer import dict_configuration

load_dotenv()


class PacketManager():
    """ PACKET MANAGER CLASS"""
    def __init__(self):
        self.parser_init = argparse.ArgumentParser(
            description="Packet Creator"
        )

    def parser(self):
        parser = self.parser_init
        if dict_configuration is not dict:
            raise TypeError("dict_configuration must be a dict")
        
        parser.add_argument(
            dict_configuration["packet_creator"][1]["command"],
            dict_configuration["packet_creator"][1]["reference"],
            type=dict_configuration["packet_creator"][1]["type"],
            required=dict_configuration["packet_creator"][1]["required"] 
        )
        
        parser.add_argument(
            dict_configuration["packet_creator"][2]["command"],
            dict_configuration
        )
    
    def dict_parser(self):
        parser = self.parser_init
        args = parser.parse_args()
        print(args)
        return vars(args)
    
    
    def create_packet(self, ttl: int, dst: str, src: str, flags: str):
        """ CREATE PACKET """
        packet = IP(ttl=ttl, dst=dst, src=src, flags=flags)
        return packet

    def stacking_layer(self):
        """ Layers TCP/ICP """
        return IP()/TCP()

    def send_packet(self, dst: str):
        return send(
            IP(dst=dst)/ICMP(),
            count=4,
            verbose=conf.verb
            )  # x -> Refers to PacketIterable

    def inject_bytes(self):
        """ INJECT BYTES """
        pkt = IP(len=RawVal(b"WHATUPPP"), src="127.0.0.1")
        return bytes(pkt)

    def packet_parser(self) -> dict[str, Any]:
        """ CREATE PACKET PARSER FUNCTION """
        try:
            parser = argparse.ArgumentParser(description="Create Packet CLI")
            parser.add_argument("-t", '--ttl', type=int, default=10, required=True)
            parser.add_argument("-d", '--dst', type=str, required=True)
            parser.add_argument("-s", '--src', required=True)
            parser.add_argument("-f", '--flags', choices=["MF", "evil"], default=10, required=False)
            args = vars(parser.parse_args())
            if args is not dict:
                raise TypeError("args must be a dict")
            return args
        except argparse.ArgumentError as e:
            print(e)
            sys.exit(1)

    def hexdump(self):
        """ HEXDUMP PACKET """
        args = self.packet_parser()
        packet = self.create_packet(ttl=args.get('ttl'),
                                    dst=args.get('dst'),
                                    src=args.get('src'),
                                    flags=args.get('flags'))
        return hexdump(packet)

    def show(self):
        """ SHOW PACKET """
        try:
            args = self.packet_parser()
            if args.keys is None:
                raise KeyError("Keys dont match")
            pkt = self.create_packet(ttl=args.get('ttl'),
                                     dst=args.get('dst'),
                                     src=args.get('src'),
                                     flags=args.get('flags')
                                     )
            return pkt.show()
        except Exception as e:
            print(e)


def main():
    """ MAIN FUNCTION """
    try:
        logger = Logger()
        logger.setLevel()
        PM = PacketManager()
        dict_options: dict = {
            'create': PM.create_packet,
            's_layer': PM.stacking_layer,
            'send': PM.send_packet,
            'inject': PM.inject_bytes,
            'hex': PM.hexdump
        }
        election = input("What option do you want: ")
        selected = dict_options.get(election)
        if selected:
            selected()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
