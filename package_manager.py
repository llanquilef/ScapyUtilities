""" SCAPY """
import logging
import argparse
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import (send,
                       conf,
                       RawVal,
                       hexdump,
                       sr1
                       )
from dotenv import load_dotenv
from dict import dict_configuration
from logger import setup_logger


load_dotenv()


class PacketManager():
    """ PACKET MANAGER """
    def __init__(self):
        self.logger = setup_logger()
        self.parser_init = argparse.ArgumentParser(
            description="Packet Creator CLI"
            )

    def parser(self) -> argparse.ArgumentParser:
        try:
            parser = self.parser_init
            # TTL
            parser.add_argument(
                dict_configuration["packet_creator"][1]["command"],
                dict_configuration["packet_creator"][1]["reference"],
                type=dict_configuration["packet_creator"][1]["type"],
                default=dict_configuration["packet_creator"][1]["default"],
                required=dict_configuration["packet_creator"][1]["required"]
                )
            # DST
            parser.add_argument(
                dict_configuration["packet_creator"][2]["command"],
                dict_configuration["packet_creator"][2]["reference"],
                type=dict_configuration["packet_creator"][2]["type"],
                required=dict_configuration["packet_creator"][2]["required"]
            )
            # SOURCE -> SRC
            parser.add_argument(
                dict_configuration["packet_creator"][3]["command"],
                dict_configuration["packet_creator"][3]["reference"],
                type=dict_configuration["packet_creator"][3]["type"]
            )
            # FLAGS -> -f
            parser.add_argument(
                dict_configuration["packet_creator"][4]["command"],
                dict_configuration["packet_creator"][4]["reference"],
                choices=dict_configuration["packet_creator"][4]["choices"],
                type=dict_configuration["packet_creator"][4]["type"],
                default=dict_configuration["packet_creator"][4]["default"],
                required=dict_configuration["packet_creator"][4]["required"] 
            )
            return parser
        except argparse.ArgumentError as e:
            self.logger.error("Parsing Error: %s", e)

    def dict_parser(self) -> dict:
        """ ARGS DICTIONARY  """
        parser_result = self.parser()
        self.logger.info("Parsing...")
        args = vars(parser_result.parse_args())
        return args

    def create_packet(self):
        """ PACKET CREATOR """
        args = self.dict_parser()
        packet = IP(
            ttl=args.get('ttl'),
            dst=args.get('dst')
            )
        self.logger.info("Packet: %s", packet)
        return packet

    def stacking_layer(self):
        """ STACKING LAYER """
        self.logger.info("%s", IP/TCP)
        return IP()/TCP()

    def send_packet(self):
        """ PACKET SEND """
        args = self.dict_parser()
        return send(
            IP(dst=args.get('dst'))/ICMP(),
            count=4,
            verbose=conf.verb
            )  # x -> Refers to PacketIterable

    def inject_bytes(self):
        args = self.dict_parser()
        pkt = IP(len=RawVal(b"WHATUPPPP"), src=args.get('src'))
        self.logger.info("Bytes: %s", bytes(pkt))
        return bytes(pkt)

    def hexdump_packet(self):
        packet = self.create_packet()
        return hexdump(packet)

    def show_and_receive_packets(self):
        args = self.dict_parser()
        p = sr1(IP(dst=args.get('dst'))/ICMP()/"XXXXXXXXXXX")
        p.show(dump=True, indent=3)
        self.logger.info("%s", p)
        return p

    # def selector(self):
    #     """ PACKET MANAGER SELECTOR """
    #     election = input("What do you need to do: ")
    #     match election:
    #         case 1:
    #             return self.create_packet()
    #         case 2:
    #             return self.send_packet()
    #         case 3:
    #             return self.stacking_layer()
    #         case 4:
    #             return self.inject_bytes()
    #         case 5:
    #             return self.show_and_receive_packets()
    #         case 6:
    #             return self.hexdump_packet()
    #         case _:
    #             print("Invalid option")


def main():
    try:
        packet = PacketManager()
        packet.create_packet()
        PM = PacketManager()
        dict_options: dict = {
            1: PM.create_packet,
            2: PM.stacking_layer,
            3: PM.send_packet,
            4: PM.inject_bytes,
            5: PM.hexdump_packet,
            # 6: PM.show_and_receive_packets
        }
        election = input("""
        ****** OPTIONS ****** \n
        1.- 'create': Packet Creation
        2.- 's_layer': Stacking Layer \n
        What options do you need:
        """)
        selected = dict_options.get(election)
        if selected:
            selected()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
