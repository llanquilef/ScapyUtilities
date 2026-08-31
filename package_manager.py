""" SCAPY """
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import (send,
                       conf,
                       RawVal,
                       hexdump,
                       sr1
                       )
from logger import Logger
from dotenv import load_dotenv
import os

load_dotenv()

logger = Logger()
logger.setLevel()

IP_SRC = os.getenv('ip_src')
IP_DST = os.getenv('ip_dst')


class PacketManager():
    def __init__(self):
        pass

    def create_packet(self):
        packet = IP(ttl=10, dst=os.environ.get('ip_dst'))
        print(packet)
        return packet

    def stacking_layer(self):
        print(IP()/TCP())
        return IP()/TCP()

    def send_packet(self):
        return send(
            IP(dst="192.168.1.1")/ICMP(),
            count=4,
            verbose=conf.verb
            )  # x -> Refers to PacketIterable

    def inject_bytes(self):
        pkt = IP(len=RawVal(b"WHATUPPP"), src="127.0.0.1")
        print(bytes(pkt))
        return bytes(pkt)

    def hexdump_packet(self):
        packet = self.create_packet()
        return hexdump(packet)

    # def show_and_receive_packets(self):
    #     p = sr1(IP(dst="www.google.com")/ICMP()/"XXXXXXXXXXX")
    #     p.show(dump=True, indent=3)
    #     print(p)
    #     return p

    def log(self):
        with open('log.txt', 'w', encoding='utf-8') as log:
            log_txt = log.read()
            return log_txt


def main():
    try:
        PM = PacketManager()
        dict_options: dict = {
            1: PM.create_packet,
            2: PM.stacking_layer,
            3: PM.send_packet,
            4: PM.inject_bytes,
            5: PM.hexdump_packet,
            # 6: PM.show_and_receive_packets
        }
        # election = input("""
        # ****** OPTIONS ****** \n
        # 1.- 'create': Packet Creation
        # 2.- 's_layer': Stacking Layer \n
        # What options do you need:
        # """)
        for option, function in dict_options.items():
            if function:
                function()
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
