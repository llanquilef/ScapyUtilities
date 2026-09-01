""" SCAPY """
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import (send,
                       conf,
                       hexdump,
                       RawVal
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
    """ PACKET MANAGER CLASS"""
    def __init__(self):
        pass

    def create_packet(self):
        """ CREATE PACKET """
        packet = IP(ttl=10, dst=os.getenv('ip_dst'))
        return packet

    def show(self):
        pkt = self.create_packet()
        return pkt.show()
    
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
        """ INJECT BYTES """
        pkt = IP(len=RawVal(b"WHATUPPP"), src="127.0.0.1")
        return bytes(pkt)

    def hexdump(self):
        packet = self.create_packet()
        return hexdump(packet)

    def log(self):
        with open('log.txt', 'w', encoding='utf-8') as log:
            log_txt = log.read()
            return log_txt


def main():
    """ MAIN FUNCTION """
    try:
        PM = PacketManager()
        dict_options: dict = {
            1: PM.create_packet,
            2: PM.stacking_layer,
            3: PM.send_packet,
            4: PM.inject_bytes,
            5: PM.hexdump
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
