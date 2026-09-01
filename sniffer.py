from scapy.all import (
    sniff
)
from logger import Logger
from server import PacketManager

logger = Logger()
logger.setLevel()


class Sniffer():
    def __init__(self):
        pass

    def sniffer(self):
        pkt = PacketManager()
        ifaces = ["wlp0s20f3", "enp0s31f6", "lo"]
        print(sniff(iface=[i for i in ifaces],
                    prn=pkt.show(),
                    count=40
                    ))


def main():
    try:
        sniffer = Sniffer()
        options: dict = {
            1: sniffer.sniffer
        }
        for option, func in options.items():
            if func:
                func() 
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()