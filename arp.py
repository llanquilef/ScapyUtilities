import argparse
from scapy.all import (srp)
from scapy.layers.l2 import Ether, ARP



class ARPManager():
    def __init__(self):
        self.target = None
        self.gateway = None
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"
        self.hosts = []

    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--iface', type=str, help="Interfaces to review")
        parser.add_argument('-r', '--range', type=str, help="IP range")
        return parser

    def dict_parser(self):
        args = self.parser()
        return vars(args.parse_args())

    def arp_packet(self):
        """
        pdst parameter accepts individual addresses
        and CIDR ranges like 10.10.10.0/24
        """
        args = self.dict_parser()
        ether_layer = Ether(dst=self.broadcast_mac)
        arp_layer = ARP(pdst=args.get('range'))
        return ether_layer / arp_layer

    def network_scanner(self, timeout=2):
        try:
            args = self.dict_parser()
            pkt = self.arp_packet()
            ans, unans = srp(pkt, timeout=timeout,
                             iface=args.get('iface') if args else 'wlp0s20f3',
                             inter=0.1, verbose=False
                             )
            for s, r in ans:
                ip = r[ARP].psrc
                mac = r[Ether].src
                self.hosts.append((ip, mac))
                print(self.hosts)
            return self.hosts
        except TimeoutError:
            pass


def main():
    arp = ARPManager()
    arp.network_scanner()


if __name__ == "__main__":
    main()
