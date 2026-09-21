import argparse
from scapy.all import (srp)
from scapy.layers.l2 import Ether, ARP
import logging


class ARPManager():
    def __init__(self):
        self.target = None
        self.gateway = None
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"
        self.hosts = []
        self.logger = logging.getLogger(__class__.__name__)
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s - %(processName)s "
            )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

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
            self.logger.info('Starting network scanner...')
            args = self.dict_parser()
            pkt = self.arp_packet()
            ans, unans = srp(pkt, timeout=timeout,
                             iface=args.get('iface'),
                             inter=0.1, verbose=False
                             )
            for s, r in ans:
                ip = r[ARP].psrc
                mac = r[Ether].src
                self.hosts.append((ip, mac))
            self.logger.info("Hosts: %s", self.hosts)
            self.logger.info("Network Scanning Finished")
            return self.hosts
        except TimeoutError:
            self.logger.error("Timeout Error")

    def dict_host(self):
        hosts = self.network_scanner()
        results = {
            "IP": [],
            "MAC": []
        }
        for ip, mac in hosts:
            results["IP"].append(ip)
            results["MAC"].append(mac)
        return results


def main():
    arp = ARPManager()
    arp.dict_host()


if __name__ == "__main__":
    main()
