import argparse
from scapy.all import (srp)
from scapy.layers.l2 import Ether, ARP
from logger import setup_logger


class ARPManager():
    def __init__(self):
        self.target = None
        self.gateway = None
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"
        self.hosts = {}
        self.logger = setup_logger()
        self.parser = argparse.ArgumentParser(
            description=""
        )
        self.parser.add_argument('-i', '--iface', type=str, help="Interfaces to review")
        self.parser.add_argument('-r', '--range', type=str, help="IP range")
        self.args = vars(self.parser.parse_args())

    def arp_packet(self):
        """
        pdst parameter accepts individual addresses
        and CIDR ranges like 10.10.10.0/24
        """
        ether_layer = Ether(dst=self.broadcast_mac)
        arp_layer = ARP(pdst=self.args.get('range'))
        return ether_layer / arp_layer

    def network_scanner(self, timeout=2):
        try:
            self.logger.info('Starting network scanner...')
            pkt = self.arp_packet()
            ans, unans = srp(pkt, timeout=timeout,
                             iface=self.args.get('iface'),
                             inter=0.1, verbose=False
                             )
            for s, r in ans:
                ip = r[ARP].psrc
                mac = r[Ether].src
                self.hosts[ip] = mac
            self.logger.info("Hosts: %s", self.hosts)
            self.logger.info("Network Scanning Finished")
            return self.hosts
        except TimeoutError:
            self.logger.error("Timeout Error")

    # def store(self):
    #     hosts = self.network_scanner()
    #     results = {
    #         "IP": [],
    #         "MAC": []
    #     }
    #     for ip, mac in hosts:
    #         results["IP"].append(ip)
    #         results["MAC"].append(mac)
    #     self.logger.info("Storing Results...")
    #     self.logger.info("Hosts: %s", results)
    #     return results


def main():
    arp = ARPManager()
    arp.network_scanner()


if __name__ == "__main__":
    main()
