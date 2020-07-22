import abc
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether
from scapy.all import *
from threading import Thread, Event
import requests
import pydevd_pycharm

from time import sleep
from scapy.contrib.nsh import NSH


class Sniffer(Thread):

    def __init__(self, interface_in, interface_out=None):
        self.interface_in = interface_in
        if interface_out is None:
            self.interface_out = self.interface_in
        else:
            self.interface_out = interface_out
        super(Sniffer, self).__init__()

        self.daemon = True
        self.socket = None
        self.stop_sniffer = Event()
        self.n_packets = 0

        self.l3socket = None

    def isNotOutgoing(self, pkt):
        return pkt[Ether].src != Ether().src

    def run(self):

        self.l3socket = conf.L3socket()
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            #type=ETH_P_IP,
            iface=self.interface_in
        )

        sniff(
            opened_socket=self.socket,
            prn=self.process_packet,
            store=False,
            filter=self.isNotOutgoing
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super(Sniffer, self).join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    @abc.abstractmethod
    def process_packet(self, pkt):
        pass

    def send_packet(self, packet_new):
        sendp(packet_new, iface=self.interface_out)


class PingDecoy(Sniffer):
    def __init__(self, interface_in, interface_out=None):
        super(PingDecoy, self).__init__(interface_in, interface_out)
        self.self_mac = get_if_hwaddr(interface_in)

    def process_packet(self, pkt):
        #print("Crafting ICMP PING reply")
        #if (pkt.haslayer(UDP)):
            #pydevd_pycharm.settrace('192.168.1.110', port=54321, stdoutToServer=True, stderrToServer=True)
        if (pkt.haslayer(ICMP)):


            eth_pkt = pkt.getlayer(Ether)
            if self.self_mac != eth_pkt.src:
                src_icmp = pkt.getlayer(ICMP)
                src_ip = pkt.getlayer(IP)
                ip2 = IP()
                ip2.dst = src_ip.src
                ip2.src = src_ip.dst

                icmp = ICMP()
                icmp.type = 0
                icmp.id = src_icmp.id
                icmp.seq = src_icmp.seq
                icmp.payload = src_icmp.payload
                #print("Replying for ICMP PING for %s to %s" % (ip2.dst, ip2.src))
                #send(ip2 / icmp, socket=self.l3socket, verbose=False)

                ether = Ether(dst=eth_pkt.src, src=eth_pkt.dst)
                packet = ether / ip2 / icmp
                sendpfast(packet)


if __name__ == '__main__':
    print(f'interface: {sys.argv[1]}')
    sniffer = PingDecoy(interface_in=sys.argv[1])
    print("[*] Start sniffing...")
    sniffer.start()
    duration = 200
    sleep(duration)
    sniffer.join()

    print("[*] Stop sniffing")