import abc
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.all import *
from threading import Thread, Event
import requests
import pydevd_pycharm

from time import sleep
from scapy.contrib.nsh import NSH
from sdn_defense import FACTOR
if __name__ == '__main__':
    #print(f'interface: {sys.argv[1]}')

    with open("ip_blacklist_test.txt") as f:
        content = f.readlines()
    blacklist_ip = list()
    content = [x.strip() for x in content]
    for item in content:
        ip_tuple = item.replace("(", "").replace(")", "").replace("'", "").replace(" ", "").split(",")
        blacklist_ip.append(ip_tuple[0])
    quarantione_ip = ["10.0.88.2", "10.0.88.3", "10.0.88.4", "10.0.88.5", "10.0.88.6", "10.0.88.7", "10.0.88.8"
                      , "10.0.88.9", "10.0.88.10", "10.0.88.11"]
    dst_ip_ind = random.randint(0, len(quarantione_ip)-1)
    factor = FACTOR
    send(IP(src=blacklist_ip[0:factor], dst=quarantione_ip[7]) / ICMP(), verbose=False)
