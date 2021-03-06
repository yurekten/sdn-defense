import socket
from datetime import datetime

from getmac import get_mac_address as gma
from ryu.lib.packet import arp
from ryu.lib.packet import packet, ethernet
from ryu.ofproto import ether

from configuration import BROADCAST_MAC, ZERO_MAC


def copy_remove_msg_data(msg, target_dict):
    target_dict["removed_time"] = datetime.timestamp(datetime.now())
    target_dict["packet_count"] = msg.packet_count
    target_dict["byte_count"] = msg.byte_count
    target_dict["duration_sec"] = msg.duration_sec
    target_dict["duration_nsec"] = msg.duration_nsec
    target_dict["hard_timeout"] = msg.hard_timeout
    target_dict["idle_timeout"] = msg.idle_timeout
    target_dict["priority"] = msg.priority
    target_dict["reason"] = msg.reason
    target_dict["table_id"] = msg.table_id


def get_Host_name_IP():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        print("Hostname :  ", host_name)
        print("IP : ", host_ip)
    except:
        print("Unable to get Hostname and IP")


def build_arp_request(src_ip, dst_ip, src_mac=None):
    _eth_dst_mac = BROADCAST_MAC
    _arp_dst_mac = ZERO_MAC
    if src_mac is None:
        src_mac = gma()
    e = build_ether(ether.ETH_TYPE_ARP, _eth_dst_mac, src_mac)
    a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                opcode=1, src_mac=src_mac, src_ip=src_ip,
                dst_mac=_arp_dst_mac, dst_ip=dst_ip)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()

    return p


def build_ether(ethertype, dst_mac, src_mac):
    e = ethernet.ethernet(dst_mac, src_mac, ethertype)
    return e
