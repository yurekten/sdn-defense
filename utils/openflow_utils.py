from datetime import datetime

from ryu.lib import mac
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import arp
from ryu.ofproto import ether
from getmac import get_mac_address as gma


ZERO_MAC = mac.haddr_to_bin('00:00:00:00:00:00')
BROADCAST_MAC = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')

def delete_flow(datapath, cookie=0, cookie_mask=0xFFFFFFFFFFFFFFFF):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    mod = parser.OFPFlowMod(datapath=datapath,
                            command=ofproto.OFPFC_DELETE,
                            out_port=ofproto.OFPP_ANY,
                            out_group=ofproto.OFPG_ANY,
                            table_id=ofproto.OFPTT_ALL,
                            cookie=cookie,
                            cookie_mask=cookie_mask,
                            )
    datapath.send_msg(mod)



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

def _build_arp_request(dst_ip):
    _eth_dst_mac = BROADCAST_MAC
    _arp_dst_mac = ZERO_MAC
    mac = gma(ip="127.0.0.1")
    e = build_ether(ether.ETH_TYPE_ARP, _eth_dst_mac)
    a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                opcode=1, src_mac=mac, src_ip=self.RYU_IP,
                dst_mac=_arp_dst_mac, dst_ip=dst_ip)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()

    return p

def build_ether(ethertype, dst_mac, src_mac):
    e = ethernet.ethernet(dst_mac, src_mac, ethertype)
    return e