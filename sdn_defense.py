import logging
import pathlib
from collections import defaultdict
from datetime import datetime

from cachetools import cached, TTLCache
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_4
from ryu.topology import event

from configuration import SDN_CONTROLLER_APP_KEY
from defense_managers.blacklist.black_list_manager import BlackListManager
from defense_managers.multipath.multipath_manager import MultipathManager
from rest.flow_monitor_rest import FlowMonitorRest
from rest.multipath_manager_rest import MultipathManagerRest
from sdn.flow_monitor import FlowMonitor
from sdn.topology_monitor import TopologyMonitor

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)


class SDNDefenseApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):

        super(SDNDefenseApp, self).__init__(*args, **kwargs)
        self.wsgi = kwargs['wsgi']
        self.wsgi.register(BlackListManager, {SDN_CONTROLLER_APP_KEY: self})
        self.wsgi.register(FlowMonitorRest, {SDN_CONTROLLER_APP_KEY: self})
        self.wsgi.register(MultipathManagerRest, {SDN_CONTROLLER_APP_KEY: self})


        self.sw_cookie = defaultdict()
        self.unused_cookie = 0x0010000
        self.hosts = {}
        self.host_ip_map = {}
        self.mac_to_port = {}


        now = int(datetime.now().timestamp())

        self.topology_monitor = TopologyMonitor()
        self.topology = self.topology_monitor.topology
        self.datapath_list = self.topology_monitor.datapath_list

        watch_generated_flows = False  # If flows generated by this class is reported, It is used to test
        flows_report_folder = "flows-%d" % (now)
        self.flow_monitor = FlowMonitor(flows_report_folder, watch_generated_flows)

        self.multipath_manager = MultipathManager(self)


    def _get_next_flow_cookie(self, sw_id):
        if sw_id not in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, cookie=0,
                 table_id=0, idle_timeout=0, caller=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_id = cookie
        if cookie == 0:
            flow_id = self._get_next_flow_cookie(datapath.id)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    instructions=inst, hard_timeout=hard_timeout, flags=flags, cookie=flow_id,
                                    table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout,
                                    match=match, instructions=inst, hard_timeout=hard_timeout, flags=flags,
                                    cookie=flow_id, table_id=table_id)
        datapath.send_msg(mod)
        flows = self.flow_monitor.flows
        if datapath.id not in flows:
            flows[datapath.id] = defaultdict()
        if caller:
            flows[datapath.id][flow_id] = (mod, caller)
        else:
            flows[datapath.id][flow_id] = (mod, self)
        return flow_id

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        logger.debug("switch_features_handler is called for %s" % str(ev))
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flags=0)

        ofp_parser = datapath.ofproto_parser

        actions = []
        match1 = ofp_parser.OFPMatch(eth_type=0x86DD)  # IPv6
        self.add_flow(datapath, 999, match1, actions, flags=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # avoid broadcast from LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if pkt.get_protocol(ipv6.ipv6):
            return

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        in_port = msg.match['in_port']
        logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
        else:
            # ignore other packets
            return

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port, src_ip)
            self.host_ip_map[src_ip] = (dpid, in_port, src)

        out_port = None
        if src in self.hosts and dst in self.hosts:
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if h1[0] == dpid:
                # if self._can_be_managed_flow(in_port, dst, src, h1[0]):
                out_port = self.multipath_manager.get_active_path_port_for(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, dpid)
        if out_port is None:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.multipath_manager.default_flow_will_be_added(datapath, src_ip, dst_ip, in_port, out_port)

            #add idle flow
            priority = 1
            idle_timeout = 10
            hard_timeout = 0
            flags = 0
            if self.flow_monitor.watch_generated_flows:
                flags = ofproto.OFPFF_SEND_FLOW_REM

            self.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_port, priority, flags,
                                           hard_timeout, idle_timeout)
            self.create_rule_if_not_exist(dpid, dst_ip, src_ip, out_port, in_port, priority, flags,
                                           hard_timeout, idle_timeout)
        else:

            no_flood_ports = self.topology_monitor.get_no_flood_ports()
            actions = []
            if dpid in no_flood_ports:
                for port, port_info in self.datapath_list[dpid].ports.items():
                    if port_info.state == 4 and port not in no_flood_ports[dpid]:
                        if port != in_port:
                            actions.append(parser.OFPActionOutput(port))
            else:
                actions.append(parser.OFPActionOutput(out_port))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)



    @cached(cache=TTLCache(maxsize=1024, ttl=1))
    def create_rule_if_not_exist(self, dpid, src_ip, dst_ip, in_port, out_port, priority, flags, hard_timeout,
                                  idle_timeout):
        datapath = self.datapath_list[dpid]
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            in_port=in_port
        )

        flow_id = self.add_flow(datapath, priority, match, actions, hard_timeout=hard_timeout, flags=flags,
                                idle_timeout=idle_timeout)
        #TODO: flags == datapath.ofproto.OFPFF_SEND_FLOW_REM will be flags & datapath.ofproto.OFPFF_SEND_FLOW_REM >1
        if self.host_ip_map[src_ip][0] == dpid and flags == datapath.ofproto.OFPFF_SEND_FLOW_REM:
            self.flow_monitor.add_to_flow_list(dpid, flow_id, match, actions, priority, idle_timeout, hard_timeout)

        return flow_id

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        self.flow_monitor.flow_removed_handler(ev)

    def flow_removed(self, msg):
        self.flow_monitor.flow_removed(msg)
        self.multipath_manager.flow_removed(msg)

    ### topology events
    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        self.topology_monitor.switch_enter_handler(ev)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def _switch_leave_handler(self, ev):
        self.topology_monitor.switch_leave_handler(ev)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        self.topology_monitor.link_add_handler(ev)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def _link_delete_handler(self, ev):
        self.topology_monitor.link_delete_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        self.topology_monitor.port_status_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        self.topology_monitor.port_desc_stats_reply_handler(ev)
