from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
import networkx as nx



from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse, FlowAddedEvent
from utils.file_utils import save_dict_to_file
from utils.openflow_utils import build_arp_request


class BaseDefenseManager(ABC):

    def __init__(self, name, sdn_controller_app, enabled, report_folder):
        self.name = name
        self.sdn_controller_app = sdn_controller_app
        self.enabled = enabled
        self.report_folder = report_folder
        self.statistics = defaultdict()
        self.host_ip_map = self.sdn_controller_app.host_ip_map
        self.hosts = self.sdn_controller_app.hosts
        self.topology = self.sdn_controller_app.topology
        self.datapath_list = self.sdn_controller_app.datapath_list

    def get_statistics(self):
        return self.statistics

    def reset_statistics(self):
        self.statistics.clear()

    def save_statistics(self):
        now = int(datetime.now().timestamp())
        file_name = "%s-stats.json" % (now)
        return save_dict_to_file(self.report_folder, file_name, self.statistics)

    def send_arp_request(self, dpid, src_ip, dst_ip, in_port=None, src_mac=None):

        arp = build_arp_request(src_ip, dst_ip, src_mac)
        datapath = self.datapath_list[dpid]
        ofproto = datapath.ofproto
        out_port = ofproto.OFPP_FLOOD
        if in_port is None:
            in_port = datapath.ofproto.OFPP_LOCAL

        actions = self.sdn_controller_app.get_flood_output_actions(dpid, in_port, out_port)

        buffer_id = 0xffffffff
        in_port = datapath.ofproto.OFPP_LOCAL
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath, buffer_id, in_port, actions, arp.data)
        datapath.send_msg(out)

    def get_shortest_flow(self, src_dpid, first_port, dst_dpid, last_port):
        path = self.get_shortest_path(src_dpid, dst_dpid)
        paths_with_ports = self.add_ports_to_paths([(path, 1)], first_port, last_port)
        return paths_with_ports[0]

    def get_shortest_path(self, src_dpid, dst_dpid) :
        path = nx.shortest_path(self.topology, source=src_dpid, target=dst_dpid)
        nodes = []
        for node in path:
            nodes.append(node)

        return nodes

    def add_ports_to_paths(self, paths, first_port, last_port):
        """
        Add the ports that connects the switches for all paths
        """
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[0][:-1], path[0][1:]):
                out_port = self.topology.edges.get((s1, s2))["port_no"]
                p[s1] = (in_port, out_port)
                in_port = self.topology.edges.get((s2, s1))["port_no"]
            p[path[0][-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    @abstractmethod
    def get_status(self):
        pass

    def get_output_port_for_packet(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass

    def on_adding_auto_generated_flow(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass

    def before_adding_default_flow(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass

    def flow_is_deleted(self, dpid, flow_id, caller):
        pass

    def on_flow_added(self, event : FlowAddedEvent):
        pass
