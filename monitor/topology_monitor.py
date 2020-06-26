import logging
import pathlib
from collections import defaultdict
from datetime import datetime

import networkx as nx
from ryu.ofproto import ofproto_v1_3

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)


class TopologyMonitor(object):

    def __init__(self, *args, **kwargs):
        super(TopologyMonitor, self).__init__(*args, **kwargs)

        self.topology = nx.DiGraph()
        self.datapath_list = defaultdict()
        self.no_flood_ports = None

    def get_no_flood_ports(self):
        if self.no_flood_ports is None:
            self._recalculate_flood_ports()
        return self.no_flood_ports

    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Port Description Stats for Switch %s" % switch.id)
        if switch.id in self.topology.nodes:

            sw_ports = defaultdict()
            port_bandwidths = defaultdict()
            for port in ev.msg.body:
                sw_ports[port.port_no] = port
                max_bw = 0
                if port.state & 0x01 != 1:  # select port with status different than OFPPS_LINK_DOWN
                    if switch.ofproto.OFP_VERSION <= ofproto_v1_3.OFP_VERSION:
                        if max_bw < port.curr_speed:
                            max_bw = port.curr_speed
                        if logger.isEnabledFor(level=logging.DEBUG):
                            # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate
                            # type 0: ethernet 1: optical 0xFFFF: experimenter
                            logger.debug("Port:%s state:%s - current features=0x%x, current speed:%s kbps"
                                         % (port.port_no, port.state, port.curr, port.curr_speed,))
                    else:
                        for prop in port.properties:
                            # select maximum speed
                            if max_bw < prop.curr_speed:
                                max_bw = prop.curr_speed
                            if logger.isEnabledFor(level=logging.DEBUG):
                                # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate
                                # type 0: ethernet 1: optical 0xFFFF: experimenter
                                logger.debug("Port:%s type:%d state:%s - current features=0x%x, current speed:%s kbps"
                                             % (port.port_no, prop.type, port.state, prop.curr, prop.curr_speed,))
                port_bandwidths[port.port_no] = max_bw
            self.topology.nodes[switch.id]["port_desc_stats"] = sw_ports
            self.topology.nodes[switch.id]["port_bandwidths"] = port_bandwidths

    def _recalculate_flood_ports(self):
        nodes = list(self.topology.nodes)
        edges = list(self.topology.edges)
        graph = nx.Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)

        spanning_tree = nx.minimum_spanning_tree(graph)

        no_flood_links = list(set(graph.edges) - set(spanning_tree.edges))

        self.no_flood_ports = defaultdict()
        if len(no_flood_links) > 0:
            for link in no_flood_links:
                s1 = link[0]
                s2 = link[1]
                e1 = self.topology.edges.get((s1, s2))["port_no"]
                if s1 not in self.no_flood_ports:
                    self.no_flood_ports[s1] = set()
                self.no_flood_ports[s1].add(e1)

                e2 = self.topology.edges.get((s2, s1))["port_no"]
                if s2 not in self.no_flood_ports:
                    self.no_flood_ports[s2] = set()
                self.no_flood_ports[s2].add(e2)

            logger.warning(f"{datetime.now()} - Spanning tree is updated: %s" % dict(self.no_flood_ports))

    def switch_enter_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.info("Switch %s is entered" % ev.switch.dp.id)
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.topology.nodes:
            self.datapath_list[switch.id] = switch
            self.topology.add_node(switch.id, dp=switch)
            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    def link_delete_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        s1 = ev.link.src
        s2 = ev.link.dst
        if (s1.dpid, s2.dpid) in self.topology.edges:
            self.topology.remove_edge(s1.dpid, s2.dpid)
        if (s2.dpid, s1.dpid) in self.topology.edges:
            self.topology.remove_edge(s2.dpid, s1.dpid)

    def link_add_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        s1 = ev.link.src
        s2 = ev.link.dst
        self.topology.add_edge(s1.dpid, s2.dpid, port_no=s1.port_no)
        self.topology.add_edge(s2.dpid, s1.dpid, port_no=s2.port_no)
        if self.no_flood_ports is not None:
            self._recalculate_flood_ports()

    def port_status_handler(self, ev):
        if self.no_flood_ports is not None:
            self._recalculate_flood_ports()

    def switch_leave_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        switch_id = ev.switch.dp.id
        if switch_id in self.topology.nodes:
            self.topology.remove_node(switch_id)
