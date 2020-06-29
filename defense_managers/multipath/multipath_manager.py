import logging
import os
from collections import defaultdict
from datetime import datetime
from threading import RLock

import networkx as nx

from defense_managers.base_manager import BaseDefenseManager
from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse
from defense_managers.multipath.flow_multipath_tracker import FlowMultipathTracker

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000

DEFAULT_TARGET_IP_LIST_FILE = os.path.join(CURRENT_PATH, "target_ip_list.txt")


class MultipathManager(BaseDefenseManager):

    def __init__(self, sdn_controller_app, multipath_enabled=True):

        now = datetime.now()
        report_folder = "multipath-%d" % int(now.timestamp())
        name = "multipath_manager"
        super(MultipathManager, self).__init__(name, sdn_controller_app, multipath_enabled, report_folder)

        self.activation_delay = 1  # (sec.) flow is checked after activation_delay to active multipath
        # After activation delay, Multipath starts if flow packet count is greater than min_packet_in_period
        self.min_packet_in_period = 10
        self.multipath_tracker_params = {
            # if multipath_enabled is enabled, it defines parameters of multipath trackers
            'forward_with_random_ip': True,  # random ip generation is activated.
            'random_ip_for_each_hop': False,  # if False, first node generates random ip
            'random_ip_subnet': "10.93.0.0",  # random ip subnet, default mask is 255.255.0.0
            'max_random_paths': 200,  # maximum random paths used in multipath trackers
            'max_installed_path_count': 2,  # maximum flow count installed in switch for each path
            'max_time_period_in_second': 2,  # random path expire time in seconds.
            'lowest_flow_priority': 20000,  # minimum flow priority in random path flows
        }

        logger.warning("............................................................................")
        if self.enabled:
            logger.warning(f"{now} - {self.name} - Multipath manager is enabled")
        else:
            logger.warning(f"{now} - {self.name} - Multipath manager is initiated but not enabled")

        if self.enabled:

            logger.warning(f"{now} - {self.name} - Multipath starts if activation_delay: {self.activation_delay}")
            logger.warning(f"{now} - {self.name} - Minimum period: {self.min_packet_in_period}")
            logger.warning(f"{now} - {self.name} - Start if min_packet count in period: {self.min_packet_in_period}")

            for key, value in self.multipath_tracker_params.items():
                logger.warning(f"{now} - {self.name} - {key}: {value}")
        self.watch_list = set()
        self.multipath_trackers = defaultdict()
        self.lock = RLock()
        self.all_possible_paths = {}
        self.target_ip_list_file = DEFAULT_TARGET_IP_LIST_FILE
        self.target_ip_list = {}
        self._initialize_target_ip_list()

    def _initialize_target_ip_list(self):
        """
        Reads file from self.ip_whitelist_file to exclude from blacklist.
        Lines of ip_whitelist_file are like that:
        8.8.8.8
        1.1.1.1
        4.4.4.4
        """
        if self.enabled:
            with open(self.target_ip_list_file) as f:
                content = f.readlines()

            content = [x.strip() for x in content]
            for item in content:
                self.target_ip_list[item.strip()] = {}

    def get_status(self):
        return {"multipath_enabled": self.enabled,
                "activation_delay": self.activation_delay,
                "min_packet_in_period": self.min_packet_in_period,
                "multipath_report_folder": self.report_folder,
                "multipath_tracker_params": self.multipath_tracker_params,
                "active_multipath_trackers_count": len(self.multipath_trackers),
                "active_multipath_trackers": list(self.multipath_trackers.keys()),
                "statistics_count": len(self.statistics)
                }

    def _start_multipath_tracker(self, ipv4_src, ipv4_dst):

        with self.lock:
            src = self.host_ip_map[ipv4_src][2]
            dst = self.host_ip_map[ipv4_dst][2]
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            # same switch
            if h1[0] == h2[0]:
                return

            if (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2]) in self.multipath_trackers:
                return

            dp_list = self.datapath_list

            multipath_tracker = FlowMultipathTracker(self, self.sdn_controller_app, dp_list, h1[0],
                                                     h1[1], h2[0], h2[1], h1[2], h2[2],
                                                     **self.multipath_tracker_params)
            self.multipath_trackers[multipath_tracker.flow_info] = multipath_tracker
            multipath_tracker.get_output_port_for_packet(dp_list[h1[0]])
            if logger.isEnabledFor(level=logging.WARNING):
                logger.warning(
                    f"{datetime.now()} - Initiate multipath tracker {multipath_tracker.flow_info} at {datetime.now()}")

    def multipath_tracker_is_destroying(self, flow):
        with self.lock:
            if flow.flow_info in self.multipath_trackers:
                stats = self.multipath_trackers[flow.flow_info].statistics
                key = ""
                for item in flow.flow_info:
                    key += str(item) + "_"
                self.statistics[key] = dict(stats)
                del self.multipath_trackers[flow.flow_info]
                if logger.isEnabledFor(level=logging.WARNING):
                    logger.warning(
                        f"{datetime.now()} - Terminate multipath tracker {flow.flow_info}  at {datetime.now()}")

    def get_output_port_for_packet(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return None
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.multipath_trackers:
            multipath_tracker = self.multipath_trackers[(src, first_port, dst, last_port, ip_src, ip_dst)]
            output_port = multipath_tracker.get_output_port_for_packet(current_dpid)
            return output_port
        return None

    def before_adding_default_flow(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return

        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port
        out_ports = request_ctx.params.out_port
        if src_ip in self.target_ip_list or dst_ip in self.target_ip_list:

            if src_ip in self.host_ip_map and dst_ip in self.host_ip_map:

                src = self.host_ip_map[src_ip][2]
                dst = self.host_ip_map[dst_ip][2]
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                # same switch, ignore
                if h1[0] == h2[0]:
                    return
                flow_tuple = (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2])
                if flow_tuple in self.multipath_trackers:
                    tracker = self.multipath_trackers[flow_tuple]
                    if tracker.get_status() == FlowMultipathTracker.ACTIVE or tracker.get_status() == FlowMultipathTracker.INITIATED:
                        return

                if flow_tuple in self.watch_list:
                    return

                ofproto = self.datapath_list[dpid].ofproto
                priority = 3
                flags = ofproto.OFPFF_SEND_FLOW_REM
                hard_timeout = self.activation_delay
                idle_timeout = 0

                flow_id = self.sdn_controller_app.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_ports,
                                                                           priority, flags,
                                                                           hard_timeout, idle_timeout, self, self,
                                                                           request_ctx, response_ctx)
                self.watch_list.add(flow_id)
                # flow_id = self.sdn_controller_app.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_ports, priority, flags,
                #                                                  hard_timeout + 1, idle_timeout, self, self)

                flow_id = self.sdn_controller_app.create_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, out_ports,
                                                                           priority, flags,
                                                                           hard_timeout, idle_timeout, self, self,
                                                                           request_ctx, response_ctx)
                self.watch_list.add(flow_id)
                # flow_id = self.sdn_controller_app.create_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, out_ports, priority, flags,
                #                                                  hard_timeout + 1, idle_timeout, self, self)
                # self.watch_list.add(flow_id)

    # def default_flow_will_be_added(self, datapath, src_ip, dst_ip, in_port, out_ports):
    #     if not self.enabled:
    #         return
    #     if self.enabled and src_ip in self.host_ip_map and dst_ip in self.host_ip_map:
    #
    #         src = self.host_ip_map[src_ip][2]
    #         dst = self.host_ip_map[dst_ip][2]
    #         h1 = self.hosts[src]
    #         h2 = self.hosts[dst]
    #         # same switch, ignore
    #         if h1[0] == h2[0]:
    #             return
    #         if (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2]) in self.multipath_trackers:
    #             tracker = self.multipath_trackers[(h1[0], h1[1], h2[0], h2[1], h1[2], h2[2])]
    #             if tracker.get_status() == FlowMultipathTracker.ACTIVE:
    #                 return
    #
    #         ofproto = datapath.ofproto
    #         dpid = datapath.id
    #         priority = 3
    #         flags = ofproto.OFPFF_SEND_FLOW_REM
    #         hard_timeout = self.activation_delay
    #         idle_timeout = 0
    #         self.sdn_controller_app.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_ports, priority, flags,
    #                                                          hard_timeout, idle_timeout, self, self)
    #         self.sdn_controller_app.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_ports, priority, flags,
    #                                                          hard_timeout + 1, idle_timeout, self, self)
    #         self.sdn_controller_app.create_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, out_ports, priority, flags,
    #                                                          hard_timeout, idle_timeout, self, self)
    #         self.sdn_controller_app.create_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, out_ports, priority, flags,
    #                                                          hard_timeout + 1, idle_timeout, self, self)

    def flow_removed(self, msg):
        if not self.enabled:
            return
        if self.enabled and msg.cookie in self.watch_list:
            ipv4_src = None
            ipv4_dst = None
            if "ipv4_src" in msg.match:
                ipv4_src = msg.match["ipv4_src"]
            if "ipv4_dst" in msg.match:
                ipv4_dst = msg.match["ipv4_dst"]

            src = self.host_ip_map[ipv4_src][2]
            dst = self.host_ip_map[ipv4_dst][2]
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if ipv4_src is not None and ipv4_dst is not None:
                if (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2]) in self.multipath_trackers:
                    return
                if msg.packet_count > self.min_packet_in_period:
                    self._start_multipath_tracker(ipv4_src, ipv4_dst)
            self.watch_list.remove(msg.cookie)

    # not used not, may be soon
    def _request_flow_packet_count(self, in_port, dst, src, datapath_id):
        datapath = self.datapath_list[datapath_id]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    def get_all_possible_paths(self, src, dst):

        if (src, dst) in self.all_possible_paths:
            return self.all_possible_paths[(src, dst)]

        # start = time.perf_counter()
        if src == dst:
            if logger.isEnabledFor(level=logging.DEBUG):
                logger.debug(f"Path selection is completed. src and dst is in same datapath")
            # host target is on the same switch
            return [([src], 1)]

        path_results = nx.all_simple_paths(self.topology, source=src, target=dst, cutoff=16)

        paths = []
        for path in path_results:
            paths.append(path)

        selected_paths = MultipathManager.select_superset_paths(paths)
        all_paths = []
        for path in selected_paths:
            path_cost = self._get_path_cost(path)
            all_paths.append((path, path_cost))

        self.all_possible_paths[(src, dst)] = all_paths

        return self.all_possible_paths[(src, dst)]

    @staticmethod
    def select_superset_paths(paths):
        selected_paths = paths[:]
        # select only subset paths, eliminate paths contains others
        for x in paths:
            superset = []
            for y in selected_paths:
                if set(x) < set(y):
                    superset.append(y)
            for deleted_item in superset:
                ind = selected_paths.index(deleted_item)
                del selected_paths[ind]

        return selected_paths

    def _get_path_cost(self, path):
        """
        Get the path cost
        """
        path_cost = 0
        for i in range(len(path) - 1):
            s1 = path[i]
            s2 = path[i + 1]
            e1 = self.topology.edges.get((s1, s2))["port_no"]
            e2 = self.topology.edges.get((s2, s1))["port_no"]
            bw1 = self.topology.nodes[s1]["port_bandwidths"][e1]
            bw2 = self.topology.nodes[s2]["port_bandwidths"][e2]
            bw_low = min(bw1, bw2)
            link_cost = int(REFERENCE_BW / bw_low)
            path_cost += link_cost

        return path_cost

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
