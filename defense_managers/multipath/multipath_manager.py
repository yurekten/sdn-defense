import json
import logging
import os
import pathlib
import subprocess
from collections import defaultdict
from datetime import datetime
from threading import RLock

from defense_managers.multipath.flow_multipath_tracker import FlowMultipathTracker
from utils.file_utils import save_dict_to_file

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)

class MultipathManager():

    def __init__(self, sdn_controller_app):
        self.sdn_controller_app = sdn_controller_app

        self.multipath_enabled = True  # If True, multipath functions enabled else, all switches work as L2 switch

        now = int(datetime.now().timestamp())
        self.multipath_report_folder = "multipath-%d" % (now)
        self.statistics = defaultdict()
        self.activation_delay = 1  # (sec.) flow is checked after activation_delay to active multipath
        self.min_packet_in_period = 10  # After activation delay, Multipath starts if flow packet count is greater than min_packet_in_period
        self.multipath_tracker_params = {  # if multipath_enabled is enabled, it defines parameters of multipath trackers
            'forward_with_random_ip': True,  # random ip generation is activated.
            'random_ip_for_each_hop': True,  # if False, first node generates random ip
            'random_ip_subnet': "10.93.0.0",  # random ip subnet, default mask is 255.255.0.0
            'max_random_paths': 200,  # maximum random paths used in multipath trackers
            'max_installed_path_count': 2,  # maximum flow count installed in switch for each path
            'max_time_period_in_second': 2,  # random path expire time in seconds.
            'lowest_flow_priority': 20000,  # minimum flow priority in random path flows
            'report_folder': self.multipath_report_folder
        }
        logger.warning("............................................................................")
        logger.warning("SDN CONTROLLER started - multipath enabled:  %s" % self.multipath_enabled)

        if self.multipath_enabled:
            logger.warning("..... multipath starts if activation_delay    :  %s" % self.activation_delay)
            logger.warning("..... multipath starts if min_packet_in_period:  %s" % self.min_packet_in_period)
            params = json.dumps(self.multipath_tracker_params, indent=4, separators=(',', '= '))
            logger.warning("..... multipath tracker params: \n%s" % params)

        logger.warning("............................................................................")

        self.multipath_trackers = defaultdict()

        self.lock = RLock()

        self.host_ip_map = self.sdn_controller_app.host_ip_map
        self.hosts = self.sdn_controller_app.hosts
        self.topology = self.sdn_controller_app.topology
        self.datapath_list = self.sdn_controller_app.datapath_list
        self.flow_coordinator = self.sdn_controller_app

    def get_statistics(self):
        return self.statistics

    def reset_statistics(self):
        self.statistics.clear()

    def get_status(self):
        return {"multipath_enabled":self.multipath_enabled,
                "activation_delay":self.activation_delay,
                "min_packet_in_period":self.min_packet_in_period,
                "multipath_report_folder": self.multipath_report_folder,
                "multipath_tracker_params":self.multipath_tracker_params,
                "active_multipath_trackers_count": len(self.multipath_trackers),
                "active_multipath_trackers": list(self.multipath_trackers.keys()),
                "statistics_count": len(self.statistics)
                }

    def save_statistics(self):
        now = int(datetime.now().timestamp())
        file_name = "%s-multipath-flow-stats.json" % (now)
        return save_dict_to_file(self.multipath_report_folder, file_name, self.statistics)


    def _start_multipath_tracker(self, ipv4_src, ipv4_dst):

        with self.lock:
            src = self.host_ip_map[ipv4_src][2]
            dst = self.host_ip_map[ipv4_dst][2]
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            #same switch
            if h1[0] == h2[0]:
                return

            if (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2]) in self.multipath_trackers:
                return

            dp_list = self.datapath_list

            multipath_tracker = FlowMultipathTracker(self, self.sdn_controller_app, self.topology, dp_list, h1[0], h1[1], h2[0], h2[1], h1[2], h2[2],
                                                **self.multipath_tracker_params)
            self.multipath_trackers[multipath_tracker.flow_info] = multipath_tracker
            multipath_tracker.get_active_path_port_for(dp_list[h1[0]])
            if logger.isEnabledFor(level=logging.WARNING):
                logger.warning(f"{datetime.now()} - Initiate multipath tracker {multipath_tracker.flow_info} at {datetime.now()}")

    def multipath_tracker_is_destroying(self, flow):
        with self.lock:
            if flow.flow_info in self.multipath_trackers:
                stats = self.multipath_trackers[flow.flow_info].statistics
                self.statistics[flow.flow_info] = stats
                del self.multipath_trackers[flow.flow_info]
                if logger.isEnabledFor(level=logging.WARNING):
                    logger.warning(f"{datetime.now()} - Terminate multipath tracker {flow.flow_info}  at {datetime.now()}")

    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.multipath_trackers:
            multipath_tracker = self.multipath_trackers[(src, first_port, dst, last_port, ip_src, ip_dst)]
            output_port = multipath_tracker.get_active_path_port_for(current_dpid)
            return output_port
        return None


    def default_flow_will_be_added(self, datapath, src_ip, dst_ip, in_port, out_port):
        if self.multipath_enabled:
            src = self.host_ip_map[src_ip][2]
            dst = self.host_ip_map[dst_ip][2]
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            #same switch, ignore
            if h1[0] == h2[0]:
                return

            ofproto = datapath.ofproto
            dpid = datapath.id
            priority = 3
            flags = ofproto.OFPFF_SEND_FLOW_REM
            hard_timeout = self.activation_delay
            idle_timeout = 0
            self.sdn_controller_app.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, out_port, priority, flags,
                                           hard_timeout, idle_timeout)
            self.sdn_controller_app.create_rule_if_not_exist(dpid, dst_ip, src_ip, out_port, in_port, priority, flags,
                                           hard_timeout, idle_timeout)

    def flow_removed(self, msg):
        ofproto = msg.datapath.ofproto
        if self.multipath_enabled:
            if msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
                if msg.packet_count > self.min_packet_in_period:
                    ipv4_src = None
                    ipv4_dst = None
                    if "ipv4_src" in msg.match:
                        ipv4_src = msg.match["ipv4_src"]
                    if "ipv4_dst" in msg.match:
                        ipv4_dst = msg.match["ipv4_dst"]

                    if ipv4_src is not None and ipv4_dst is not None:
                        self._start_multipath_tracker(ipv4_src, ipv4_dst)

    #not used not, may be soon
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
