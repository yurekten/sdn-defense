import json
import logging
import pathlib
from collections import defaultdict
from datetime import datetime

from iptc.ip6tc import ip6tc
from ryu.lib.packet import ether_types

from defense_managers.base_manager import BaseDefenseManager, ProcessResult
from utils.file_utils import save_dict_to_file

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000

deafult_blacklist = ["10.0.88.3", "10.0.88.1"]

class BlacklistManager(BaseDefenseManager):


    def __init__(self, sdn_controller_app, blacklist_enabled=True):

        now = int(datetime.now().timestamp())
        report_folder = "blacklist-%d" % (now)
        name = "blacklist_manager"
        super(BlacklistManager, self).__init__(name, sdn_controller_app, blacklist_enabled, report_folder)

        self.max_blacklist_item_count = 10000
        self.blacklist = {}
        self.applied_blacklist = {}
        self.statistics["blacklist"] = self.blacklist
        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
        logger.warning("............................................................................")
        logger.warning("SDN CONTROLLER started - blacklist enabled:  %s" % self.enabled)

        if self.enabled:
            logger.warning("..... blacklist max item count  %s" % self.max_blacklist_item_count)
        logger.warning("............................................................................")

        self._initialize_blacklist()

    def _initialize_blacklist(self):
        if self.enabled:
            for item in deafult_blacklist:
                self.blacklist[item] = (0, None, None)


    def get_status(self):
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "current_blacklist_count": len(self.blacklist),
                "max_blacklist_item_count":self.max_blacklist_item_count,
                "hit_count":self.statistics["hit_count"],
                "reset_time":datetime.fromtimestamp(self.statistics["reset_time"])

                }

    def new_packet_detected(self, msg, dpid, in_port, src_ip, dst_ip, eth_src, eth_dst):
        if not self.enabled:
            return ProcessResult.IGNORE
        if src_ip in self.blacklist or dst_ip in self.blacklist:
            parser = self.datapath_list[dpid].ofproto_parser

            priority = 60000
            dp = self.datapath_list[dpid]
            ofproto = dp.ofproto
            matches = []
            if src_ip in self.blacklist and src_ip not in self.applied_blacklist:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip
                )
                matches.append(match)
                self._add_ip_to_blacklist(dpid, src_ip)

            if dst_ip in self.blacklist and dst_ip not in self.applied_blacklist:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=dst_ip
                )
                matches.append(match)
                self._add_ip_to_blacklist(dpid, dst_ip)

            if len(matches) > 0:
                self.statistics["hit_count"] = self.statistics["hit_count"] + 1
                actions = None
                hard_timeout = 10

                action_instructions = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                for match in matches:
                    flow_id = self.sdn_controller_app.add_flow(dp, priority,
                                                             match, actions,
                                                             hard_timeout=hard_timeout,
                                                             idle_timeout=0,
                                                             flags=ofproto.OFPFF_SEND_FLOW_REM,
                                                             instructions=action_instructions,
                                                             caller=self)

            return ProcessResult.FINISH
        return ProcessResult.CONTINUE

    def _add_ip_to_blacklist(self, dpid, ip):
        if ip not in self.statistics["applied_blacklist"]:
            self.statistics["applied_blacklist"][ip] = {}
            self.applied_blacklist[ip] = []
        if dpid not in self.statistics["applied_blacklist"][ip]:
            self.statistics["applied_blacklist"][ip][dpid] = {}
            self.statistics["applied_blacklist"][ip][dpid]["hit_count"] = 0
            self.statistics["applied_blacklist"][ip][dpid]["created_time"] = datetime.now().timestamp()
            self.statistics["applied_blacklist"][ip][dpid]["delete_time"] = None
            self.applied_blacklist[ip].append(dpid)

        hit_count = self.statistics["applied_blacklist"][ip][dpid]["hit_count"]
        self.statistics["applied_blacklist"][ip][dpid]["hit_count"] = hit_count + 1

        if logger.isEnabledFor(level=logging.WARNING):
            logger.warning(f"{datetime.now()} - Blacklist: {ip} in {dpid}")

    def flow_removed(self, msg):

        if not self.enabled:
            return
        ofproto = msg.datapath.ofproto
        if self.enabled:
            if msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
                ipv4_src = None
                ipv4_dst = None
                if "ipv4_src" in msg.match:
                    ipv4_src = msg.match["ipv4_src"]
                if "ipv4_dst" in msg.match:
                    ipv4_dst = msg.match["ipv4_dst"]


    def default_flow_will_be_added(self, datapath, src_ip, dst_ip, in_port, out_port):
        if not self.enabled:
            return

    def can_manage_flow(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return False

        if ip_src in self.blacklist or ip_dst in self.blacklist:
            return True
        else:
            return False

    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return None

        if ip_src in self.blacklist:
            return None

        return None

    def initiate_flow_manager_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if ip_src in self.blacklist or ip_dst in self.blacklist:

            parser = self.datapath_list[current_dpid].ofproto_parser
            ofproto = self.datapath_list[current_dpid].ofproto
            action_instructions = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

            return action_instructions
        return None

    def reset_statistics(self):
        super(BlacklistManager, self).reset_statistics()
        self.statistics["blacklist"] = self.blacklist
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
