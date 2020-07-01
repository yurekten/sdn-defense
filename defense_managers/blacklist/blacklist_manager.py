import logging
import os
from datetime import datetime

from ryu.lib.packet import ether_types

from defense_managers.base_manager import BaseDefenseManager
from defense_managers.blacklist.base_item_manager import ManagedItemManager
from defense_managers.event_parameters import ProcessResult, SDNControllerRequest, SDNControllerResponse, \
    ManagerResponse, AddFlowAction
from utils.common_utils import is_valid_remote_ip

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
DEFAULT_IP_WHITELIST_FILE = os.path.join(CURRENT_PATH, "ip_whitelist.txt")
DEFAULT_IP_BLACKLIST_FILE = os.path.join(CURRENT_PATH, "ip_blacklist.txt")




class BlacklistManager(ManagedItemManager):

    def __init__(self, sdn_controller_app, enabled=True, max_managed_item_count=30000,
                 default_idle_timeout=10, item_whitelist_file=DEFAULT_IP_WHITELIST_FILE, managed_item_file=DEFAULT_IP_BLACKLIST_FILE):
        """
        :param sdn_controller_app: Ryu Controller App
        :param enabled: If True, managed item manager is enabled
        """
        name = "blacklist_manager"
        super(BlacklistManager, self).__init__(name, sdn_controller_app, enabled=enabled,
                                               max_managed_item_count=max_managed_item_count,
                                               default_idle_timeout=default_idle_timeout,
                                               item_whitelist_file=item_whitelist_file,
                                               managed_item_file=managed_item_file)

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port

        if src_ip in self.managed_item_list or dst_ip in self.managed_item_list:
            parser = self.datapath_list[dpid].ofproto_parser

            priority = 60000
            dp = self.datapath_list[dpid]
            ofproto = dp.ofproto
            matches = []
            if src_ip in self.managed_item_list and (
                    src_ip not in self.applied_item_list or dpid not in self.applied_item_list[src_ip]):
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip
                )
                matches.append(match)
                self._add_ip_to_blacklist(dpid, src_ip)

            if dst_ip in self.managed_item_list and (
                    dst_ip not in self.applied_item_list or dpid not in self.applied_item_list[dst_ip]):
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=dst_ip
                )
                matches.append(match)
                self._add_ip_to_blacklist(dpid, dst_ip)

            if len(matches) > 0:
                self.statistics["hit_count"] = self.statistics["hit_count"] + 1
                manager_response = ManagerResponse(self, ProcessResult.FINISH)
                actions = []
                for match in matches:
                    response = AddFlowAction(dp, priority, match, actions, hard_timeout=0,
                                             idle_timeout=self.default_idle_timeout,
                                             flags=ofproto.OFPFF_SEND_FLOW_REM,
                                             caller=self, manager=self)
                    manager_response.action_list.append(response)

                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f'{self.name} - {match} will be inserted into {dpid}')

                response_ctx.add_response(self, manager_response)

    def _add_ip_to_blacklist(self, dpid, ip):
        if ip not in self.applied_item_list:
            self.statistics[self.applied_items][ip] = {}
            self.applied_item_list[ip] = []
        if dpid not in self.statistics[self.applied_items][ip]:
            self.statistics[self.applied_items][ip][dpid] = {}
            self.statistics[self.applied_items][ip][dpid]["hit_count"] = 0
            self.statistics[self.applied_items][ip][dpid]["first_created_time"] = datetime.now().timestamp()
            self.statistics[self.applied_items][ip][dpid]["packet_count"] = 0
            self.statistics[self.applied_items][ip][dpid]["duration_sec"] = 0
            self.statistics[self.applied_items][ip][dpid]["last_delete_time"] = None

        if dpid not in self.applied_item_list[ip]:
            self.applied_item_list[ip].append(dpid)

        hit_count = self.statistics[self.applied_items][ip][dpid]["hit_count"]
        self.statistics[self.applied_items][ip][dpid]["hit_count"] = hit_count + 1

        if logger.isEnabledFor(level=logging.WARNING):
            logger.warning(f"{datetime.now()} - {self.name} - blaclist ip: {ip} in {dpid}")

    def flow_removed(self, msg):

        if not self.enabled:
            return
        if self.enabled:
            dpid = msg.datapath.id

            if "ipv4_dst" in msg.match:
                ipv4_dst = msg.match["ipv4_dst"]

                if ipv4_dst in self.applied_item_list:
                    if dpid in self.applied_item_list[ipv4_dst]:
                        ind = self.applied_item_list[ipv4_dst].index(dpid)
                        if ind >= 0:
                            del self.applied_item_list[ipv4_dst][ind]
                    self.statistics[self.applied_items][ipv4_dst][dpid][
                        "last_delete_time"] = datetime.now().timestamp()
                    pkt_count = self.statistics[self.applied_items][ipv4_dst][dpid]["packet_count"]
                    self.statistics[self.applied_items][ipv4_dst][dpid]["packet_count"] = pkt_count + msg.packet_count
                    duration = self.statistics[self.applied_items][ipv4_dst][dpid]["duration_sec"]
                    self.statistics[self.applied_items][ipv4_dst][dpid]["duration_sec"] = duration + msg.duration_sec

                    logger.warning(
                        f"{datetime.now()} - {self.name} - {ipv4_dst} in {dpid} is removed from applied applied list.")