import logging
import os
from datetime import datetime

from ryu.lib.packet import ether_types

from defense_managers.base_manager import BaseDefenseManager
from defense_managers.event_parameters import ProcessResult, SDNControllerRequest, SDNControllerResponse, \
    ManagerResponse, AddFlowAction
from utils.common_utils import is_valid_remote_ip

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
DEFAULT_IP_WHITELIST_FILE = os.path.join(CURRENT_PATH, "ip_whitelist.txt")
DEFAULT_IP_BLACKLIST_FILE = os.path.join(CURRENT_PATH, "ip_blacklist.txt")


class BlacklistManager(BaseDefenseManager):

    def __init__(self, sdn_controller_app, blacklist_enabled=True, max_blacklist_item_count=30000,
                 blacklist_idle_timeout=10,
                 ip_whitelist_file=DEFAULT_IP_WHITELIST_FILE, ip_blacklist_file=DEFAULT_IP_BLACKLIST_FILE):
        """
        :param sdn_controller_app: Ryu Controller App
        :param blacklist_enabled: If True, blacklist is enabled
        """
        now = datetime.now()
        report_folder = "blacklist-%d" % int(now.timestamp())
        name = "blacklist_manager"
        super(BlacklistManager, self).__init__(name, sdn_controller_app, blacklist_enabled, report_folder)

        self.max_blacklist_item_count = max_blacklist_item_count
        self.ip_whitelist_file = ip_whitelist_file
        self.ip_blacklist_file = ip_blacklist_file
        self.blacklist_idle_timeout = blacklist_idle_timeout

        self.blacklist = {}
        self.applied_blacklist = {}

        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()

        logger.warning("............................................................................")
        if self.enabled:
            logger.warning(f"{now} - {self.name} - Blacklist manager is enabled")
        else:
            logger.warning(f"{now} - {self.name} - Blacklist manager is initiated but not enabled")

        self.whitelist = []
        self._initialize_whitelist()
        self._initialize_blacklist()

        if self.enabled:
            logger.warning(f"{now} - {self.name} - Blacklist max item count: {self.max_blacklist_item_count}")
            logger.warning(f"{now} - {self.name} - Blacklist idle timeout: {self.blacklist_idle_timeout}")
            logger.warning(f"{now} - {self.name} - Blacklist report folder: {self.report_folder}")
            logger.warning(f"{now} - {self.name} - Initial blacklist file: {self.ip_blacklist_file}")
            logger.warning(f"{now} - {self.name} - Initial blacklist item count: {len(self.blacklist)}")

    def _initialize_whitelist(self):
        """
        Reads file from self.ip_whitelist_file to exclude from blacklist.
        Lines of ip_whitelist_file are like that:
        8.8.8.8
        1.1.1.1
        4.4.4.4
        """
        if self.enabled:
            with open(self.ip_whitelist_file) as f:
                content = f.readlines()

            content = [x.strip() for x in content]
            for item in content:
                self.whitelist.append(item.strip())

    def _initialize_blacklist(self):
        """
        Reads file from self.ip_blacklist_file and parse tuples. File content is like that.
        ('xyz', '1.2.3.4')
        ('abc.com', '12.21.32.42')
        ...
        Ip addresses that are not valid remote address or in whitelist are excuded.
        """
        if self.enabled:
            with open(self.ip_blacklist_file) as f:
                content = f.readlines()

            content = [x.strip() for x in content]
            for item in content:
                ip_tuple = item.replace("(", "").replace(")", "").replace("'", "").replace(" ", "").split(",")
                ip = ip_tuple[1]
                url = ip_tuple[0]

                if ip not in self.whitelist and is_valid_remote_ip(ip):

                    if ip not in self.blacklist:
                        self.blacklist[ip] = {}

                    if "url" not in self.blacklist[ip]:
                        self.blacklist[ip]["url"] = set()

                    self.blacklist[ip]["url"].add(url)

    def get_status(self):
        """
        :return: manager status dictianary
        """
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "max_blacklist_item_count": self.max_blacklist_item_count,
                "current_blacklist_count": len(self.blacklist),
                "applied_blacklist_count": len(self.applied_blacklist),
                "applied_blacklist": self.applied_blacklist,
                "hit_count": self.statistics["hit_count"],
                "reset_time": datetime.fromtimestamp(self.statistics["reset_time"])

                }

    def get_output_port_for_packet(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port

        if src_ip in self.blacklist or dst_ip in self.blacklist:
            parser = self.datapath_list[dpid].ofproto_parser

            priority = 60000
            dp = self.datapath_list[dpid]
            ofproto = dp.ofproto
            matches = []
            if src_ip in self.blacklist and (
                    src_ip not in self.applied_blacklist or dpid not in self.applied_blacklist[src_ip]):
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip
                )
                matches.append(match)
                self._add_ip_to_blacklist(dpid, src_ip)

            if dst_ip in self.blacklist and (
                    dst_ip not in self.applied_blacklist or dpid not in self.applied_blacklist[dst_ip]):
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
                                             idle_timeout=self.blacklist_idle_timeout,
                                             flags=ofproto.OFPFF_SEND_FLOW_REM,
                                             caller=self, manager=self)
                    manager_response.action_list.append(response)

                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f'Blacklist {match} will be inserted into {dpid}')

                response_ctx.add_response(self, manager_response)

    def _add_ip_to_blacklist(self, dpid, ip):
        if ip not in self.applied_blacklist:
            self.statistics["applied_blacklist"][ip] = {}
            self.applied_blacklist[ip] = []
        if dpid not in self.statistics["applied_blacklist"][ip]:
            self.statistics["applied_blacklist"][ip][dpid] = {}
            self.statistics["applied_blacklist"][ip][dpid]["hit_count"] = 0
            self.statistics["applied_blacklist"][ip][dpid]["first_created_time"] = datetime.now().timestamp()
            self.statistics["applied_blacklist"][ip][dpid]["packet_count"] = 0
            self.statistics["applied_blacklist"][ip][dpid]["duration_sec"] = 0
            self.statistics["applied_blacklist"][ip][dpid]["last_delete_time"] = None

        if dpid not in self.applied_blacklist[ip]:
            self.applied_blacklist[ip].append(dpid)

        hit_count = self.statistics["applied_blacklist"][ip][dpid]["hit_count"]
        self.statistics["applied_blacklist"][ip][dpid]["hit_count"] = hit_count + 1

        if logger.isEnabledFor(level=logging.WARNING):
            logger.warning(f"{datetime.now()} - {self.name} - Blacklist: {ip} in {dpid}")

    def flow_removed(self, msg):

        if not self.enabled:
            return
        if self.enabled:
            dpid = msg.datapath.id

            if "ipv4_dst" in msg.match:
                ipv4_dst = msg.match["ipv4_dst"]

                if ipv4_dst in self.applied_blacklist:
                    if dpid in self.applied_blacklist[ipv4_dst]:
                        ind = self.applied_blacklist[ipv4_dst].index(dpid)
                        if ind >= 0:
                            del self.applied_blacklist[ipv4_dst][ind]
                    self.statistics["applied_blacklist"][ipv4_dst][dpid][
                        "last_delete_time"] = datetime.now().timestamp()
                    pkt_count = self.statistics["applied_blacklist"][ipv4_dst][dpid]["packet_count"]
                    self.statistics["applied_blacklist"][ipv4_dst][dpid]["packet_count"] = pkt_count + msg.packet_count
                    duration = self.statistics["applied_blacklist"][ipv4_dst][dpid]["duration_sec"]
                    self.statistics["applied_blacklist"][ipv4_dst][dpid]["duration_sec"] = duration + msg.duration_sec

                    logger.warning(
                        f"{datetime.now()} - {self.name} - {ipv4_dst} in {dpid} is removed from applied blacklist.")

    def reset_statistics(self):

        super(BlacklistManager, self).reset_statistics()
        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
