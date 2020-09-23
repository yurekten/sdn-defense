import logging
import os
import socket
import struct
from datetime import datetime
import random
from typing import List

from ryu.lib.packet import ether_types

from defense_managers.base_manager import BaseDefenseManager
from defense_managers.event_parameters import ProcessResult, SDNControllerRequest, SDNControllerResponse, \
    ManagerResponse, AddFlowAction
from utils.common_utils import is_valid_remote_ip, is_valid_ip

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
DEFAULT_WHITELIST_IP_FILE = os.path.join(CURRENT_PATH, "ip_whitelist.txt")
DEFAULT_MANAGED_IP_FILE = os.path.join(CURRENT_PATH, "ip_blacklist.txt")


class ManagedItemManager(BaseDefenseManager):

    def __init__(self, name, sdn_controller_app, enabled=True, max_managed_item_count=30000,
                 default_idle_timeout=100, item_whitelist_file=DEFAULT_WHITELIST_IP_FILE,
                 managed_item_file=DEFAULT_MANAGED_IP_FILE, service_path_index=100, random_ip_subnet="10.99.0.0"):
        """
        :param sdn_controller_app: Ryu Controller App
        :param blacklist_enabled: If True, managed item manager is enabled
        """
        now = datetime.now()
        report_folder = name + "-" + str(now.timestamp())

        super(ManagedItemManager, self).__init__(name, sdn_controller_app, enabled, report_folder)
        
        self.max_managed_item_count = max_managed_item_count
        self.item_whitelist_file = item_whitelist_file
        self.managed_item_file = managed_item_file
        self.default_idle_timeout = default_idle_timeout

        self.managed_item_list = {}
        self.applied_item_list = {}

        self.managed_paths = {}
        self.flow_id_path_dict = {}

        self.spi = service_path_index
        self.src_si = 50
        self.dst_si = 51
        
        self.applied_items = "applied_items"
        self.statistics[self.applied_items] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()

        self.random_ip_subnet = random_ip_subnet
        sub_address_nodes = random_ip_subnet.split(".")
        self.random_ip_subnet_prefix = sub_address_nodes[0] + "." + sub_address_nodes[1]

        logger.warning("............................................................................")
        if self.enabled:
            logger.warning(f"{now} - {self.name} is enabled")
        else:
            logger.warning(f"{now} - {self.name} is initiated but not enabled")

        self.whitelist = []
        self._initialize_whitelist()
        self._initialize_managed_items()

        if self.enabled:
            logger.warning(f"{now} - {self.name} - Max managed item count: {self.max_managed_item_count}")
            logger.warning(f"{now} - {self.name} - Default idle timeout: {self.default_idle_timeout}")
            logger.warning(f"{now} - {self.name} - Report folder: {self.report_folder}")
            logger.warning(f"{now} - {self.name} - Initial file: {self.managed_item_file}")
            logger.warning(f"{now} - {self.name} - Initial item count: {len(self.managed_item_list)}")

    def _initialize_whitelist(self):
        """
        Reads file from self.item_whitelist_file to exclude from managed_item_list.
        Lines of item_whitelist_file are like that:
        8.8.8.8,1,2
        1.1.1.1,1,2
        4.4.4.4,12,2
        """
        if self.enabled:
            with open(self.item_whitelist_file) as f:
                content = f.readlines()

            content = [x.strip() for x in content]
            for item in content:
                self.whitelist.append(item.strip())

    def _initialize_managed_items(self):
        """
        Reads file from self.managed_item_file and parse tuples. File content is like that.
        8.8.8.8,1,2
        1.1.1.1,1,2
        4.4.4.4,12,2
        ...
        Ip addresses that are not valid remote address or in whitelist are excuded.
        """
        if self.enabled:
            with open(self.managed_item_file) as f:
                content = f.readlines()

            content = [x.strip() for x in content]
            for item in content:
                ip_tuple = item.replace("(", "").replace(")", "").replace("'", "").replace(" ", "").split(",")
                ip = ip_tuple[0]

                if ip not in self.whitelist and is_valid_ip(ip):

                    if ip not in self.managed_item_list:
                        self.managed_item_list[ip] = {}

    def get_status(self):
        """
        :return: manager status dictianary
        """
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "max_managed_item_count": self.max_managed_item_count,
                "managed_item_list_count": len(self.managed_item_list),
                "applied_item_list_count": len(self.applied_item_list),
                "applied_item_list": self.applied_item_list,
                "hit_count": self.statistics["hit_count"],
                "reset_time": datetime.fromtimestamp(self.statistics["reset_time"])

                }


    def reset_statistics(self):

        super(ManagedItemManager, self).reset_statistics()
        self.statistics[self.applied_items] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()

    def create_flows(self, src_dpid_, src_in_port_, src_ip_, dst_dpid_, dst_dpid_port_, dst_ip_, priority, nsh_spi, nsh_si, reverse=False):
        if reverse:
            dst_dpid = src_dpid_
            dst_dpid_port = src_in_port_
            dst_ip = src_ip_
            src_dpid = dst_dpid_
            src_in_port = dst_dpid_port_
            src_ip = dst_ip_
            #nsh_si = self.dst_si
        else:
            src_dpid = src_dpid_
            src_in_port = src_in_port_
            src_ip = src_ip_
            dst_dpid = dst_dpid_
            dst_dpid_port = dst_dpid_port_
            dst_ip = dst_ip_
            #nsh_si = self.src_si

        flow_tuple = (src_dpid, src_in_port, src_ip, dst_dpid, dst_dpid_port, dst_ip)
        current_path = self.get_shortest_flow(src_dpid, src_in_port, dst_dpid, dst_dpid_port)


        #logger.error(f'{datetime.now()} - {self.name} - Path: {current_path})')

        self.managed_paths[flow_tuple] = current_path

        match_actions, src_ip, dst_ip = self._create_service_match_actions_for(current_path, src_ip, dst_ip,
                                                                               nsh_spi, nsh_si)
        first = None
        install_path_ordered = {}
        for node in current_path:
            if first is None:
                first = node
                continue
            install_path_ordered[node] = current_path[node]
        install_path_ordered[first] = current_path[first]
        for node in install_path_ordered:

            dp = self.datapath_list[node]
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            # in_port = install_path_ordered[node][0]
            # output_action = parser.OFPActionOutput(install_path_ordered[node][1])
            match = match_actions[node][0]
            actions = match_actions[node][1]

            new_flow = AddFlowAction(dp, priority, match, actions)
            new_flow.hard_timeout = 0
            new_flow.flags = ofproto.OFPFF_SEND_FLOW_REM
            new_flow.idle_timeout = self.default_idle_timeout
            new_flow.caller = self
            new_flow.manager = self

            flow_id_result = self.sdn_controller_app.flow_monitor.add_managed_flow(new_flow)
            if not isinstance(flow_id_result, List):
                flow_id_result = [flow_id_result]

            for flow_id in flow_id_result:
                self.flow_id_path_dict[flow_id] = flow_tuple
        # self.applied_item_list[src_ip].append((src_dpid, src_in_port))
        self._add_ip_to_list(src_dpid, src_in_port, src_ip)
        return  (src_ip, dst_ip)

    def ip2int(self, addr):
        result = struct.unpack("!I", socket.inet_aton(addr))[0]
        return result
    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))


    def create_random_ip(self):
        return self.random_ip_subnet_prefix + "." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))

    def _create_service_match_actions_for(self, path, src_ip, dst_ip, nsh_spi=100, nsh_si=255):
        match_actions = {}
        path_size = len(path)
        path_ind = -1
        original_src_ip = dst_ip
        original_dst_ip = None
        for node in path:
            path_ind = path_ind + 1
            dp = self.datapath_list[node]
            ofp_parser = dp.ofproto_parser


            in_port = path[node][0]
            output_action = ofp_parser.OFPActionOutput(path[node][1])
            if path_size > 1:
                if path_ind == 0:
                    #all flows from suspecious ip
                    if nsh_si == self.src_si:
                        match_ip = ofp_parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=src_ip,
                            in_port=in_port
                        )
                    else:
                        #only to suspecious ip
                        match_ip = ofp_parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            in_port=in_port
                        )
                    nsh_encap_action = ofp_parser.NXActionEncapNsh()
                    eth_encap_action = ofp_parser.NXActionEncapEther()
                    nsh_spi_action = ofp_parser.OFPActionSetField(nsh_spi=nsh_spi)
                    nsh_si_action = ofp_parser.OFPActionSetField(nsh_si=nsh_si)

                    nsh_c1_action = ofp_parser.OFPActionSetField(nsh_c1=self.ip2int(src_ip))
                    nsh_c2_action = ofp_parser.OFPActionSetField(nsh_c2=self.ip2int(dst_ip))

                    actions = [nsh_encap_action, nsh_spi_action, nsh_si_action, nsh_c1_action, nsh_c2_action, eth_encap_action, output_action]

                elif path_ind >= path_size - 1:
                    match_ip = ofp_parser.OFPMatch(eth_type_nxm=0x894f, nsh_spi=nsh_spi, nsh_si=nsh_si)

                    nsh_decap_action = ofp_parser.NXActionDecap()
                    eth_decap_action = ofp_parser.NXActionDecap()

                    actions = [nsh_decap_action, eth_decap_action, output_action]
                else:
                    match_ip = ofp_parser.OFPMatch(eth_type_nxm=0x894f, nsh_spi=nsh_spi, nsh_si=nsh_si)

                    actions = [output_action]
            else:
                if nsh_si == self.src_si:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        in_port=in_port
                    )
                else:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        in_port=in_port
                    )
                actions = [output_action]

            match_actions[node] = (match_ip, actions)

        return match_actions, src_ip, dst_ip

    def _add_ip_to_list(self, dpid, in_port, src_ip):
        ip = src_ip
        if ip not in self.applied_item_list:
            self.statistics[self.applied_items][ip] = {}
            self.applied_item_list[ip] = []
            self.statistics[self.applied_items] = {}
        if ip not in self.statistics[self.applied_items]:
            self.statistics[self.applied_items][ip] = {}
        if dpid not in self.statistics[self.applied_items][ip]:
            self.statistics[self.applied_items][ip][dpid] = {}
            self.statistics[self.applied_items][ip][dpid]["hit_count"] = 0
            self.statistics[self.applied_items][ip][dpid]["first_created_time"] = datetime.now().timestamp()
            self.statistics[self.applied_items][ip][dpid]["packet_count"] = 0
            self.statistics[self.applied_items][ip][dpid]["duration_sec"] = 0
            self.statistics[self.applied_items][ip][dpid]["last_delete_time"] = None

        if dpid not in self.applied_item_list[ip]:
            self.applied_item_list[ip].append((dpid, in_port))

        hit_count = self.statistics[self.applied_items][ip][dpid]["hit_count"]
        self.statistics[self.applied_items][ip][dpid]["hit_count"] = hit_count + 1

        #if logger.isEnabledFor(level=logging.ERROR):
        #    logger.warning(f"{datetime.now()} - {self.name} - Suspicious ip: {ip} in {dpid} port {in_port}")