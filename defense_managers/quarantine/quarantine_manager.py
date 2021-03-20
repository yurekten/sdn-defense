import logging
import os
from datetime import datetime
from typing import List

from ryu.lib import hub
from ryu.lib.packet import ether_types

from configuration import CONTROLLER_IP
from defense_managers.base_item_manager import ManagedItemManager
from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse, AddFlowAction, \
    ManagerResponse, ProcessResult

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
DEFAULT_IP_WHITELIST_FILE = os.path.join(CURRENT_PATH, "ip_whitelist.txt")
DEFAULT_IP_QUARANTINE_FILE = os.path.join(CURRENT_PATH, "ip_quarantine.txt")
ACCESSIBLE_SERVER_IP = "10.0.88.15"


class QuarantineManager(ManagedItemManager):

    def __init__(self, sdn_controller_app, enabled=True, max_managed_item_count=30000,
                 default_idle_timeout=0, item_whitelist_file=DEFAULT_IP_WHITELIST_FILE, default_priority =55000,
                 managed_item_file=DEFAULT_IP_QUARANTINE_FILE, accessible_server_ip=ACCESSIBLE_SERVER_IP, service_path_index=120):
        """
        :param sdn_controller_app: Ryu Controller App
        :param enabled: If True, managed item manager is enabled
        """
        name = "quarantine_manager"
        super(QuarantineManager, self).__init__(name, sdn_controller_app, enabled=enabled,
                                                 max_managed_item_count=max_managed_item_count,
                                                 default_idle_timeout=default_idle_timeout,
                                                 item_whitelist_file=item_whitelist_file,
                                                 managed_item_file=managed_item_file,
                                                 service_path_index=service_path_index)

        self.server_ip = accessible_server_ip
        self.server_dpid = None
        self.server_dpid_port = None
        self.server_eth_address = None
        self.priority = default_priority
        if self.enabled:
            hub.spawn(self._find_server)

    def _find_server(self):

        while self.server_dpid is None:
            dp_list = list(self.datapath_list.keys())
            if len(dp_list) > 0:
                dpid = dp_list[0]

                self.send_arp_request(dpid, CONTROLLER_IP, self.server_ip)
                logger.warning(f"{datetime.now()} - {self.name} - ARP request from {dpid} for {self.server_ip}")

            hub.sleep(1)

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return

        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port
        eth_src = request_ctx.params.src_eth

        if self.server_dpid is None:
            if src_ip == self.server_ip:
                self.server_dpid = dpid
                self.server_dpid_port = in_port
                self.server_eth_address = eth_src
                logger.warning(
                    f'{datetime.now()} - {self.name} - Server accessible in quarantine is connected to datapath {dpid} port {in_port}')
        else:
            self._apply_quarantine(request_ctx, response_ctx)

    def _apply_quarantine(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dst_dpid = request_ctx.params.dst_dpid
        dst_dpid_out_port = request_ctx.params.dst_dpid_out_port
        src_dpid = request_ctx.params.src_dpid
        src_in_port = request_ctx.params.in_port

        # if src  ip in managed ip list, decide to apply send to decoy
        # TODO: check dst ip later
        if src_ip in self.managed_item_list:

            if src_ip not in self.applied_item_list:
                self.applied_item_list[src_ip] = []

            src = self.host_ip_map[src_ip][2]
            h1 = self.hosts[src]
            # only source dpid is processed
            if h1[0] != src_dpid:
                return
            # TODO: Check IP changes port
            if src_ip in self.applied_item_list and len(self.applied_item_list[src_ip]) > 0:
                applied_rules = self.applied_item_list[src_ip]
                if (src_dpid, src_in_port) in applied_rules:
                    return

            #flow_tuple = (src_dpid, src_in_port, src_ip, dst_dpid, dst_dpid_out_port, dst_ip)
            if src_ip == self.server_ip or dst_ip == self.server_ip:
                manager_response = ManagerResponse(self, ProcessResult.CONTINUE)
            else:
                manager_response = ManagerResponse(self, ProcessResult.FINISH)
            flow = self.create_drop_rule(src_dpid, src_in_port, src_ip, self.priority, source_ip=True)
            manager_response.action_list.append(flow)


            flow = self.create_drop_rule(src_dpid, src_in_port, src_ip, self.priority, source_ip=False)
            manager_response.action_list.append(flow)

            flow = self.access_to_server_rule(src_dpid, src_in_port, src_ip, self.priority + 1, to_server=True)
            manager_response.action_list.append(flow)

            flow = self.access_to_server_rule(src_dpid, src_in_port, src_ip, self.priority + 1, to_server=False)
            manager_response.action_list.append(flow)
            self._add_ip_to_list(src_dpid, src_in_port, src_ip)

            response_ctx.add_response(self, manager_response)
    def access_to_server_rule(self, src_dpid, src_in_port, src_ip, priority, to_server):
        ofp_parser = self.datapath_list[src_dpid].ofproto_parser
        if to_server:
            match = ofp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=self.server_ip,
                in_port=src_in_port
            )
        else:
            match = ofp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=self.server_ip,
                ipv4_dst=src_ip
            )
        dp = self.datapath_list[src_dpid]
        if to_server:
            current_path = self.get_shortest_flow(src_dpid, src_in_port, self.server_dpid, self.server_dpid_port)
            output = current_path[src_dpid][1]
        else:
            output = src_in_port

        actions = [ofp_parser.OFPActionOutput(output)]
        ofproto = dp.ofproto

        new_flow = AddFlowAction(dp, priority, match, actions)
        new_flow.hard_timeout = 0
        new_flow.flags = ofproto.OFPFF_SEND_FLOW_REM
        new_flow.idle_timeout = self.default_idle_timeout
        new_flow.caller = self
        new_flow.manager = self
        # flow_id_result = self.sdn_controller_app.add_managed_flow(new_flow)
        # if not isinstance(flow_id_result, List):
        #     flow_id_result = [flow_id_result]
        #
        # for flow_id in flow_id_result:
        #     self.flow_id_path_dict[flow_id] = flow_tuple
        # # self.applied_item_list[src_ip].append((src_dpid, src_in_port))
        # self._add_ip_to_list(src_dpid, src_in_port, ip)
        return new_flow

    def create_drop_rule(self, src_dpid, src_in_port, ip, priority, source_ip=True):
        ofp_parser = self.datapath_list[src_dpid].ofproto_parser
        if source_ip:
            match = ofp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
                in_port=src_in_port
            )
        else:
            match = ofp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=ip
            )

        actions = []
        dp = self.datapath_list[src_dpid]
        ofproto = dp.ofproto

        new_flow = AddFlowAction(dp, priority, match, actions)
        new_flow.hard_timeout = 0
        new_flow.flags = ofproto.OFPFF_SEND_FLOW_REM
        new_flow.idle_timeout = self.default_idle_timeout
        new_flow.caller = self
        new_flow.manager = self
        # flow_id_result = self.sdn_controller_app.add_managed_flow(new_flow)
        # if not isinstance(flow_id_result, List):
        #     flow_id_result = [flow_id_result]
        #
        # for flow_id in flow_id_result:
        #     self.flow_id_path_dict[flow_id] = flow_tuple
        # # self.applied_item_list[src_ip].append((src_dpid, src_in_port))
        # self._add_ip_to_list(src_dpid, src_in_port, ip)
        return new_flow


    def flow_removed(self, msg):
        if not self.enabled:
            return
        if self.enabled and msg.cookie in self.flow_id_path_dict:
            nsh_si = None
            nsh_spi = None
            if "nsh_spi" in msg.match:
                nsh_spi = msg.match["nsh_spi"]
            if "nsh_si" in msg.match:
                nsh_si = msg.match["nsh_si"]

            if nsh_spi is not None and nsh_spi == self.spi:
                flow_tuple = self.flow_id_path_dict[msg.cookie]
                dpid = flow_tuple[0]
                in_port = flow_tuple[1]
                ip = flow_tuple[2]
                if ip in self.applied_item_list:
                    if (dpid, in_port) in self.applied_item_list[ip]:
                        if nsh_si and nsh_si == self.src_si:
                            logger.warning(
                                f"{datetime.now()} - {self.name} - Sent to decoy service is deleted for suspicious ip {ip} in {dpid} port {in_port}")
                        else:
                            logger.warning(
                                f"{datetime.now()} - {self.name} - Sent to decoy reverse service is deleted from {ip} to suspicious ip")
                        ind = self.applied_item_list[ip].index((dpid, in_port))
                        del self.applied_item_list[ip][ind]
                        if len(self.applied_item_list[ip]) == 0:
                            del self.applied_item_list[ip]
