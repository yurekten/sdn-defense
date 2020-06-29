import datetime
import json
import logging
import os
import pathlib
import socket
from datetime import datetime

import networkx as nx
from ryu.lib import hub
from ryu.lib.packet import ether_types

from configuration import CONTROLLER_IP
from defense_managers.base_manager import BaseDefenseManager
from defense_managers.event_parameters import ProcessResult, SDNControllerRequest, SDNControllerResponse, \
    ManagerResponse, AddFlowAction
from utils.openflow_utils import build_arp_request

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)

IDS_IP = "10.0.88.17"
GATEWAY_IP = "10.0.88.18"
SOCKET_FILE = "/tmp/suricata_ids.socket"


class IDSBlacklistManager(BaseDefenseManager):

    def __init__(self, sdn_controller_app, ids_blacklist_enabled=True,
                 socket_file=SOCKET_FILE, ids_ip=IDS_IP, gateway_ip=GATEWAY_IP):

        now = datetime.now()
        report_folder = "ids_blacklist-%d" % int(now.timestamp())
        name = "ids_blacklist_manager"
        super(IDSBlacklistManager, self).__init__(name, sdn_controller_app, ids_blacklist_enabled, report_folder)
        self.ids_ip = ids_ip
        self.gateway_ip = gateway_ip
        self.socket_file = socket_file
        self.ids_dpid = None
        self.ids_port_no = None
        self.ids_eth_address = None
        self.ids_arp_request_count = 0
        self.gateway_dpid = None
        self.gateway_port_no = None
        self.gateway_eth_address = None
        self.gateway_arp_request_count = 0

        self.gateway_ids_path = []

        self.applied_blacklist = {}
        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()

        logger.warning("............................................................................")
        if self.enabled:
            logger.warning(f"{now} - {self.name} - ids_blacklist_manager is enabled")
        else:
            logger.warning(f"{now} - {self.name} - ids_blacklist_manager is initiated but not enabled")

        if self.enabled:
            logger.warning(f"{now} - {self.name} - IDS unix socket file: {self.socket_file}")
            logger.warning(f"{now} - {self.name} - IDS IP address: {self.ids_ip}")
            logger.warning(f"{now} - {self.name} - Gateway IP address: {self.gateway_ip}")

            hub.spawn(self.listen_unix_stream, self.socket_file)
            hub.spawn(self._find_ids_and_gateway)
        logger.warning("............................................................................")

    def listen_unix_stream(self, socket_file):

        if os.path.exists(socket_file):
            os.unlink(socket_file)

        with hub.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(socket_file)
            sock.listen(1)
            while True:
                connection = None
                try:
                    # Wait for a connection
                    logger.warning(f'{datetime.now()} - {self.name} - Waiting for IDS connection')
                    connection, client_address = sock.accept()
                    while True:
                        data = IDSBlacklistManager.read_socket(connection)
                        if data is not None:
                            for item in data:
                                print(f'{datetime.now()} -> {item}')

                finally:
                    if connection is not None:
                        # Clean up the connection
                        connection.close()

    @staticmethod
    def read_socket(socket):
        buffer = socket.recv(4096 * 2)
        buf_data = buffer.decode("utf-8").strip()
        data = buf_data.split('\n')

        result_list = []
        try:
            for d in data:
                if len(d) > 0:
                    json_data = json.loads(d)
                    result_list.append(json_data)
        except Exception as e:
            logger.warning(e)
            return None
        return result_list

    def get_status(self):
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "hit_count": self.statistics["hit_count"],
                "reset_time": datetime.fromtimestamp(self.statistics["reset_time"])
                }

    def _find_ids_and_gateway(self):

        while self.gateway_dpid is None:

            if self.ids_dpid is None:
                dp_list = list(self.datapath_list.keys())
                if len(dp_list) > 0:
                    dpid = dp_list[0]

                    self._send_arp_request(dpid, CONTROLLER_IP, self.ids_ip)
                    logger.warning(f"{datetime.now()} - {self.name} - ARP request for {self.ids_ip}")
            else:
                src_mac = self.ids_eth_address
                self._send_arp_request(self.ids_dpid, self.ids_ip, self.gateway_ip, self.ids_port_no, src_mac)
                logger.warning(f"{datetime.now()} - {self.name} - ARP request for {self.gateway_ip}")
            hub.sleep(1)

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return

        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port
        eth_src = request_ctx.params.src_eth

        if self.ids_dpid is None or self.gateway_dpid is None:
            if src_ip == IDS_IP:
                if self.ids_dpid is None:
                    self.ids_dpid = dpid
                    self.ids_port_no = in_port
                    self.ids_eth_address = eth_src
                    logger.warning(
                        f'{datetime.now()} - {self.name} - IDS is connected to datapath {dpid}, port {in_port}')

            if src_ip == GATEWAY_IP:
                if self.gateway_dpid is None:
                    self.gateway_dpid = dpid
                    self.gateway_port_no = in_port
                    self.gateway_eth_address = eth_src
                    logger.warning(
                        f'{datetime.now()} - {self.name} - Gateway is connected to datapath {dpid}, port {in_port}')

            if self.ids_dpid is not None and self.gateway_dpid is not None:
                path = nx.shortest_path(self.topology, source=self.gateway_dpid, target=self.ids_dpid)
                nodes = []
                for node in path:
                    nodes.append(node)
                self.gateway_ids_path = nodes
                logger.warning(f'{datetime.now()} - {self.name} - Path from gateway to ids {nodes}')

        self._send_to_ids_port(request_ctx, response_ctx)


    def _send_to_ids_port(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):

        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port
        eth_src = request_ctx.params.src_eth

        if self.ids_dpid is not None and self.gateway_dpid is not None:
            if self.gateway_dpid == dpid and self.ids_port_no != in_port:
                manager_response = ManagerResponse(self, ProcessResult.CONTINUE)
                parser = self.datapath_list[dpid].ofproto_parser

                priority = 60000
                dp = self.datapath_list[dpid]
                ofproto = dp.ofproto
                match = None
                actions = [parser.OFPActionOutput(self.ids_port_no)]
                response = AddFlowAction(dp, priority, match, actions, hard_timeout=0,
                                         idle_timeout=10,
                                         flags=ofproto.OFPFF_SEND_FLOW_REM,
                                         caller=self, manager=self)
                manager_response.action_list.append(response)

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f'Reroute to IDS {match} will be inserted into {dpid}')

                response_ctx.add_response(self, manager_response)

    def before_adding_default_flow(self, request_ctx : SDNControllerRequest, response_ctx: SDNControllerResponse):
        self._send_to_ids_port(request_ctx, response_ctx)

    def get_output_port_for_packet(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass


    def _send_arp_request(self, dpid, src_ip, dst_ip, in_port=None, src_mac=None):

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

    def flow_removed(self, msg):
        if not self.enabled:
            return


    def reset_statistics(self):
        super(IDSBlacklistManager, self).reset_statistics()
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
