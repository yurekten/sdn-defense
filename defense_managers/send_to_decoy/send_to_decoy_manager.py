import logging
import os
from datetime import datetime
from random import random
import csv
import time
from ryu.lib import hub

from configuration import CONTROLLER_IP
from defense_managers.base_item_manager import ManagedItemManager
from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger(__name__)
DEFAULT_IP_WHITELIST_FILE = os.path.join(CURRENT_PATH, "ip_whitelist.txt")
DEFAULT_IP_SUPICIOUS_FILE = os.path.join(CURRENT_PATH, "ip_suspicious.txt")
DECOY_IP_ADDRESS = "10.0.88.15"


class SendToDecoyManager(ManagedItemManager):

    def __init__(self, sdn_controller_app, enabled=True, max_managed_item_count=30000,
                 default_idle_timeout=100, item_whitelist_file=DEFAULT_IP_WHITELIST_FILE,
                 managed_item_file=DEFAULT_IP_SUPICIOUS_FILE, decoy_ip=DECOY_IP_ADDRESS, service_path_index=111,
                 default_priority=60000, random_ip_subnet="10.99.0.0"):
        """
        :param sdn_controller_app: Ryu Controller App
        :param enabled: If True, managed item manager is enabled
        """
        name = "send_to_decoy_manager"
        super(SendToDecoyManager, self).__init__(name, sdn_controller_app, enabled=enabled,
                                                 max_managed_item_count=max_managed_item_count,
                                                 default_idle_timeout=default_idle_timeout,
                                                 item_whitelist_file=item_whitelist_file,
                                                 managed_item_file=managed_item_file,
                                                 service_path_index=service_path_index, random_ip_subnet=random_ip_subnet)

        self.decoy_ip = decoy_ip
        self.decoy_dpid = None
        self.decoy_dpid_port = None
        self.decoy_eth_address = None
        self.default_priority = default_priority
        self.test_completed = False
        if self.enabled:
            hub.spawn(self._find_decoy)

    def _find_decoy(self):

        while self.decoy_dpid is None:
            dp_list = list(self.datapath_list.keys())
            if len(dp_list) > 0:
                dpid = dp_list[0]

                self.send_arp_request(dpid, CONTROLLER_IP, self.decoy_ip)
                logger.warning(f"{datetime.now()} - {self.name} - ARP request from {dpid} for {self.decoy_ip}")

            hub.sleep(1)

    def on_new_packet_detected(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse):
        if not self.enabled:
            return

        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dpid = request_ctx.params.src_dpid
        in_port = request_ctx.params.in_port
        eth_src = request_ctx.params.src_eth

        if self.decoy_dpid is None:
            if src_ip == self.decoy_ip:
                self.decoy_dpid = dpid
                self.decoy_dpid_port = in_port
                self.decoy_eth_address = eth_src
                logger.warning(
                    f'{datetime.now()} - {self.name} - Decoy is connected to datapath {dpid}, port {in_port}')
        else:
            self._send_to_decoy(request_ctx, response_ctx)
            # if self.test_completed:
            #     pass
            #     #self._send_to_decoy(request_ctx, response_ctx)
            # else:
            #     src_ip = request_ctx.params.src_ip
            #     src_dpid = request_ctx.params.src_dpid
            #     dst_dpid_out_port = request_ctx.params.dst_dpid_out_port
            #     src = self.host_ip_map[src_ip][2]
            #     h1 = self.hosts[src]
            #     # only source dpid is processed
            #     if src_ip in self.managed_item_list and dst_dpid_out_port is not None and h1[0] == src_dpid:
            #         self.calculate(request_ctx, response_ctx)
            #         self.test_completed = True

    def _send_to_decoy(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse, priority = None):
        if not self.enabled:
            return
        if priority is None:
            priority = self.default_priority
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        dst_dpid = request_ctx.params.dst_dpid
        dst_eth = request_ctx.params.dst_eth
        src_eth = request_ctx.params.src_eth
        dst_dpid_out_port = request_ctx.params.dst_dpid_out_port
        if dst_dpid_out_port is None:
            return
        # if src  ip in managed ip list, decide to apply send to decoy
        # TODO: check dst ip later
        if src_ip in self.managed_item_list:

            if src_ip not in self.applied_item_list:
                self.applied_item_list[src_ip] = []

            src_dpid = request_ctx.params.src_dpid
            src_in_port = request_ctx.params.in_port
            src = self.host_ip_map[src_ip][2]
            h1 = self.hosts[src]
            # only source dpid is processed
            if h1[0] != src_dpid:
                return
            # TODO: Check IP changes port
            if src_ip in self.applied_item_list and len(self.applied_item_list[src_ip]) > 0:
                applied_rules = self.applied_item_list[src_ip]
                if (src_dpid, src_in_port) in applied_rules and self.test_completed:
                    return

            nsh_spi = self.spi
            nsh_si = self.src_si
            self.create_flows(src_dpid, src_in_port, src_ip, self.decoy_dpid, self.decoy_dpid_port, dst_ip, src_eth, self.decoy_eth_address, nsh_spi, nsh_si, priority)
            nsh_si = self.src_si - 1
            #self.create_flows(src_dpid, src_in_port, src_ip, self.decoy_dpid, self.decoy_dpid_port, dst_ip, self.default_priority,
            #                  reverse=True)
            self.create_flows(self.decoy_dpid, self.decoy_dpid_port, self.decoy_ip, src_dpid, src_in_port, src_ip, self.decoy_eth_address, src_eth,
                              nsh_spi, nsh_si, priority)

            #self.create_flows(self.decoy_dpid, self.decoy_dpid_port, self.decoy_ip, dst_dpid, dst_dpid_out_port, dst_ip, nsh_spi, nsh_si, self.default_priority)
            #nsh_si = self.src_si - 2
            #self.create_flows(self.decoy_dpid, self.decoy_dpid_port, self.decoy_ip, src_dpid, src_in_port, src_ip, nsh_spi, nsh_si, self.default_priority,
            #                  reverse=True)



    def calculate(self, request_ctx, response_ctx):

        statistics = list()
        start = time.perf_counter()
        priority = self.default_priority
        for j in range(1, 401, 1):
            for i in range(1):
                priority = priority + 1
                self._send_to_decoy(request_ctx, response_ctx, priority)
            stop = time.perf_counter()
            statistics.append((j, (stop-start)*1000))

        with open('send-to-decoy-delay-time.csv', mode='w') as out_file:
            file_writer = csv.writer(out_file, delimiter='\t', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            for res in statistics:
                file_writer.writerow(list(res))

        print("send-to-decoy-delay-time.csv is created")

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
