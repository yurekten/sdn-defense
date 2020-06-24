import datetime
import json
import logging
import os
import pathlib
import socket
from datetime import datetime

from ryu.lib import hub

from defense_managers.base_manager import BaseDefenseManager, ProcessResult

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000

SOCKFILE = "/tmp/suricata_ids.socket"

class RerouteManager(BaseDefenseManager):


    def __init__(self, sdn_controller_app, reroute_enabled=True, ):

        now = int(datetime.now().timestamp())
        report_folder = "reroute-%d" % (now)
        name = "reroute_manager"
        super(RerouteManager, self).__init__(name, sdn_controller_app, reroute_enabled, report_folder)
        self.reroute_target = []

        self.applied_blacklist = {}
        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
        logger.warning("............................................................................")
        logger.warning("Reroute manager enabled:  %s" % self.enabled)
        logger.warning("............................................................................")
        if reroute_enabled:
            hub.spawn(self._listen_unix_stream(SOCKFILE))

    def _listen_unix_stream(self, socket_file):

        if os.path.exists(socket_file):
            os.unlink(socket_file)

        with hub.socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(socket_file)
            sock.listen(1)
            while True:
                connection = None
                try:
                    # Wait for a connection
                    print('Waiting for a connection')
                    connection, client_address = sock.accept()
                    while True:
                        data = self._read_socket(connection)
                        if data is not None:
                            for item in data:
                                print(f'{datetime.now()} -> {item}')

                finally:
                    if connection is not None:
                        # Clean up the connection
                        connection.close()

    def _read_socket(self, socket):
        buffer = socket.recv(4096 * 2)
        buf_data = buffer.decode("utf-8").strip()
        data = buf_data.split('\n')

        result_list = []
        try:
            for d in data:
                json_data = json.loads(d)
                result_list.append(json_data)
        except Exception as e:
            print(e)
            return None
        return result_list

    def get_status(self):
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "hit_count":self.statistics["hit_count"],
                "reset_time":datetime.fromtimestamp(self.statistics["reset_time"])
                }

    def new_packet_detected(self, msg, dpid, in_port, src_ip, dst_ip, eth_src, eth_dst):
        return ProcessResult.IGNORE

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

        return False

    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return None

        return None

    def initiate_flow_manager_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        return None

    def reset_statistics(self):
        super(RerouteManager, self).reset_statistics()
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
