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

IDS_IP = "10.0.88.18"
GATEWAY_IP = "10.0.88.17"
SOCKET_FILE = "/tmp/suricata_ids.socket"


class RerouteManager(BaseDefenseManager):

    def __init__(self, sdn_controller_app, reroute_enabled=True,
                 socket_file=SOCKET_FILE, ids_ip=IDS_IP, gateway_ip=GATEWAY_IP):

        now = int(datetime.now().timestamp())
        report_folder = "reroute-%d" % (now)
        name = "reroute_manager"
        super(RerouteManager, self).__init__(name, sdn_controller_app, reroute_enabled, report_folder)
        self.ids_ip = ids_ip
        self.gateway_ip = gateway_ip
        self.socket_file = socket_file
        self.ids_dpid = None
        self.ids_port_no = None

        self.applied_blacklist = {}
        self.statistics["applied_blacklist"] = {}
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
        logger.warning("............................................................................")
        logger.warning("Reroute manager enabled:  %s" % self.enabled)
        logger.warning("............................................................................")
        if reroute_enabled:
            hub.spawn(RerouteManager.listen_unix_stream, self.socket_file)

    @staticmethod
    def listen_unix_stream(socket_file):

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
                        data = RerouteManager.read_socket(connection)
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
            print(e)
            return None
        return result_list

    def get_status(self):
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "hit_count": self.statistics["hit_count"],
                "reset_time": datetime.fromtimestamp(self.statistics["reset_time"])
                }

    def new_packet_detected(self, msg, dpid, in_port, src_ip, dst_ip, eth_src, eth_dst):
        if src_ip == IDS_IP:
            if self.ids_dpid is None:
                self.ids_dpid = dpid
                self.ids_port_no = in_port

        return ProcessResult.IGNORE

    def _add_ip_to_blacklist(self, dpid, ip):
        pass

    def flow_removed(self, msg):
        if not self.enabled:
            return

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
