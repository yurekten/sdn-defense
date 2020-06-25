from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from enum import Enum

from utils.file_utils import save_dict_to_file


class ProcessResult(Enum):
    IGNORE = 0,
    CONTINUE = 1,
    FINISH = 2,


class BaseDefenseManager(ABC):

    def __init__(self, name, sdn_controller_app, enabled, report_folder):
        self.name = name
        self.sdn_controller_app = sdn_controller_app
        self.enabled = enabled
        self.report_folder = report_folder
        self.statistics = defaultdict()
        self.host_ip_map = self.sdn_controller_app.host_ip_map
        self.hosts = self.sdn_controller_app.hosts
        self.topology = self.sdn_controller_app.topology
        self.datapath_list = self.sdn_controller_app.datapath_list

    def get_statistics(self):
        return self.statistics

    def reset_statistics(self):
        self.statistics.clear()

    def save_statistics(self):
        now = int(datetime.now().timestamp())
        file_name = "%s-stats.json" % (now)
        return save_dict_to_file(self.report_folder, file_name, self.statistics)

    @abstractmethod
    def get_status(self):
        pass

    @abstractmethod
    def can_manage_flow(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    @abstractmethod
    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    @abstractmethod
    def new_packet_detected(self, msg, dpid, in_port, src_ip, dst_ip, eth_src, eth_dst):
        pass

    @abstractmethod
    def initiate_flow_manager_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    @abstractmethod
    def default_flow_will_be_added(self, datapath, src_ip, dst_ip, in_port, out_port):
        pass
