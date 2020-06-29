from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime

from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse
from utils.file_utils import save_dict_to_file





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
    def get_output_port_for_packet(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        pass

    def on_new_packet_detected(self, request_ctx : SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass
    def on_adding_auto_generated_flow(self, request_ctx : SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass

    def before_adding_default_flow(self, request_ctx : SDNControllerRequest, response_ctx: SDNControllerResponse):
        pass

    def flow_is_deleted(self, dpid, flow_id, caller):
        pass
