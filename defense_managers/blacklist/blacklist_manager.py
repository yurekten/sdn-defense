import json
import logging
import pathlib
from collections import defaultdict
from datetime import datetime

from iptc.ip6tc import ip6tc

from defense_managers.base_manager import BaseDefenseManager
from utils.file_utils import save_dict_to_file

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000

deafult_blacklist = ["10.0.88.3", "10.0.88.1"]

class BlacklistManager(BaseDefenseManager):


    def __init__(self, sdn_controller_app, blacklist_enabled=True):

        now = int(datetime.now().timestamp())
        report_folder = "blacklist-%d" % (now)
        name = "blacklist_manager"
        super(BlacklistManager, self).__init__(name, sdn_controller_app, blacklist_enabled, report_folder)

        self.max_blacklist_item_count = 10000
        self.blacklist = {}

        self.statistics["blacklist"] = self.blacklist
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
        logger.warning("............................................................................")
        logger.warning("SDN CONTROLLER started - blacklist enabled:  %s" % self.enabled)

        if self.enabled:
            logger.warning("..... blacklist max item count  %s" % self.max_blacklist_item_count)
        logger.warning("............................................................................")

        self._initialize_blacklist()

    def _initialize_blacklist(self):
        if self.enabled:
            for item in deafult_blacklist:
                self.blacklist[item] = (0, None, None)


    def get_status(self):
        return {"enabled": self.enabled,
                "report_folder": self.report_folder,
                "current_blacklist_count": len(self.blacklist),
                "max_blacklist_item_count":self.max_blacklist_item_count,
                "hit_count":self.statistics["hit_count"],
                "reset_time":datetime.fromtimestamp(self.statistics["reset_time"])

                }

    def default_flow_will_be_added(self, datapath, src_ip, dst_ip, in_port, out_port):
        if not self.enabled:
            return

    def can_manage_flow(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return False

        if ip_src in self.blacklist or ip_dst in self.blacklist:
            return True
        else:
            return False

    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if not self.enabled:
            return None

        if ip_src in self.blacklist:
            return None

        return None

    def initiate_flow_manager_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid):
        if ip_src in self.blacklist or ip_dst in self.blacklist:

            parser = self.datapath_list[current_dpid].ofproto_parser
            ofproto = self.datapath_list[current_dpid].ofproto
            action_instructions = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

            return action_instructions
        return None

    def reset_statistics(self):
        super(BlacklistManager, self).reset_statistics()
        self.statistics["blacklist"] = self.blacklist
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
