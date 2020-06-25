import logging
import pathlib
from datetime import datetime

from defense_managers.base_manager import BaseDefenseManager

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
        self.applied_blacklist = {}
        self.statistics["blacklist"] = self.blacklist
        self.statistics["applied_blacklist"] = {}
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
                "max_blacklist_item_count": self.max_blacklist_item_count,
                "hit_count": self.statistics["hit_count"],
                "reset_time": datetime.fromtimestamp(self.statistics["reset_time"])

                }

    def new_packet_detected(self, msg, dpid, in_port, src_ip, dst_ip, eth_src, eth_dst):
        pass

    def _add_ip_to_blacklist(self, dpid, ip):
        pass

    def flow_removed(self, msg):
        pass

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
        pass

    def reset_statistics(self):
        super(BlacklistManager, self).reset_statistics()
        self.statistics["blacklist"] = self.blacklist
        self.statistics["hit_count"] = 0
        self.statistics["reset_time"] = datetime.now().timestamp()
