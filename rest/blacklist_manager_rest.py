import json
from datetime import datetime

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route

from configuration import SDN_CONTROLLER_APP_KEY


class BlacklistManagerRest(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(BlacklistManagerRest, self).__init__(req, link, data, **config)
        self.sdn_controller_app = data[SDN_CONTROLLER_APP_KEY]

    @route('get_stats', "/blacklist_manager/statistics", methods=['GET'])
    def flow_monitor_flows(self, req, **kwargs):
        comparator = lambda o: o.__str__() if isinstance(o, object) else None
        stats = self.sdn_controller_app.blacklist_manager.get_statistics()
        result = json.dumps(stats, default=comparator)
        return result

    @route('get_status', "/blacklist_manager/status", methods=['GET'])
    def flow_monitor_get_status(self, req, **kwargs):
        status = self.sdn_controller_app.blacklist_manager.get_status()
        return f'{datetime.now()}: Status: {status}'

    @route('delete_flows', "/blacklist_manager/reset", methods=['GET'])
    def flow_monitor_reset_flows(self, req, **kwargs):
        self.sdn_controller_app.blacklist_manager.reset_statistics()
        return f'{datetime.now()}: Statistics are reset'

    @route('save_flows', "/blacklist_manager/save", methods=['GET'])
    def flow_monitor_save_statistics(self, req, **kwargs):
        manager = self.sdn_controller_app.blacklist_manager
        filename = manager.save_statistics()
        return f'{datetime.now()}: Statistics are saved into {filename}'
