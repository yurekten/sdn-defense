import json
from datetime import datetime

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route

from configuration import SDN_CONTROLLER_APP_KEY


class FlowMonitorRest(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(FlowMonitorRest, self).__init__(req, link, data, **config)
        self.sdn_controller_app = data[SDN_CONTROLLER_APP_KEY]

    @route('get_flows', "/flow_monitor/flows", methods=['GET'])
    def flow_monitor_flows(self, req, **kwargs):
        comparator = lambda o: o.__str__() if isinstance(o, object) else None
        stats = self.sdn_controller_app.flow_monitor.statistics
        result = json.dumps(stats, default=comparator)
        return result

    @route('get_status', "/flow_monitor/status", methods=['GET'])
    def flow_monitor_get_status(self, req, **kwargs):
        status = self.sdn_controller_app.flow_monitor.get_status()
        return f'{datetime.now()}: Status: {status}'

    @route('delete_flows', "/flow_monitor/reset", methods=['GET'])
    def flow_monitor_reset_flows(self, req, **kwargs):
        self.sdn_controller_app.flow_monitor.reset_statistics()
        return f'{datetime.now()}: Statistics are reset'

    @route('delete_flows', "/flow_monitor/save", methods=['GET'])
    def flow_monitor_save_statistics(self, req, **kwargs):
        manager = self.sdn_controller_app.flow_monitor
        filename = manager.save_statistics()
        return f'{datetime.now()}: Statistics are saved into {filename}'
