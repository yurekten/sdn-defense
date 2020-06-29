from abc import ABC
from enum import Enum
from threading import RLock


class ProcessResult(Enum):
    IGNORE = 0,
    CONTINUE = 1,
    FINISH = 2

class ManagerActionType(Enum):
    ADD_FLOW = 100
    DELETE_FLOW = 110


class RequestParams(object):
    def __init__(self):
        pass

class PacketParams(RequestParams):

    def __init__(self, src_dpid=None, in_port=None, out_port=None, src_ip=None, dst_ip=None,
                 src_eth=None, dst_eth=None, target_dpid=None, target_dpid_out_port=None, default_match=None):

        super(PacketParams, self).__init__()
        self.src_dpid = src_dpid
        self.in_port = in_port
        self.src_ip = src_ip
        self.src_eth = src_eth
        self.out_port = out_port

        self.dst_ip = dst_ip
        self.dst_eth = dst_eth
        self.target_dpid = target_dpid
        self.target_dpid_out_port = target_dpid_out_port

        self.default_match = default_match


class SDNControllerRequest(object):
    _id_counter = 0
    lock = RLock()

    def __init__(self, msg, params):
        with SDNControllerRequest.lock:
            SDNControllerRequest._id_counter = SDNControllerRequest._id_counter + 1
            self.id = SDNControllerRequest._id_counter

        self.context = {}
        self.msg = msg
        self.params = params


class ManagerResponse(object):
    _id_counter = 0
    lock = RLock()

    def __init__(self, owner, process_result=ProcessResult.CONTINUE):
        with ManagerResponse.lock:
            ManagerResponse._id_counter = ManagerResponse._id_counter + 1
            self.id = ManagerResponse._id_counter

        self.owner = owner
        self.action_list = list()
        self.process_result = process_result


class BaseAction(ABC):
    _counter = 0
    _lock = RLock()

    def __init__(self, action_type: ManagerActionType):
        self.result_type = action_type
        with BaseAction._lock:
            BaseAction._counter = BaseAction._counter + 1
            self.id = BaseAction._counter



class AddFlowAction(BaseAction):

    def __init__(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, cookie=0,
                 table_id=0, idle_timeout=0, caller=None, manager=None, related_group_id=None):
        super(AddFlowAction, self).__init__(ManagerActionType.ADD_FLOW)
        self.datapath = datapath
        self.priority = priority
        self.match = match
        self.actions = actions
        self.buffer_id = buffer_id
        self.hard_timeout = hard_timeout
        self.flags = flags
        self.cookie = cookie
        self.table_id = table_id
        self.idle_timeout = idle_timeout
        self.caller = caller
        self.manager = manager
        self.related_group_id = related_group_id


class SDNControllerResponse(object):
    _id_counter = 0
    lock = RLock()

    def __init__(self, request_ctx: SDNControllerRequest):
        with SDNControllerResponse.lock:
            SDNControllerResponse._id_counter = SDNControllerResponse._id_counter + 1
            self.id = SDNControllerResponse._id_counter

        self.responses = dict()
        self.request_ctx = request_ctx

    def add_response(self, owner, response: ManagerResponse):
        self.responses[owner] = response

    def get_responses(self) -> dict:
        return self.responses
