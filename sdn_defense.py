import logging
import pathlib
import sys
from collections import defaultdict
from datetime import datetime
from typing import List

from cachetools import cached, TTLCache
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_4
from ryu.topology import event

from configuration import SDN_CONTROLLER_APP_KEY
from defense_managers.blacklist.blacklist_manager import BlacklistManager
from defense_managers.blacklist.ids_blacklist_manager import IDSBlacklistManager
from defense_managers.multipath.multipath_manager import MultipathManager
from defense_managers.send_to_decoy.send_to_decoy_manager import SendToDecoyManager
from monitor.flow_monitor import FlowMonitor
from monitor.topology_monitor import TopologyMonitor
from rest.blacklist_manager_rest import BlacklistManagerRest
from rest.flow_monitor_rest import FlowMonitorRest
from rest.multipath_manager_rest import MultipathManagerRest
from defense_managers.event_parameters import SDNControllerRequest, SDNControllerResponse, PacketParams, ProcessResult, \
    ManagerActionType, AddFlowAction

CURRENT_PATH = pathlib.Path().absolute()
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)

sys.setrecursionlimit(10000)


class SDNDefenseApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SDNDefenseApp, self).__init__(*args, **kwargs)
        self.wsgi = kwargs['wsgi']

        self.wsgi.register(FlowMonitorRest, {SDN_CONTROLLER_APP_KEY: self})
        self.wsgi.register(MultipathManagerRest, {SDN_CONTROLLER_APP_KEY: self})
        self.wsgi.register(BlacklistManagerRest, {SDN_CONTROLLER_APP_KEY: self})

        self.sw_cookie = defaultdict()
        self.unused_cookie = 0x0010000
        self.hosts = {}
        self.host_ip_map = {}
        self.mac_to_port = {}

        now = int(datetime.now().timestamp())

        self.topology_monitor = TopologyMonitor()
        self.topology = self.topology_monitor.topology
        self.datapath_list = self.topology_monitor.datapath_list

        watch_generated_flows = False  # If flows generated by this class is reported, It is used to test
        flows_report_folder = "flows-%d" % (now)
        self.flow_monitor = FlowMonitor(flows_report_folder, watch_generated_flows)
        multipath_enabled = True
        blacklist_enabled = True
        ids_blacklist_enabled = True
        send_to_decoy_enabled = True

        self.defense_managers_dict = {}
        self.multipath_manager = MultipathManager(self, multipath_enabled)
        self.blacklist_manager = BlacklistManager(self, blacklist_enabled)
        self.ids_blacklist_manager = IDSBlacklistManager(self, ids_blacklist_enabled)
        #self.send_to_decoy_manager = SendToDecoyManager(self, send_to_decoy_enabled)

        self.defense_managers_dict[self.multipath_manager.name] = self.multipath_manager
        self.defense_managers_dict[self.blacklist_manager.name] = self.blacklist_manager
        self.defense_managers_dict[self.ids_blacklist_manager.name] = self.ids_blacklist_manager
        #self.defense_managers_dict[self.send_to_decoy_manager.name] = self.send_to_decoy_manager

        self.defense_managers = []
        for manager in list(self.defense_managers_dict.values()):
            if manager.enabled:
                self.defense_managers.append(manager)

    def update_manager_status(self, name, enabled):
        if name in self.defense_managers_dict:
            if self.defense_managers_dict[name].enabled != enabled:
                self.defense_managers_dict[name].enabled = enabled
                if enabled:
                    self.defense_managers.append(self.defense_managers_dict[name])
                else:
                    ind = self.defense_managers.index(self.defense_managers_dict[name])
                    del self.defense_managers[ind]

    def delete_flow(self, dpid, flow_id, caller):

        datapath = self.datapath_list[dpid]
        self.delete_flow_with_datapath(datapath=datapath, cookie=flow_id)

        for manager in self.defense_managers:
            if caller != manager:
                manager.flow_is_deleted(dpid, flow_id, caller)

    def delete_flow_with_datapath(self, datapath, cookie=0, cookie_mask=0xFFFFFFFFFFFFFFFF):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                table_id=ofproto.OFPTT_ALL,
                                cookie=cookie,
                                cookie_mask=cookie_mask,
                                )
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, cookie=0,
                 table_id=0, idle_timeout=0, caller=None, manager=None, related_group_id=None, request_ctx=None, response_ctx=None, inform_managers=True):
        if manager is None:
            manager = []
        elif not isinstance(manager, List):
            manager = [manager]

        if caller is None:
            caller = []
        elif not isinstance(caller, List):
            caller = [caller]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if idle_timeout == 0:
            pass
        flow_id = cookie
        if cookie == 0:
            flow_id = self._get_next_flow_cookie(datapath.id)

        #manager generates it
        if inform_managers and request_ctx is None:
            new_flow = AddFlowAction(datapath, priority, match, actions)
            new_flow.buffer_id = buffer_id
            new_flow.hard_timeout = hard_timeout
            new_flow.flags = flags
            new_flow.cookie = cookie
            new_flow.table_id = table_id
            new_flow.idle_timeout = idle_timeout
            new_flow.caller = caller
            new_flow.manager = manager
            new_request_ctx = SDNControllerRequest(None, new_flow)

            response_ctx = SDNControllerResponse(request_ctx=new_request_ctx)
            self.on_adding_auto_generated_flow(new_request_ctx, response_ctx)
            respose_actions = []
            for item in response_ctx.responses:
                responses=  response_ctx.responses[item]
                for item_action in responses.action_list:
                    respose_actions.extend(item_action.actions)

            #actions.extend(respose_actions)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    instructions=inst, hard_timeout=hard_timeout, flags=flags, cookie=flow_id,
                                    table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout,
                                    match=match, instructions=inst, hard_timeout=hard_timeout, flags=flags,
                                    cookie=flow_id, table_id=table_id)

        datapath.send_msg(mod)
        flows = self.flow_monitor.flows
        if datapath.id not in flows:
            flows[datapath.id] = defaultdict()

        flows[datapath.id][flow_id] = {"packet": mod, "caller": caller, "manager": manager,
                                       "group_id": related_group_id}
        return flow_id

    def on_adding_auto_generated_flow(self, request_ctx, response_ctx):

        for manager in self.defense_managers:
            manager.on_adding_auto_generated_flow(request_ctx, response_ctx)


    def _get_next_flow_cookie(self, sw_id):
        if sw_id not in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_group_id"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]

    def _get_next_group_id(self, sw_id):

        if sw_id not in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_group_id"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_group_id"] = self.sw_cookie[sw_id]["last_group_id"] + 1

        return self.sw_cookie[sw_id]["last_group_id"]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        logger.debug("switch_features_handler is called for %s" % str(ev))
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        delete_groups = parser.OFPGroupMod(datapath=datapath, command=ofproto.OFPGC_DELETE, group_id=ofproto.OFPG_ALL)
        datapath.send_msg(delete_groups)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flags=0, inform_managers=False)

        ofp_parser = datapath.ofproto_parser

        actions = []
        match1 = ofp_parser.OFPMatch(eth_type=0x86DD)  # IPv6
        self.add_flow(datapath, 999, match1, actions, flags=0, inform_managers=False)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # avoid broadcast from LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if pkt.get_protocol(ipv6.ipv6):
            return

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        in_port = msg.match['in_port']
        logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        default_match = None
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            default_match=parser.OFPMatch(
                    eth_type=0x0806,
                    arp_spa=src_ip,
                    arp_tpa=dst_ip,
                    in_port=in_port
                )
            if arp_pkt.opcode == 2:
                pass
        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            default_match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                in_port=in_port
            )
        else:
            # ignore other packets
            return

        if src_ip not in self.host_ip_map:
            self.hosts[src] = (dpid, in_port, src_ip)
            self.host_ip_map[src_ip] = (dpid, in_port, src)

        request_params = PacketParams(src_dpid=dpid, in_port=in_port, src_ip=src_ip,
                                     dst_ip=dst_ip, src_eth=src, dst_eth=dst, default_match=default_match)

        request_ctx = SDNControllerRequest(msg, request_params)

        finish = self.new_packet_detected(request_ctx)
        if finish:
            return
        out_port_list = []
        if src in self.hosts and dst in self.hosts:
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if h1[0] == dpid:
                for manager in self.defense_managers:
                    out = manager.get_output_port_for_packet(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, dpid)
                    if out:
                        out_port_list.append(out)

        actions = []
        if len(out_port_list) == 0:
            if dst in self.mac_to_port[dpid]:
                out = self.mac_to_port[dpid][dst]
                actions.append(parser.OFPActionOutput(out))
                out_port_list.append(out)
            else:
                out = ofproto.OFPP_FLOOD
                actions.append(parser.OFPActionOutput(out))
                out_port_list.append(out)
        else:
            for out in out_port_list:
                actions.append(parser.OFPActionOutput(out))
                out_port_list.append(out)


        # install a flow to avoid packet_in next time
        if actions[0].port != ofproto.OFPP_FLOOD:

            self.before_adding_default_flow(request_ctx, out_port_list, actions)

        else:

            actions = self.get_flood_output_actions(dpid, in_port, ofproto.OFPP_FLOOD)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def request_ctx_hash(self, request_ctx, *args, **kwargs):
        in_port = request_ctx.params.in_port
        dpid = request_ctx.msg.datapath.id
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        hash_val = str(dpid) +":"+str(in_port)+":"+str(src_ip)+":"+str(dst_ip)
        return hash_val

    @cached(cache=TTLCache(maxsize=1024, ttl=1), key=request_ctx_hash)
    def new_packet_detected(self, request_ctx):
        response_ctx = SDNControllerResponse(request_ctx=request_ctx)

        for manager in self.defense_managers:
            manager.on_new_packet_detected(request_ctx, response_ctx)

        finish = self._process_event_responses(request_ctx, response_ctx)
        return finish

    @cached(cache=TTLCache(maxsize=1024, ttl=1), key=request_ctx_hash)
    def before_adding_default_flow(self, request_ctx, out_port_list, actions):
        src_ip = request_ctx.params.src_ip
        dst_ip = request_ctx.params.dst_ip
        in_port = request_ctx.params.in_port


        datapath = request_ctx.msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # add idle flow
        priority = 1
        idle_timeout = 5
        hard_timeout = 0
        flags = 0
        # out_port = actions[0].port
        if self.flow_monitor.watch_generated_flows:
            flags = ofproto.OFPFF_SEND_FLOW_REM

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            in_port=in_port
        )
        out_port_list = sorted(out_port_list)
        out_port_list = [str(i) for i in out_port_list]
        output_ports = ":".join(out_port_list)
        request_ctx.params.out_port = output_ports

        add_flow_action = AddFlowAction(datapath, priority, match, actions, hard_timeout=hard_timeout,
                                        idle_timeout=idle_timeout,
                                        flags=flags,
                                        caller=self, manager=self)
        # add defined actions in to request
        request_ctx.context["add_flow_action"] = add_flow_action
        response_ctx = SDNControllerResponse(request_ctx=request_ctx)

        for manager in self.defense_managers:
            manager.before_adding_default_flow(request_ctx, response_ctx)

        del request_ctx.context["add_flow_action"]

        self._process_event_responses(request_ctx, response_ctx)
        self.create_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, output_ports, priority, flags,
                                      hard_timeout, idle_timeout, self, self, request_ctx, response_ctx)

        self.create_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, output_ports, priority, flags,
                                      hard_timeout, idle_timeout, self, self, request_ctx, response_ctx)
        self.create_arp_rule_if_not_exist(dpid, src_ip, dst_ip, in_port, output_ports, priority, flags,
                                          hard_timeout, idle_timeout, self, self, request_ctx, response_ctx)

        self.create_arp_rule_if_not_exist(dpid, dst_ip, src_ip, in_port, output_ports, priority, flags,
                                          hard_timeout, idle_timeout, self, self, request_ctx, response_ctx)

    def apply_add_flow_action(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse, action: AddFlowAction):
        assert action.result_type == ManagerActionType.ADD_FLOW

        dp = action.datapath
        priority = action.priority
        match = action.match
        actions = action.actions
        flags = action.flags
        buffer_id = action.buffer_id
        hard_timeout = action.hard_timeout
        idle_timeout = action.idle_timeout
        caller = action.caller
        manager = action.manager

        flow_id = self.add_flow(datapath=dp, priority=priority, match=match, actions=actions,
                                buffer_id=buffer_id, hard_timeout=hard_timeout, idle_timeout=idle_timeout,
                                flags=flags, caller=caller, manager=manager, request_ctx=request_ctx, response_ctx=response_ctx)
        return flow_id

    def merge_and_apply_flow_actions(self, request_ctx: SDNControllerRequest, response_ctx: SDNControllerResponse,
                                     actions : List[AddFlowAction], append_actions: List[AddFlowAction], callers, managers):
        assert len(actions) >= 1
        buckets = []
        if len(actions) == 1 and len(append_actions) == 0:
            return self.apply_add_flow_action(request_ctx, response_ctx, actions[0])

        datapath = request_ctx.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        for action in actions:

            bucket_actions = action.actions
            buckets.append(
                parser.OFPBucket(
                    actions=bucket_actions
                )
            )
        for action in append_actions:
            bucket_actions = action.actions
            buckets.append(
                parser.OFPBucket(
                    actions=bucket_actions
                )
            )
        group_id = self._get_next_group_id(datapath.id)
        req = parser.OFPGroupMod(datapath, command=ofproto.OFPGC_ADD, type_=ofproto.OFPGT_ALL, group_id=group_id, buckets=buckets)
        datapath.send_msg(req)

        # TODO: select first but check others
        action = actions[0]
        priority = action.priority
        match = action.match
        flags = action.flags
        buffer_id = action.buffer_id
        hard_timeout = action.hard_timeout
        idle_timeout = action.idle_timeout
        caller = callers
        manager = managers

        goto_group_actions = [parser.OFPActionGroup(group_id)]
        flow_id = self.add_flow(datapath=datapath, priority=priority, match=match, actions=goto_group_actions,
                                buffer_id=buffer_id, hard_timeout=hard_timeout, idle_timeout=idle_timeout,
                                flags=flags, caller=caller, manager=manager, related_group_id=group_id,
                                request_ctx=request_ctx, response_ctx=response_ctx)
        return flow_id

    def _process_event_responses(self, request_ctx, response_ctx) -> bool:
        finish = False
        add_flow_actions = {}
        append_actions = []
        callers = []
        managers = []
        for _manager, response in response_ctx.responses.items():

            for action in response.action_list:

                if action.caller not in callers:
                    callers.append(action.caller)
                if action.manager not in managers:
                    managers.append(action.manager)
                if action.result_type == ManagerActionType.ADD_FLOW:
                    if action.match is None:
                        append_actions.append(action)
                        continue
                    #if action.actions is None or len(action.actions) == 0:
                    #    continue
                    if action.match not in add_flow_actions:
                        add_flow_actions[action.match] = []
                    add_flow_actions[action.match].append(action)

            if response.process_result == ProcessResult.FINISH:
                finish = True

        for match, actions in add_flow_actions.items():
            flow_id = self.merge_and_apply_flow_actions(request_ctx, response_ctx, actions, append_actions, callers, managers)

        #x = action.manager
        return finish


    def get_flood_output_actions(self, dpid, in_port, out_port):

        no_flood_ports = self.topology_monitor.get_no_flood_ports()
        actions = []

        parser = self.datapath_list[dpid].ofproto_parser
        if dpid in no_flood_ports:
            for port, port_info in self.datapath_list[dpid].ports.items():
                if port_info.state == 4 and port not in no_flood_ports[dpid]:
                    if port != in_port:
                        actions.append(parser.OFPActionOutput(port))
        else:
            actions.append(parser.OFPActionOutput(out_port))
        return actions

    @cached(cache=TTLCache(maxsize=1024, ttl=1))
    def create_arp_rule_if_not_exist(self, dpid, src_ip, dst_ip, in_port, out_port_list, priority, flags, hard_timeout,
                                     idle_timeout, caller, manager, request_ctx, response_ctx):
        datapath = self.datapath_list[dpid]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0806,
            arp_spa=src_ip,
            arp_tpa=dst_ip,
            in_port=in_port
        )
        return self._add_rule(dpid, match, src_ip, dst_ip, in_port, out_port_list, priority, flags,
                              hard_timeout, idle_timeout, caller, manager, request_ctx, response_ctx)



    @cached(cache=TTLCache(maxsize=1024, ttl=1))
    def create_rule_if_not_exist(self, dpid, src_ip, dst_ip, in_port, output_ports, priority, flags, hard_timeout,
                                 idle_timeout, caller, manager, request_ctx, response_ctx):
        datapath = self.datapath_list[dpid]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            in_port=in_port
        )
        return self._add_rule(dpid, match, src_ip, dst_ip, in_port, output_ports, priority, flags, hard_timeout, idle_timeout,
                             caller, manager, request_ctx, response_ctx)

    def _add_rule(self, dpid, match, src_ip, dst_ip, in_port, output_ports, priority, flags,
                 hard_timeout, idle_timeout, caller, manager, request_ctx, response_ctx):
        datapath = self.datapath_list[dpid]
        parser = datapath.ofproto_parser
        actions = []

        out_port_list = output_ports.split(":")
        for out_port in out_port_list:
            actions.append(parser.OFPActionOutput(int(out_port)))

        if caller is None:
            caller = self
        if manager is None:
            manager = self
        flow_id = self.add_flow(datapath, priority, match, actions, hard_timeout=hard_timeout, flags=flags,
                                idle_timeout=idle_timeout, caller=caller, manager=manager,
                                request_ctx=request_ctx, response_ctx=response_ctx)
        flow_rem_flag = flags & datapath.ofproto.OFPFF_SEND_FLOW_REM > 1
        if src_ip in self.host_ip_map and self.host_ip_map[src_ip][0] == dpid and flow_rem_flag:
            self.flow_monitor.add_to_flow_list(dpid, flow_id, match, actions, priority, idle_timeout, hard_timeout)
        return flow_id

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        self.flow_monitor.flow_removed_handler(ev)

    def flow_removed(self, msg):
        self.flow_monitor.flow_removed(msg)
        self.multipath_manager.flow_removed(msg)

    ### topology events
    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        self.topology_monitor.switch_enter_handler(ev)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def _switch_leave_handler(self, ev):
        self.topology_monitor.switch_leave_handler(ev)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        self.topology_monitor.link_add_handler(ev)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def _link_delete_handler(self, ev):
        self.topology_monitor.link_delete_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        self.topology_monitor.port_status_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        self.topology_monitor.port_desc_stats_reply_handler(ev)


