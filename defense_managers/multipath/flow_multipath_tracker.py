import logging
import pathlib
import random
import time
from collections import defaultdict, Counter
from datetime import datetime
from threading import RLock
from typing import List

from ryu.lib import hub
from ryu.lib.packet import ether_types

from utils.common_utils import entropy
from utils.openflow_utils import copy_remove_msg_data

CURRENT_PATH = pathlib.Path().absolute()

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000


class FlowMultipathTracker(object):
    NOT_ACTIVE = 0
    INITIATED = 1
    ACTIVE = 2
    DESTROYING = 3
    DEAD = 4
    STATES = {0: "NOT_ACTIVE", 1: "INITIATED", 2: "ACTIVE", 3: "DESTROYING", 4: "DEAD"}

    def __init__(self, caller_app, flow_coordinator, dp_list, src, first_port, dst, last_port, ip_src, ip_dst,
                 max_random_paths=100, lowest_flow_priority=30000,
                 max_installed_path_count=2, max_time_period_in_second=4, forward_with_random_ip=True,
                 random_ip_subnet="10.93.0.0", random_ip_for_each_hop=True):

        self.caller_app = caller_app
        self.flow_coordinator = flow_coordinator

        self.dp_list = dp_list
        self.src = src
        self.first_port = first_port
        self.dst = dst
        self.last_port = last_port
        self.ip_src = ip_src
        self.ip_dst = ip_dst

        self.max_installed_path_count = max_installed_path_count
        self.max_time_period_in_second = max_time_period_in_second
        self.max_random_paths = max_random_paths
        self.lowest_flow_priority = lowest_flow_priority
        self.forward_with_random_ip = forward_with_random_ip
        self.random_ip_for_each_hop = random_ip_for_each_hop
        self.random_ip_subnet = random_ip_subnet
        sub_address_nodes = random_ip_subnet.split(".")
        self.random_ip_subnet_prefix = sub_address_nodes[0] + "." + sub_address_nodes[1]
        self.flow_info = (src, first_port, dst, last_port, ip_src, ip_dst,)

        self.flow_remove_lock = RLock()

        self.state = FlowMultipathTracker.NOT_ACTIVE

        self.statistics = defaultdict()
        self.statistics["rule_set"] = defaultdict()
        self.statistics["paths"] = None
        self.statistics["path_choices"] = None
        self.statistics["idle_count"] = 0
        self.statistics["start_time"] = datetime.now().timestamp()
        params = {"max_installed_path_count": self.max_installed_path_count,
                  "max_time_period_in_second": self.max_time_period_in_second,
                  "max_random_paths": self.max_random_paths,
                  "lowest_flow_priority": self.lowest_flow_priority,
                  "forward_with_random_ip": self.forward_with_random_ip,
                  "random_ip_for_each_hop": self.random_ip_for_each_hop,
                  "random_ip_subnet": self.random_ip_subnet
                  }

        self.statistics["params"] = params
        self._reset_tracker()

    def _reset_tracker(self):

        self.optimal_paths = None
        self.paths_with_ports = None

        self.path_choices = None

        self.rule_set_id = 0x10000
        self.flow_id_rule_set = defaultdict()

        self.active_path = None

    def get_status(self):
        return self.state

    def get_output_port_for_packet(self, datapath_id):
        if self.state == FlowMultipathTracker.NOT_ACTIVE:
            # hub.spawn(self._time_tracking)
            hub.spawn(self._maintain_flows)
            return None

        if self.active_path is not None and datapath_id in self.active_path:
            first_output_port = self.active_path[datapath_id][1]
            return first_output_port
        else:
            return None

    def flow_removed(self, msg):
        # called by owner
        if msg.cookie in self.flow_id_rule_set:
            rule_id = self.flow_id_rule_set[msg.cookie]
            if rule_id in self.statistics["rule_set"]:
                if msg.datapath.id in self.statistics["rule_set"][rule_id]["datapath_list"]:
                    stats = self.statistics["rule_set"][rule_id]["datapath_list"][msg.datapath.id]["ip_flow"]
                    if msg.cookie in stats:
                        with self.flow_remove_lock:
                            flow_stat = stats[msg.cookie]
                            copy_remove_msg_data(msg, flow_stat)

                            deleted_count = self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"]
                            self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"] = deleted_count + 1

                            max_ip_packet = self.statistics["rule_set"][rule_id]["max_ip_packet_count"]
                            if msg.packet_count > max_ip_packet:
                                self.statistics["rule_set"][rule_id]["max_ip_packet_count"] = msg.packet_count

                path_count = len(self.statistics["rule_set"][rule_id]["path"])
                if self.state == FlowMultipathTracker.ACTIVE or self.state == FlowMultipathTracker.INITIATED:
                    deleted_ip_flow = self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"]
                    if deleted_ip_flow >= path_count:
                        max_ip_packet = self.statistics["rule_set"][rule_id]["max_ip_packet_count"]
                        if max_ip_packet <= 0:
                            self.statistics["idle_count"] = self.statistics["idle_count"] + 1
                            if self.statistics["idle_count"] > 1:
                                self._set_state(FlowMultipathTracker.DESTROYING)
                        else:
                            self.statistics["idle_count"] = 0

    def _set_state(self, state):
        if state != self.state:
            self.state = state
            if logger.isEnabledFor(logging.WARNING):
                logger.warning('%s - State is now: %s for %s ' % (
                    datetime.now(), FlowMultipathTracker.STATES[self.state], self.flow_info))

    def _calculate_optimal_paths(self, recalculate=False):
        """
        Get the n-most optimal paths according to MAX_PATHS
        """

        if recalculate is False and self.optimal_paths is not None:
            return self.optimal_paths

        start = time.perf_counter()
        paths = self.caller_app.get_all_possible_paths(self.src, self.dst)
        paths_count = len(paths) if len(paths) < self.max_random_paths else self.max_random_paths

        sorted_paths = sorted(paths, key=lambda x: x[1])[0:paths_count]
        self.optimal_paths = sorted_paths

        # TODO: Entropy için çalışma yapılacak
        selected_paths = []

        count_of_previous_paths = 1
        if paths_count > 0:
            selected_paths.append(self.optimal_paths[0])
            cp = self.optimal_paths.copy()
            del cp[0]
            for i in range(1, paths_count):
                if i - count_of_previous_paths < 0:
                    first_ind = 0
                else:
                    first_ind = i - count_of_previous_paths

                all_nodes = []

                for p_index in range(first_ind, i):
                    dp_set = set(selected_paths[p_index][0]) - {self.src, self.dst}
                    all_nodes.extend(dp_set)

                counts = dict(Counter(all_nodes))
                # count = sum([item[1] for item in counts.items()])

                # p = [item[1] * 1.0 / count for item in counts.items()]
                ent_list = {}
                for j in range(0, len(cp)):
                    path = cp[j][0]

                    dp_set = set(path) - {self.src, self.dst}
                    test_count = counts.copy()
                    for dp in dp_set:
                        if dp not in test_count:
                            test_count[dp] = 1
                        else:
                            test_count[dp] = test_count[dp] + 1
                    new_count = sum([item[1] for item in test_count.items()])
                    p_new = [item[1] * 1.0 / new_count for item in test_count.items()]
                    new_entropy = entropy(p_new)
                    ent_list[j] = new_entropy

                items = sorted(ent_list.items(), key=lambda x: x[1])
                max_value = items[0]
                max_value_index = max_value[0]
                dp_set = set(cp[max_value_index][0]) - {self.src, self.dst}
                selected_paths.append(cp[max_value_index])

                del cp[max_value_index]

        # create path cost array
        pw = [item[1] for item in sorted_paths]

        path_indices = range(0, len(sorted_paths))
        self.path_choices = random.choices(path_indices, weights=pw, k=100)

        self.paths_with_ports = self.caller_app.add_ports_to_paths(self.optimal_paths, self.first_port, self.last_port)
        self.statistics["paths"] = self.paths_with_ports
        self.statistics["path_choices"] = self.path_choices

        if logger.isEnabledFor(level=logging.DEBUG):
            end = time.perf_counter()
            logger.debug(f"path creation is completed for {self.flow_info} in {end - start:0.4f} seconds")

        return sorted_paths

    def _maintain_flows(self):
        start_index = -1
        next_index = 0
        installed_times = {}
        # threshold = 0.001
        # period = 1.0 * self.max_time_period_in_second / self.max_installed_path_count
        length = -1

        while self.state != FlowMultipathTracker.DEAD:
            logger.debug(f'{datetime.now()} - {self.flow_info} state is {FlowMultipathTracker.STATES[self.state]}.')
            if self.state == FlowMultipathTracker.NOT_ACTIVE:
                self._reset_tracker()
                self._calculate_optimal_paths()
                length = len(self.path_choices)
                self._set_state(FlowMultipathTracker.INITIATED)

            if self.state == FlowMultipathTracker.INITIATED or self.state == FlowMultipathTracker.ACTIVE:

                if FlowMultipathTracker.get_virtual_queue_size(length, start_index,
                                                               next_index) < self.max_installed_path_count:
                    current_index = next_index
                    rule_id = self._create_flow_rule(current_index)
                    next_index = FlowMultipathTracker.get_virtual_queue_next_index(length, current_index)
                    installed_times[current_index] = (datetime.now().timestamp(), rule_id)
                    if self.state == FlowMultipathTracker.INITIATED:
                        current_path_index = self.path_choices[current_index]
                        self.active_path = self.paths_with_ports[current_path_index]

                        self._set_state(FlowMultipathTracker.ACTIVE)

                current_time = datetime.now().timestamp()
                installed_items = list(installed_times.items())
                for index, installed_time in installed_items:
                    if installed_time[0] + self.max_time_period_in_second <= current_time:
                        if FlowMultipathTracker.get_virtual_queue_size(length, start_index, next_index) > 0:
                            start_index = FlowMultipathTracker.get_virtual_queue_next_index(length, start_index)

                        rule_id = installed_time[1]
                        ip_flows = self.statistics["rule_set"][rule_id]["datapath_list"][self.src]["ip_flow"]
                        flow_id = list(ip_flows.keys())[0]
                        #self.flow_coordinator.delete_flow(self.src, flow_id, self)

                        current_path_index = self.path_choices[start_index]
                        self.active_path = self.paths_with_ports[current_path_index]
                        logger.debug(f'{datetime.now()} - {self.flow_info} dp:{self.src} flow:{flow_id} is deleted.')
                        del installed_times[index]
                    else:
                        break

            elif self.state == FlowMultipathTracker.DESTROYING:
                self.caller_app.multipath_tracker_is_destroying(self)
                self._set_state(FlowMultipathTracker.DEAD)
                self._reset_tracker()
                self.statistics["end_time"] = datetime.now().timestamp()
            logger.debug(f'{datetime.now()} - {self.flow_info} is sleeping.')
            if self.state != FlowMultipathTracker.DEAD:
                hub.sleep(1)

        logger.warning(f'{datetime.now()} - {self.flow_info} is finished.')

    @staticmethod
    def get_virtual_queue_size(array_length, start_index, next_index):
        assert next_index != start_index
        if next_index > start_index:
            return next_index - start_index - 1
        else:
            return next_index + array_length - start_index

    @staticmethod
    def get_virtual_queue_next_index(array_length, current_index):

        if current_index >= array_length - 1:
            return 0
        else:
            return current_index + 1

    def _create_flow_rule(self, current_index, ):
        current_path_index = self.path_choices[current_index]

        priority = self.lowest_flow_priority + current_index
        timeout = self.max_time_period_in_second

        selected_path = self.paths_with_ports[current_path_index]
        rule_set_id = self._create_flow_rules(selected_path, priority, idle_timeout=self.max_time_period_in_second)

        if logger.isEnabledFor(logging.WARNING):
            now = datetime.now()
            now_string = now.strftime("%H:%M:%S.%f")
            logger.warning(
                f'{now} - Rule set {rule_set_id} : Path No:{current_index:03}(Ind:{current_path_index:03}, Pri:{priority:05}) for ({self.src}->{self.dst}) start: [{now_string}] duration: {timeout:02} sec. path: {list(selected_path.keys())}')

        self.statistics["rule_set"][rule_set_id]["installed_path_index"] = current_path_index
        self.statistics["rule_set"][rule_set_id]["choise_index"] = current_index

        return rule_set_id

    def create_random_ip(self):
        return self.random_ip_subnet_prefix + "." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))

    def _create_match_actions_for(self, path):
        match_actions = {}
        path_size = len(path)
        path_ind = -1

        src_rand_ip = self.create_random_ip()
        dst_rand_ip = self.create_random_ip()

        for node in path:
            path_ind = path_ind + 1
            dp = self.dp_list[node]
            ofp_parser = dp.ofproto_parser

            in_port = path[node][0]
            output_action = ofp_parser.OFPActionOutput(path[node][1])
            if self.forward_with_random_ip and path_size > 1:
                if path_ind == 0:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=self.ip_src,
                        ipv4_dst=self.ip_dst,
                        in_port=in_port
                    )
                    src_rand_ip = self.create_random_ip()
                    change_src_ip = ofp_parser.OFPActionSetField(ipv4_src=src_rand_ip)

                    dst_rand_ip = self.create_random_ip()
                    change_dst_ip = ofp_parser.OFPActionSetField(ipv4_dst=dst_rand_ip)

                    actions = [change_src_ip, change_dst_ip, output_action]

                elif path_ind >= path_size - 1:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_rand_ip,
                        ipv4_dst=dst_rand_ip,
                        in_port=in_port
                    )

                    change_src_ip = ofp_parser.OFPActionSetField(ipv4_src=self.ip_src)
                    change_dst_ip = ofp_parser.OFPActionSetField(ipv4_dst=self.ip_dst)

                    actions = [change_src_ip, change_dst_ip, output_action]
                else:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_rand_ip,
                        ipv4_dst=dst_rand_ip,
                        in_port=in_port
                    )
                    if self.random_ip_for_each_hop:
                        src_rand_ip = self.create_random_ip()
                        change_src_ip = ofp_parser.OFPActionSetField(ipv4_src=src_rand_ip)

                        dst_rand_ip = self.create_random_ip()
                        change_dst_ip = ofp_parser.OFPActionSetField(ipv4_dst=dst_rand_ip)

                        actions = [change_src_ip, change_dst_ip, output_action]
                    else:
                        actions = [output_action]

            else:
                match_ip = ofp_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=self.ip_src,
                    ipv4_dst=self.ip_dst,
                    in_port=in_port
                )
                actions = [output_action]

            match_actions[node] = (match_ip, actions)
        if self.forward_with_random_ip:
            pass

        return match_actions

    def _create_flow_rules(self, current_path, priority, hard_timeout=0, idle_timeout=0):
        self.rule_set_id = self.rule_set_id + 1
        self.statistics["rule_set"][self.rule_set_id] = defaultdict()

        rule_set = self.statistics["rule_set"][self.rule_set_id]
        rule_set["path"] = current_path
        rule_set["datapath_list"] = defaultdict()
        rule_set["flow_info"] = self.flow_info
        rule_set["max_ip_packet_count"] = -1
        # rule_set["max_arp_packet_count"] = -1
        rule_set["deleted_ip_flow_count"] = 0
        # rule_set["deleted_arp_flow_count"] = 0

        match_actions = self._create_match_actions_for(current_path)
        first = None
        install_path_ordered = defaultdict()
        for node in current_path:
            if first is None:
                first = node
                continue
            install_path_ordered[node] = current_path[node]

        install_path_ordered[first] = current_path[first]
        for node in install_path_ordered:
            if node not in rule_set["datapath_list"]:
                rule_set["datapath_list"][node] = defaultdict()
                rule_set["datapath_list"][node]["ip_flow"] = defaultdict()

            dp = self.dp_list[node]
            ofproto = dp.ofproto
            match = match_actions[node][0]
            actions = match_actions[node][1]
            new_hard_timeout = hard_timeout
            # if node == first:
            # hub.sleep(0.1)
            # new_hard_timeout = new_hard_timeout - 1

            flow_id_result = self.flow_coordinator.add_flow(dp, priority,
                                                     match, actions,
                                                     hard_timeout=new_hard_timeout,
                                                     idle_timeout=idle_timeout,
                                                     flags=ofproto.OFPFF_SEND_FLOW_REM,
                                                     caller=self, manager=self.caller_app)
            if not isinstance(flow_id_result, List):
                flow_id_result = [flow_id_result]
            for flow_id in flow_id_result:
                stats = rule_set["datapath_list"][node]["ip_flow"]
                timestamp = datetime.timestamp(datetime.now())
                stats[flow_id] = defaultdict()
                stats[flow_id]["created_time"] = timestamp
                stats[flow_id]["removed_time"] = None
                stats[flow_id]["packet_count"] = None
                stats[flow_id]["byte_count"] = None
                self.flow_id_rule_set[flow_id] = self.rule_set_id
                stats[flow_id]["flow_params"] = (node, match, actions)

        return self.rule_set_id
