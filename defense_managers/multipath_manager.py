import json
import os
import queue

import math
import subprocess
from collections import defaultdict, Counter
from datetime import datetime
import random
import time
from threading import RLock

import networkx as nx

import logging

from ryu.lib import hub
from ryu.lib.packet import ether_types
import pathlib

CURRENT_PATH = pathlib.Path().absolute()

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)
REFERENCE_BW = 10000000

class FlowMultipathManager(object):
    NOT_ACTIVE = 0
    INITIATED = 1
    ACTIVE = 2
    DESTROYING = 3
    DEAD = 4
    STATES = { 0: "NOT_ACTIVE", 1:"INITIATED", 2:"ACTIVE", 3:"DESTROYING", 4:"DEAD"}

    def __init__(self, caller_app, graph, dp_list, src, first_port, dst, last_port, ip_src, ip_dst,
                 max_random_paths=100, lowest_flow_priority=30000, 
                 max_installed_path_count=2, max_time_period_in_second=2, 
                 forward_with_random_ip=True, random_ip_subnet="10.93.0.0", random_ip_for_each_hop=True,
                 report_folder="multipath-statistics",
                 *args, **kwargs):

        self.caller_app = caller_app
        self.topology = graph
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
        self.random_ip_subnet_prefix  = sub_address_nodes[0] + "." + sub_address_nodes[1]
        self.flow_info = (src, first_port, dst, last_port, ip_src, ip_dst,)
        self.report_folder = report_folder

        self.write_file_lock = RLock()
        self.flow_remove_lock = RLock()

        self.state = FlowMultipathManager.NOT_ACTIVE

        self.statistics = defaultdict()
        self.statistics["rule_set"] = defaultdict()
        self.statistics["paths"] = None
        self.statistics["path_choices"] = None
        self.statistics["idle_count"] = 0
        self.statistics["saved_to_file"] = False
        params = {"max_installed_path_count": self.max_installed_path_count,
                  "max_time_period_in_second": self.max_time_period_in_second,
                  "max_random_paths": self.max_random_paths,
                  "lowest_flow_priority": self.lowest_flow_priority,
                  "forward_with_random_ip": self.forward_with_random_ip,
                  "random_ip_for_each_hop": self.random_ip_for_each_hop,
                  "random_ip_subnet": self.random_ip_subnet,
                  "report_folder": self.report_folder}

        self.statistics["params"] = params
        self._reset_manager()

    def _reset_manager(self):

        self.optimal_paths = None
        self.paths_with_ports = None

        self.path_choices = None
        self.last_installed_path_index = -1
        self.installed_path_indices = []

        self.all_paths = None
        self.rule_set_id = 0x10000
        self.flow_id_rule_set = defaultdict()

        self.active_queue = queue.Queue()
        self.initiated_queue = queue.Queue()
        self.inactive_queue = queue.Queue()
        self.delete_queue = queue.Queue()

        self.active_path = None
        self.active_path_index = -1
        self.last_rule_set_expire_time = None

    def _save_statistics(self):
        with self.write_file_lock:
            if not self.statistics["saved_to_file"]:

                report_path = os.path.join(CURRENT_PATH, "reports", self.report_folder)

                pathlib.Path(report_path).mkdir(parents=True, exist_ok=True)

                now = int(datetime.now().timestamp())
                file_name = "%d-%s_to_%s.json" % (now, self.src, self.dst)

                file_path = os.path.join(report_path, file_name)
                comparator = lambda o: o.__str__() if isinstance(o, object) else None
                with open(file_path, 'w') as outfile:
                   json.dump(self.statistics, outfile, default=comparator)
                subprocess.call(['chmod', "-R", '0777', report_path])
                self.statistics["saved_to_file"] = True


    @staticmethod
    def date_time_converter(o):
        if isinstance(o, object):
            return o.__str__()

    @staticmethod
    def delete_flow(datapath, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                table_id=ofproto.OFPTT_ALL,
                                cookie=cookie,
                                cookie_mask=0xFFFFFFFFFFFFFFFF,
                                )
        datapath.send_msg(mod)

    def get_status(self):
        return self.state

    def get_active_path_port_for(self, datapath_id):
        if self.state == FlowMultipathManager.NOT_ACTIVE:
            hub.spawn(self._maintain_paths)
            hub.spawn(self._manage_timing)
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
                            flow_stat["removed_time"] = datetime.timestamp(datetime.now())
                            flow_stat["packet_count"] = msg.packet_count
                            flow_stat["byte_count"] = msg.byte_count
                            flow_stat["duration_sec"] = msg.duration_sec
                            flow_stat["duration_nsec"] = msg.duration_nsec
                            flow_stat["hard_timeout"] = msg.hard_timeout
                            flow_stat["idle_timeout"] = msg.idle_timeout
                            flow_stat["priority"] = msg.priority
                            flow_stat["reason"] = msg.reason
                            flow_stat["table_id"] = msg.table_id

                            deleted_count = self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"]
                            self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"] = deleted_count + 1

                            max_ip_packet = self.statistics["rule_set"][rule_id]["max_ip_packet_count"]
                            if msg.packet_count > max_ip_packet:
                                self.statistics["rule_set"][rule_id]["max_ip_packet_count"] = msg.packet_count

                    # stats = self.statistics["rule_set"][rule_set_id]["datapath_list"][msg.datapath.id]["arp_flow"]
                    # if msg.cookie in stats:
                    #     stats[msg.cookie]["removed_time"] = datetime.timestamp(datetime.now())
                    #     stats[msg.cookie]["packet_count"] = msg.packet_count
                    #
                    #     deleted_count = self.statistics["rule_set"][self.rule_set_id]["deleted_arp_flow_count"]
                    #     self.statistics["rule_set"][self.rule_set_id]["deleted_arp_flow_count"] = deleted_count + 1
                    #
                    #     max_arp_packet = self.statistics["rule_set"][self.rule_set_id]["max_arp_packet_count"]
                    #     if msg.packet_count > max_arp_packet:
                    #         self.statistics["rule_set"][self.rule_set_id]["max_arp_packet_count"] = msg.packet_count

                #deleted_arp_flow = self.statistics["rule_set"][self.rule_set_id]["deleted_arp_flow_count"]
                path_count = len(self.statistics["rule_set"][rule_id]["path"])
                if self.state == FlowMultipathManager.ACTIVE or self.state == FlowMultipathManager.INITIATED:

                    deleted_ip_flow = self.statistics["rule_set"][rule_id]["deleted_ip_flow_count"]
                    #if deleted_arp_flow >= path_count and deleted_ip_flow >= path_count:
                    if deleted_ip_flow >= path_count:
                        max_ip_packet = self.statistics["rule_set"][rule_id]["max_ip_packet_count"]
                        #max_arp_packet = self.statistics["rule_set"][self.rule_set_id]["max_arp_packet_count"]
                        #if max_ip_packet <= 0 and max_arp_packet <= 0:
                        if max_ip_packet <= 0:
                            self.statistics["idle_count"] = self.statistics["idle_count"] + 1
                            if self.statistics["idle_count"] > 1:
                                self._set_state(FlowMultipathManager.DESTROYING)
                        else:
                            self.statistics["idle_count"] = 0

    def _maintain_paths(self):
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(f'{datetime.now()} - Path management thread has started')
        completed = False
        while not completed:
            if self.state == FlowMultipathManager.DESTROYING or self.state == FlowMultipathManager.DEAD:
                self._delete_paths()
                if self.active_queue.qsize() == 0:
                    self._set_state(FlowMultipathManager.DEAD)
                    hub.sleep(self.max_time_period_in_second / 4)
                    self.caller_app.flow_manager_is_destroying(self)
                    self._save_statistics()

                completed = True
            else:
                self._update_paths()
                self._delete_paths()
                hub.sleep(self.max_time_period_in_second / 4)
        if logger.isEnabledFor(logging.INFO):
            logger.info(f'Path management for {self.flow_info} has exited at {datetime.now()}')

    def _manage_timing(self):
        completed = False
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(f'{datetime.now()} - Timing thread has started')
        while not completed:
            if self.state == FlowMultipathManager.DESTROYING or self.state == FlowMultipathManager.DEAD:
                exit_loop = False
                while not exit_loop:
                    try:
                        index, deleted_item, ruleset_id = self.active_queue.get_nowait()
                        self.active_path = self.optimal_paths[self.path_choices[index + 1]]
                        self.delete_queue.put_nowait((index, deleted_item, ruleset_id))
                        if logger.isEnabledFor(logging.INFO):
                            logger.info('%s put index:%s item:%s into delete queue %s'
                                        %(self.flow_info, index, deleted_item, datetime.now(),))
                    except queue.Empty:
                        exit_loop = True

                self._set_state(FlowMultipathManager.DEAD)
                hub.sleep(self.max_time_period_in_second / 2)
                self.caller_app.flow_manager_is_destroying(self)
                self._save_statistics()
                completed = True
            else:
                started_item_count = self.initiated_queue.qsize() + self.active_queue.qsize()
                if started_item_count <= self.max_installed_path_count:
                    try:
                        index, item = self.inactive_queue.get(block=False)
                        self.initiated_queue.put_nowait((index, item))

                        if logger.isEnabledFor(logging.INFO):
                            logger.info('%s put index:%s item:%s into initiated queue %s'
                                        %(self.flow_info, index, item, datetime.now(),))

                        started_item_count = self.initiated_queue.qsize() + self.active_queue.qsize()
                        if self.max_installed_path_count < started_item_count:
                            deleted_item_count = started_item_count - self.max_installed_path_count
                            for ix in range(0, deleted_item_count):
                                if self.active_queue.qsize() > 1:
                                    index, deleted_item, ruleset_id = self.active_queue.get()
                                    self.delete_queue.put_nowait((index, deleted_item, ruleset_id))

                                    if logger.isEnabledFor(logging.INFO):
                                        logger.info('%s put index:%s item:%s into delete queue %s'
                                                    % (self.flow_info, index, deleted_item, datetime.now(),))
                                else:
                                    break
                        random_wait_time = (self.max_time_period_in_second / 2) + random.random() * (self.max_time_period_in_second / 2)
                        hub.sleep(random_wait_time)
                    except queue.Empty:
                        random_wait_time = (self.max_time_period_in_second / 4) + random.random() * (self.max_time_period_in_second / 4)
                        hub.sleep(random_wait_time)
                else:
                    random_wait_time = (self.max_time_period_in_second / 4) + random.random() * (self.max_time_period_in_second / 4)
                    hub.sleep(random_wait_time)

                if self.state == FlowMultipathManager.ACTIVE and self.inactive_queue.qsize() < 5:
                    for index in range(0, len(self.path_choices)):
                        self.inactive_queue.put_nowait((index, self.path_choices[index]))

        exit_loop = False
        while not exit_loop:
            try:
                self.inactive_queue.get_nowait()
            except queue.Empty:
                exit_loop = True

        if logger.isEnabledFor(logging.WARNING):
            logger.warning(f'{datetime.now()} - Timing thread {self.flow_info} has exited')

    def _set_state(self, state):
        if state != self.state:
            self.state = state
            if logger.isEnabledFor(logging.WARNING):
                logger.warning('%s - State is now: %s for %s ' % (datetime.now(), FlowMultipathManager.STATES[self.state], self.flow_info))
            if state == FlowMultipathManager.DEAD:
                self._reset_manager()


    def _get_all_possible_paths(self):
        """
        Get all paths from src to dst using DFS algorithm
        """

        if self.all_paths is not None:
            return self.all_paths

        start = time.perf_counter()
        if self.src == self.dst:
            if logger.isEnabledFor(level=logging.DEBUG):
                logger.debug(f"Path selection is completed. src and dst is in same datapath")
            # host target is on the same switch
            return [([self.src], 1)]

        path_results = nx.all_simple_paths(self.topology, source=self.src, target=self.dst, cutoff=16)

        paths = []
        for path in path_results:
            paths.append(path)

        selected_paths = self._select_paths(paths)
        self.all_paths = []
        for path in selected_paths:
            path_cost = self._get_path_cost(path)
            self.all_paths.append((path, path_cost))

        if logger.isEnabledFor(level=logging.DEBUG):
            end = time.perf_counter()
            logger.debug(f"Path selection is completed for {self.flow_info} in {end - start:0.4f} seconds")

        return self.all_paths

    def _select_paths(self, paths):
        selected_paths = paths[:]
        #select only subset paths, eliminate paths contains others
        for x in paths:
            superset = []
            for y in selected_paths:
                if set(x) < set(y):
                    superset.append(y)
            for deleted_item in superset:
                ind = selected_paths.index(deleted_item)
                del selected_paths[ind]

        return selected_paths

    def _get_path_cost(self, path):
        """
        Get the path cost
        """
        path_cost = 0
        for i in range(len(path) - 1):
            s1 = path[i]
            s2 = path[i + 1]
            e1 = self.topology.edges.get((s1, s2))["port_no"]
            e2 = self.topology.edges.get((s2, s1))["port_no"]
            bw1 = self.topology.nodes[s1]["port_bandwidths"][e1]
            bw2 = self.topology.nodes[s2]["port_bandwidths"][e2]
            bw_low = min(bw1, bw2)
            link_cost = int(REFERENCE_BW / bw_low)
            path_cost += link_cost

        return path_cost


    def entropy_cal(self, array):

        total_entropy = 0

        for i in array:
            total_entropy += -i * math.log(2, i)

        return total_entropy

    def _calculate_optimal_paths(self, recalculate=False):
        """
        Get the n-most optimal paths according to MAX_PATHS
        """

        if recalculate is False and self.optimal_paths is not None:
            return self.optimal_paths

        start = time.perf_counter()
        paths = self._get_all_possible_paths()
        paths_count = len(paths) if len(paths) < self.max_random_paths else self.max_random_paths

        sorted_paths = sorted(paths, key=lambda x: x[1])[0:paths_count]
        self.optimal_paths = sorted_paths

        #TODO: Entropy için çalışma yapılacak
        last_entropy = -1

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
                count = sum([item[1] for item in counts.items()])

                p = [item[1] * 1.0 / count for item in counts.items()]
                current_entropy = self.entropy_cal(p)
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
                    new_count =  sum([item[1] for item in test_count.items()])
                    p_new = [item[1] * 1.0 / new_count for item in test_count.items()]
                    new_entropy = self.entropy_cal(p_new)
                    ent_list[j] = new_entropy

                items = sorted(ent_list.items(), key=lambda x: x[1])
                max_value = items[0]
                min_value = items[len(items)-1]
                dp_set = set(cp[max_value[0]][0]) - {self.src, self.dst}
                selected_paths.append(cp[max_value[0]])

                del cp[max_value[0]]
                #
                # if abs(current_entropy - max_value[1]) > abs(current_entropy - min_value[1]):
                #     dp_set = set(self.optimal_paths[max_value[0]][0]) - {self.src, self.dst}
                #     selected_paths.append(self.optimal_paths[max_value[0]])
                #     all_nodes.extend(dp_set)
                #     current_entropy = max_value[1]
                # else:
                #     dp_set = set(self.optimal_paths[min_value[0]][0]) - {self.src, self.dst}
                #     selected_paths.append(self.optimal_paths[min_value[0]])
                #     all_nodes.extend(dp_set)
                #     current_entropy = min_value[1]


        #create path cost array
        pw = [item[1] for item in sorted_paths]

        path_indices = range(0, len(sorted_paths))
        self.path_choices = random.choices(path_indices, weights=pw, k=100)

        self.paths_with_ports = self._add_ports_to_paths(self.optimal_paths, self.first_port, self.last_port)
        self.statistics["paths"] = self.paths_with_ports
        self.statistics["path_choices"] = self.path_choices

        if logger.isEnabledFor(level=logging.DEBUG):
            end = time.perf_counter()
            logger.debug(f"path creation is completed for {self.flow_info} in {end - start:0.4f} seconds")

        return sorted_paths

    def _add_ports_to_paths(self, paths, first_port, last_port):
        """
        Add the ports that connects the switches for all paths
        """
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[0][:-1], path[0][1:]):
                out_port = self.topology.edges.get((s1, s2))["port_no"]
                p[s1] = (in_port, out_port)
                in_port = self.topology.edges.get((s2, s1))["port_no"]
            p[path[0][-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def _update_paths(self):
        if self.state == FlowMultipathManager.NOT_ACTIVE:

            self._set_state(FlowMultipathManager.INITIATED)

            self._reset_manager()
            self._calculate_optimal_paths()

            while not self.inactive_queue.empty():
                try:
                    self.inactive_queue.get_nowait()
                except queue.Empty:
                    break

            for index in range(0, len(self.path_choices)):
                self.inactive_queue.put_nowait((index, self.path_choices[index]))
        if self.last_rule_set_expire_time is not None:
            left_to_expire = self.last_rule_set_expire_time - datetime.now().timestamp()
        else:
            left_to_expire = 0

        if left_to_expire < 1:

            try:
                queue_index, index = self.initiated_queue.get(block=False)
            except queue.Empty:
                index = -1
                queue_index = -1
            counter = 0
            if index > -1:
                self.last_installed_path_index = self.last_installed_path_index + 1
                current_path_index = index
                counter = counter + 1
                priority = self.lowest_flow_priority + self.last_installed_path_index
                # if self.last_rule_set_expire_time is None:
                #     timeout = self.max_time_period_in_second
                # else:
                #     timeout = round(self.last_rule_set_expire_time + self.max_time_period_in_second - datetime.now().timestamp())
                timeout = self.max_time_period_in_second
                if self.last_rule_set_expire_time is None:
                    self.last_rule_set_expire_time = datetime.now().timestamp() +  self.max_time_period_in_second
                else:
                    self.last_rule_set_expire_time = self.last_rule_set_expire_time + self.max_time_period_in_second





                selected_path = self.paths_with_ports[current_path_index]
                rule_set_id = self._create_flow_rules(selected_path, priority, idle_timeout=timeout)
                self.active_queue.put_nowait((queue_index, current_path_index, rule_set_id))
                if logger.isEnabledFor(logging.WARNING):
                    now = datetime.now()
                    now_string = now.strftime("%H:%M:%S.%f")
                    logger.warning(f'{now} - Rule set {rule_set_id} for ({self.src}->{self.dst}) start: [{now_string}] duration: {timeout:02} sec. path: {list(selected_path.keys())}')

                self._set_state(FlowMultipathManager.ACTIVE)
                if logger.isEnabledFor(logging.INFO):
                    logger.info(f'Installer - {self.flow_info} Put index:{queue_index} item:{index} into active queue {datetime.now()}')

                if self.active_path is None:
                    self.active_path = selected_path
                    self.active_path_index = queue_index
                self.statistics["rule_set"][rule_set_id]["installed_path_index"] = current_path_index
                self.statistics["rule_set"][rule_set_id]["choise_index"] = self.last_installed_path_index

                try:
                    queue_index, index = self.initiated_queue.get(block=False)
                except queue.Empty:
                    index = -1

        if self.active_path is not None and self.src in self.active_path:
            first_output_port = self.active_path[self.src][1]
            return first_output_port
        else:
            return None

    def _delete_paths(self):
        rule_set_id = -1
        try:
            queue_index, index, rule_set_id = self.delete_queue.get(block=False)
        except queue.Empty:
            pass

        while rule_set_id > -1:
            sw_list = self.statistics["rule_set"][rule_set_id]["datapath_list"]
            sw_ordered = []
            for sw in sw_list:
                if sw == self.src:
                    sw_ordered.insert(0, sw)
                else:
                    sw_ordered.append(sw)

            for sw in sw_ordered:
                dp = self.dp_list[sw]
                if sw in self.statistics["rule_set"][rule_set_id]["datapath_list"]:
                    for ip_flow in self.statistics["rule_set"][rule_set_id]["datapath_list"][sw]["ip_flow"]:
                        self.delete_flow(dp, ip_flow)
                        # logger.info('0x%x is delete request sent to %s switch' % (ip_flow, sw))
                    # for arp_flow in self.statistics["rule_set"][rule_set_id]["datapath_list"][sw]["arp_flow"]:
                    #     self.delete_flow(dp, arp_flow)
                    #     # logger.info('0x%x is delete request sent to %s switch' % (arp_flow, sw))

            try:
                queue_index, index, rule_set_id = self.delete_queue.get(block=False)
            except queue.Empty:
                rule_set_id = -1

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

                elif path_ind >= path_size -1:
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
        #rule_set["max_arp_packet_count"] = -1
        rule_set["deleted_ip_flow_count"] = 0
        #rule_set["deleted_arp_flow_count"] = 0

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
                #rule_set["datapath_list"][node]["arp_flow"] = defaultdict()

            dp = self.dp_list[node]
            ofproto = dp.ofproto
            match = match_actions[node][0]
            actions = match_actions[node][1]
            flow_id = self.caller_app.add_flow(dp, priority,
                                                  match, actions,
                                                  hard_timeout=hard_timeout,
                                                  idle_timeout=idle_timeout,
                                                  flags=ofproto.OFPFF_SEND_FLOW_REM,
                                                  caller=self)

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

