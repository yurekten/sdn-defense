import os
import pathlib
import socket
import threading
from queue import Queue, Empty
from urllib.parse import urlparse

from utils.common_utils import is_valid_remote_ip


def create_ip_rep():
    CURRENT_PATH = pathlib.Path().absolute()

    filename = 'url-list.txt'
    ip_whitelist_file = 'ip_whitelist.txt'
    file_path = os.path.join(CURRENT_PATH, ip_whitelist_file)
    with open(file_path) as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    ip_whitelist = [x.strip() for x in content]

    queue = Queue()

    file_path = os.path.join(CURRENT_PATH, filename)
    with open(file_path) as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    content = [x.strip() for x in content]
    counter = 0
    for item in content:
        counter = counter + 1
        queue.put_nowait((counter, item))

    ip_list = {}
    thread_list = []
    for i in range(0, 100):
        thread = threading.Thread(target=_queue_worker, args=(str(i), queue, ip_list, ip_whitelist))
        thread.start()
        thread_list.append(thread)

    for thread in thread_list:
        thread.join()


    with open('iprep.list', 'w') as writer:
        for item in ip_list:
            value = ip_list[item]
            tab = "\t\t"
            if len(str(item)) >= 14:
                tab = "\t"
            comments = ", ".join(value["comments"])
            writer.write(item + "," + str(value["category"]) + "," + str(value["score"]) + tab + "# " + comments + "\r\n")



def _queue_worker(name, queue, ip_list, ip_whitelist):
    valid = True
    item = None
    try:
        item = queue.get(block=False)
    except Empty:
        valid = False
    while valid:

        parsed_uri = urlparse(item[1])
        try:
            # ip_add = query(parsed_uri.hostname, 'A')
            ipval = socket.gethostbyname(parsed_uri[2])
            if ipval not in ip_whitelist and is_valid_remote_ip(ipval):
                # for ipval in ip_add:
                print(f'{item[0]} - Thread - {name}: {item[1]} -> {ipval}')
                if ipval not in ip_list:
                    ip_list[ipval] = {}
                    ip_list[ipval]["category"] = 1
                    ip_list[ipval]["score"] = 100
                    ip_list[ipval]["comments"] = []
                ip_list[ipval]["comments"].append(str(item[1]))

            else:
                print(f'{item[0]} - Thread - {name}: {item[1]} -> {ipval} is in whitelist or invalid remote ip')

        except Exception:
            print(f'{item[0]} - Thread - {name}: {item[1]} -> None')

        try:
            item = queue.get(block=False)
        except Empty:
            valid = False

create_ip_rep()