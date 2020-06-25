import os
import pathlib
import threading
from queue import Queue, Empty
import socket
from dns.resolver import query, NoNameservers, NoAnswer, NXDOMAIN
from urllib.parse import urlparse

def read_file():
    CURRENT_PATH = pathlib.Path().absolute()

    filename = 'url-list.txt'
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

    ip_list = []
    thread_list = []
    for i in range(0, 50):
        thread = threading.Thread(target=_queue_worker, args=(str(i), queue, ip_list))
        thread.start()
        thread_list.append(thread)

    for thread in thread_list:
        thread.join()

    with open('../defense_managers/blacklist/ip_blacklist.txt', 'w') as writer:
        for item in ip_list:
            writer.write(str(item)+"\n")


def _queue_worker(name, queue, ip_list):
    valid = True
    item = None
    try:
        item = queue.get(block=False)
    except Empty:
        valid = False
    while valid:
        try:
            parsed_uri = urlparse(item[1])
            #ip_add = query(parsed_uri.hostname, 'A')
            ipval = socket.gethostbyname(parsed_uri[2])
            #for ipval in ip_add:
            print(f'{item[0]} - Thread - {name}: {item[1]} -> {ipval}')
            ip_list.append((item[1], ipval))
        except Exception:
            print(f'{item[0]} - Thread - {name}: {item[1]} -> None')
            #ip_list.append((item[1], None))


        try:
            item = queue.get(block=False)
        except Empty:
            valid = False



read_file()