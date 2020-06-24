#!/usr/bin/python3
# Reverse compatibility stuffs
from __future__ import absolute_import, division, print_function

import argparse
import logging
import os
import socket
import sys
from builtins import (int, range, str)

def set_logging(log_level):
    # Set logging level. Log to directory script was run from as __file__.stderr
    logging_level = getattr(logging, log_level.upper())
    # TODO Put script log in a better place
    log_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.splitext(os.path.basename(os.path.abspath(__file__)))[0]
    # Set basic logging configuration
    logging.basicConfig(filename='{dir}/{file}.stderr'.format(
        dir=log_dir,
        file=log_file,
        level=logging_level,
        format='%(asctime)s %(levelname)-8s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout))
    # add info level meessage to log to show start of process
    logging.info('Logging to {dir}/{file}'.format(dir=log_dir, file=log_file))



def create_socket(path):
    server_address = path
    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Bind the socket to the file
    logging.info('Starting unix stream socket located at {}'.format(path))
    sock.bind(server_address)
    return sock


def linesplit(socket):
    buffer = socket.recv(4096)
    buffering = True
    while buffering:
        if "\n" in buffer:
            (line, buffer) = buffer.split("\n", 1)
            yield line
        else:
            more = socket.recv(4096)
            if not more:
                buffering = False
            else:
                buffer += more
    if buffer:
        yield buffer



def read_data(sock):
    # Listen for incoming connections
    sock.listen(1)
    logging.info('Socket ready for incoming connections')

    # Wait for a connection
    logging.info('Waiting for a connection')
    connection, client_address = sock.accept()
    while True:
        try:
            logging.info('Connection from {}'.format(client_address))
            # Receive the data in chunks based on buffer
            # Buffer size should be large enough to get a full eve alert in a single data chunk
            while True:
                # TODO Read from the buffer
                data = linesplit(connection)
                print(data)
        finally:
            # Clean up the connection
            connection.close()


def run():


    # Set the logging level based on the config
    set_logging("INFO")

    # make sure we are working in the directory of the python executable
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Create the socket and Begin Reading data
    socket = "/dev/suricata_alert"
    read_data(create_socket(socket))


if __name__ == '__main__':
    run()