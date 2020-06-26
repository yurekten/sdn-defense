import datetime
import json
import os
import socket

SOCKFILE = "/tmp/suricata_ids.socket"


def test():
    if os.path.exists(SOCKFILE):
        os.unlink(SOCKFILE)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(SOCKFILE)
        sock.listen(5)
        while True:
            connection = None
            try:
                # Wait for a connection
                print('Waiting for a connection')
                connection, client_address = sock.accept()
                while True:
                    data = read_socket(connection)
                    if data is not None:
                        for item in data:
                            print(f'{datetime.datetime.now()} -> {item}')

            finally:
                if connection is not None:
                    # Clean up the connection
                    connection.close()


def read_socket(socket):
    buffer = socket.recv(4096 * 2)
    buf_data = buffer.decode("utf-8").strip()
    data = buf_data.split('\n')

    result_list = []
    try:
        for d in data:
            json_data = json.loads(d)
            result_list.append(json_data)
    except Exception as e:
        print(e)
        return None
    return result_list


test()
