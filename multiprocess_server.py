import server
import os
import sys
import socket
import signal

from util import (
    read_config_server,
)

def main(arg):
    if (len(arg) < 2):
        sys.exit(1)

    child_client = []
    server_port, inbox_path = read_config_server(arg[1])

    signal.signal(signal.SIGINT, handler)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            s.bind(('localhost', server_port))
        except socket.error: # Cannot bind socket to port
            sys.exit(2)

        i = 1
        while True:
            s.listen()
            client_conn, addr = s.accept()
            child_pid = os.fork()
            child_client.append(child_pid)
            if child_pid == 0:
                listen_p = server.connection_handler(client_conn, inbox_path, os.getpid(), i)
                while listen_p:
                    s.listen()
                    client_conn, addr = s.accept()
                    listen_p = server.connection_handler(client_conn, inbox_path, os.getpid(), i)
                break
            else:
                i+=1

def handler(signum, frame):
    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
