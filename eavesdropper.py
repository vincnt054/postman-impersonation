from ServerResponse import ServerResponse
from signal import SIGINT, signal
from pathlib import Path

import socket
import logging
import sys

from util import (
    read_config_eavesdropper,
    print_server_stdout,
    print_client_stdout,
    print_eavesdropper_server_stdout,
    print_eavesdropper_client_stdout,
    smtp_encode,
    smtp_decode,
    mail_write,
)

logging.disable(logging.CRITICAL)

def main(arg):
    if (len(arg) < 2): # No configuration file
        sys.exit(1)
    client_port, server_port, spy_path = read_config_eavesdropper(arg[1])

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_sock.bind(('localhost', client_port))
    client_sock.listen()
    client_conn, client_addr = client_sock.accept()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect(('localhost', server_port))
    except socket.error:
        print_eavesdropper_server_stdout("Cannot establish connection")
        sys.exit(3)

    man_in_the_middle(client_conn, server_sock, spy_path)

def man_in_the_middle(client_conn: socket.socket, server_sock: socket.socket, spy_path: str):
    source_buffer = []
    destination_buffer = []
    body_buffer = []
    authenticated_p = 0
    body_reading_p = 0

    while client_conn:
        while True:
            # Retrieve server message
            server_response = server_sock.recv(1024)

            raw_server_response = smtp_decode(server_response)
            if raw_server_response.endswith("250 AUTH CRAM-MD5"):
                raw_server_response = raw_server_response.split("\r\n")
                print_server_stdout(raw_server_response[0])
                print_server_stdout(raw_server_response[1])
                print_eavesdropper_client_stdout(raw_server_response[0])
                print_eavesdropper_client_stdout(raw_server_response[1])
            else:
                print_server_stdout(raw_server_response)
                print_eavesdropper_client_stdout(raw_server_response)

            # Send to the client
            client_conn.sendall(server_response)

            # Retrieve the client response
            client_response = client_conn.recv(1024)
            raw_client_response = smtp_decode(client_response)

            print_client_stdout(raw_client_response)
            print_eavesdropper_server_stdout(raw_client_response)

            # Capture the client response
            if body_reading_p:
                if raw_client_response == ".":
                    body_reading_p = 0
                    mail_write(source_buffer, destination_buffer, body_buffer, spy_path, authenticated_p)
                else:
                    body_buffer.append(raw_client_response)
            elif raw_client_response.startswith("MAIL FROM:"):
                source_buffer.append(raw_client_response[10:])
            elif raw_client_response.startswith("RCPT TO:"):
                destination_buffer.append(raw_client_response[8:])
            elif raw_client_response == "DATA":
                body_reading_p = 1
            elif raw_client_response == "QUIT":
                # Send client QUIT response
                server_sock.sendall(client_response)

                # Retrieve the server response
                server_response = server_sock.recv(1024)
                raw_server_response = smtp_decode(server_response)
                print_server_stdout(raw_server_response)
                print_eavesdropper_client_stdout(raw_server_response)

                # Send to the client final message
                client_conn.sendall(server_response)
                sys.exit(0)

            # Send to the server
            server_sock.sendall(client_response)

if __name__ == "__main__":
    main(sys.argv)
