from ServerResponse import ServerResponse
# from signal import SIGINT, signal
from pathlib import Path

import signal
import socket
import logging
import sys
import hmac
import secrets
import time
import base64

from util import (
    read_config_server,
    print_server_stdout,
    print_client_stdout,
    smtp_encode,
    smtp_decode,
    EHLO_REGEX,
    MAILFROM_REGEX,
    RCPTTO_REGEX,
    rfc5322_to_utc,
    mail_write,
)

logging.disable(logging.CRITICAL)

PERSONAL_ID = '9B27EF'
PERSONAL_SECRET = 'e9a5afdcac596ed06ab6825601b7b0de'

def main(arg):
    if (len(arg) < 2): # No configuration file
        sys.exit(1)

    server_port, inbox_path = read_config_server(arg[1])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_p = 1

        try:
            s.bind(('localhost', server_port))
        except socket.error: # Cannot bind socket to port
            sys.exit(2)

        while listen_p:
            s.listen()
            conn, addr = s.accept()
            listen_p = connection_handler(conn, inbox_path)

def connection_handler(conn: socket.socket, inbox: str, pid='', order='') -> int:
    mail_sequence = [0, 0, 0, 0] # EHLO, MAIL, RCPT, DATA
    source_buffer = []
    destination_buffer = []
    data_buffer = []

    ongoing_p = 1
    rset_p = 0
    authenticated_p = 0

    with conn:
        signal.signal(signal.SIGINT, lambda signum, frame: sigint_handler(signum, frame, conn, pid, order))

        conn.sendall(smtp_encode(str(ServerResponse.s220)))
        print_server_stdout(ServerResponse.s220, pid, order)

        while ongoing_p:
            raw_client_response = conn.recv(1024)

            if not raw_client_response:
                print_server_stdout("Connection lost", pid, order)
                return 1

            client_response = smtp_decode(raw_client_response)

            # Log client response
            print_client_stdout(client_response, pid, order)

            if mail_sequence == [1, 1, 1, 1]: # Check EHLO, MAIL, RCPT, DATA is issued
                if client_response == '.': # End of data buffer reading
                    server_response = ServerResponse.s250
                    mail_write(source_buffer, destination_buffer, data_buffer, inbox, authenticated_p, pid, order)
                    mail_sequence = [1, 0, 0, 0] # Prepare for new client mail request
                    source_buffer = []
                    destination_buffer = []
                    data_buffer = []
                else:
                    server_response = ServerResponse.s354
                    data_buffer.append(client_response) # Append to data buffer reading
            elif client_response.startswith("RSET"):
                server_response, rset_p = rset_parse(client_response)
            elif client_response.startswith("EHLO"):
                server_response, rset_p = ehlo_parse(client_response)
                if not isinstance(server_response, ServerResponse) and server_response[0] == "250":
                    mail_sequence = [1, 0, 0, 0]
                    source_buffer = []
                    destination_buffer = []
                    data_buffer = []
                    rset_p = 0

                    to_client = server_response[0] + " " + server_response[1] + f"\r\n{server_response[2]}"
                    conn.sendall(smtp_encode(to_client))
                    print_server_stdout(server_response[0] + " " + server_response[1], pid, order)
                    print_server_stdout(server_response[2], pid, order)
                    continue
            elif client_response.startswith("MAIL"):
                # Check EHLO is issued
                if mail_sequence == [1, 0, 0, 0]:
                    if mailfrom_valid(client_response):
                        server_response, source_addr = mailfrom_parse(client_response)
                        source_buffer = []
                        source_buffer.append(source_addr)
                        destination_buffer = []
                        data_buffer = []
                        mail_sequence[1] = 1
                    elif client_response.startswith(("MAIL", "MAIL ")):
                        server_response = ServerResponse.e501
                    else:
                        server_response = ServerResponse.e500
                elif mailfrom_valid(client_response) or client_response.startswith(("MAIL", "MAIL ")): # MAIL sent in wrong order
                    server_response = ServerResponse.e503
                else:
                    server_response = ServerResponse.e500
            elif client_response.startswith("RCPT"):
                # Check EHLO, MAIL is issued and DATA is not issued
                if [mail_sequence[0], mail_sequence[1], mail_sequence[3]] == [1, 1, 0]:
                    if rcptto_valid(client_response):
                        server_response, destination_addr = rcptto_parse(client_response)
                        destination_buffer.append(destination_addr)
                        mail_sequence[2] = 1
                    elif client_response.startswith(("RCPT", "RCPT ")) or any(x in client_response for x in (' ', '\t')):
                        server_response = ServerResponse.e501
                    else:
                        server_response = ServerResponse.e500
                elif rcptto_valid(client_response) or client_response.startswith(("RCPT", "RCPT ")) or any(x in client_response for x in (' ', '\t')): # RCPT sent in wrong order
                    server_response = ServerResponse.e503
                else:
                    server_response = ServerResponse.e500
            elif client_response.startswith("DATA"):
                # Check EHLO, MAIL, RCPT is issued
                if mail_sequence == [1, 1, 1, 0]:
                    server_response, mail_sequence[3] = data_parse(client_response)
                else:
                    server_response, dummy = data_parse(client_response)
                    if server_response.value[0] == "354":
                        server_response = ServerResponse.e503
            elif client_response.startswith("NOOP"):
                server_response = noop_parse(client_response)
            elif client_response.startswith("AUTH"):
                server_response, b64challenge = auth_parse(client_response)
                # Check EHLO is issued
                if mail_sequence == [1, 0, 0 ,0]:
                    if server_response.value[0] == "334": # Challenge successful
                        conn.sendall(smtp_encode(server_response.value[0] + " " + b64challenge.decode()))
                        print_server_stdout(server_response, pid, order)

                        # Retrieve client challenge response
                        client_response = smtp_decode(conn.recv(1024))
                        print_client_stdout(client_response, pid, order)
                        if client_response == "*": # Client cancels challenge
                            server_response = ServerResponse.e503
                        else:
                            if verify_digest(client_response, b64challenge): # Verify client challenge
                                server_response = ServerResponse.s235
                                authenticated_p = 1
                            else:
                                server_response = ServerResponse.e535
                else:
                    if server_response.value[0] == "334":
                        server_response = ServerResponse.e503
            elif client_response.startswith("QUIT"):
                server_response, ongoing_p = quit_parse(client_response)
                # Prepare client disconnection
                if server_response.value[0] == "221":
                    conn.sendall(smtp_encode(str(server_response)))
                    print_server_stdout(server_response, pid, order)
                    return 1
            else:
                server_response = ServerResponse.e500

            if rset_p:
                mail_sequence[1] = 0
                mail_sequence[2] = 0
                mail_sequence[3] = 0
                source_buffer = []
                destination_buffer = []
                data_buffer = []
                rset_p = 0

            conn.sendall(smtp_encode(str(server_response)))
            print_server_stdout(server_response, pid, order)

def quit_parse(response: str):
    # return (0, 1) - (Close the connection with client, Connection with client is still ongoing)
    if response == "QUIT":
        return ServerResponse.s221, 0
    elif any(x in response for x in (' ', '\t')):
        return ServerResponse.e501, 1
    else:
        return ServerResponse.e500, 1

def verify_digest(client: str, b64challenge: str):
    b64decode_challenge = base64.b64decode(b64challenge) # bytes object
    b64decode_client = base64.b64decode(client).decode() # bytes object -> str object

    # Extract the md5 digest of the client
    b64decode_client = b64decode_client.split(' ')

    # Cannot find username appened to challenge
    try:
        md5digest_client = b64decode_client[1]
    except IndexError:
        return 0

    # Server calculate the digest itself
    md5digest_server = hmac.new(PERSONAL_SECRET.encode(), b64decode_challenge, 'md5').hexdigest()

    return md5digest_client == md5digest_server

def auth_parse(response: str):
    # return (b64challenge, None)
    if response == "AUTH CRAM-MD5":
        b64challenge = base64.b64encode(secrets.token_bytes(32).decode(errors='ignore').encode('ascii', errors='ignore'))
        return ServerResponse.s334, b64challenge
    elif any(x in response for x in (' ', '\t')) or response.startswith("AUTH "):
        return ServerResponse.e501, None
    else:
        return ServerResponse.e500, None

def noop_parse(response: str):
    if response == "NOOP":
        return ServerResponse.s250
    elif any(x in response for x in (' ', '\t')):
        return ServerResponse.e501
    else:
        return ServerResponse.e500

def data_parse(response: str):
    # return (0, 1) - (mail_sequence, mail_sequence)
    if response == "DATA":
        return ServerResponse.s354, 1
    elif any(x in response for x in (' ', '\t')):
        return ServerResponse.e501, 0
    else:
        return ServerResponse.e500, 0

def rcptto_parse(response: str):
    return ServerResponse.s250, RCPTTO_REGEX.search(response).group(2)

def rcptto_valid(response: str):
    if RCPTTO_REGEX.match(response):
        return True
    return False

def mailfrom_parse(response: str):
    return ServerResponse.s250, MAILFROM_REGEX.search(response).group(2)

def mailfrom_valid(response: str):
    if MAILFROM_REGEX.match(response):
        return True
    return False

def ehlo_parse(response: str):
    # return (0, 1) - rset_p
    if EHLO_REGEX.match(response):
        return ["250", "127.0.0.1", "250 AUTH CRAM-MD5"], 1
    elif any(x in response for x in (' ', '\t')) or response == "EHLO":
        return ServerResponse.e501, 0
    else:
        return ServerResponse.e500, 0

def rset_parse(response: str):
    # return (0, 1) - rset_p
    if response == "RSET":
        return ServerResponse.s250, 1
    elif any(x in response for x in (' ', '\t')):
        return ServerResponse.e501, 0
    else:
        return ServerResponse.e500, 0

def sigint_handler(signum, frame, conn, pid, order):
    print_server_stdout("SIGINT received, closing", pid, order)
    conn.sendall(smtp_encode(str(ServerResponse.s421)))
    print_server_stdout(str(ServerResponse.s421), pid, order)
    conn.close()
    sys.exit(0)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    main(sys.argv)
