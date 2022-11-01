from pathlib import Path
from typing import Type

import ServerResponse
import re
import os
import logging
import sys
import time

def read_config_eavesdropper(config_file: str):
    client_port_read = 0
    client_port = ''
    server_port_read = 0
    server_port = ''
    spy_path_read = 0
    spy_path = ''
    with open(config_file, mode='r', encoding='utf-8') as f:
        for line in f:
            line = line.strip('\n').split('=')
            if line[0] == "client_port" and client_port_read == 0:
                client_port = line[1]
                client_port_read = 1
            elif line[0] == "server_port" and server_port_read == 0:
                server_port = line[1]
                server_port_read = 1
            elif line[0] == "spy_path" and spy_path_read == 0:
                spy_path = line[1]
                spy_path_read = 1
            elif line[0] == "client_port" and client_port_read:
                sys.exit(2)
            elif line[0] == "server_port" and server_port_read:
                sys.exit(2)
            elif line[0] == "spy_path" and spy_path_read:
                sys.exit(2)

    if '' in (client_port, server_port, spy_path):
        sys.exit(2)

    if not client_port.isdigit() or not server_port.isdigit():
        sys.exit(2)

    if not os.access(path_parse(spy_path), os.W_OK):
        sys.exit(2)

    if int(client_port) <= 1024 or int(server_port) <= 1024:
        sys.exit(2)

    logging.debug("client_port: " + str(client_port) + ", spy_path: " + str(path_parse(spy_path)))
    return [int(client_port), int(server_port), str(path_parse(spy_path))]

def read_config_server(config_file: str):
    server_port_read = 0
    server_port = ''
    inbox_path_read = 0
    inbox_path = ''
    with open(config_file, mode='r', encoding='utf-8') as f:
        for line in f:
            line = line.strip('\n').split('=')
            if line[0] == "server_port" and server_port_read == 0:
                server_port = line[1]
                server_port_read = 1
            elif line[0] == "inbox_path" and inbox_path_read == 0:
                inbox_path = line[1]
                inbox_path_read = 1
            elif line[0] == "server_port" and server_port_read:
                sys.exit(2)
            elif line[0] == "inbox_path" and inbox_path_read:
                sys.exit(2)

    if '' in (server_port, inbox_path):
        sys.exit(2)

    if not server_port.isdigit():
        sys.exit(2)

    if not os.access(path_parse(inbox_path), os.W_OK):
        sys.exit(2)

    if int(server_port) <= 1024:
        sys.exit(2)

    logging.debug("server_port: " + str(server_port) + ", inbox_path: " + str(path_parse(inbox_path)))
    return [int(server_port), str(path_parse(inbox_path))]

def read_config_client(config_file: str):
    server_port_read = 0
    server_port = ''
    send_path_read = 0
    send_path = ''
    with open(config_file, mode='r', encoding='utf-8') as f:
        for line in f:
            line = line.strip('\n').split('=')
            if line[0] == "server_port" and server_port_read == 0:
                server_port = line[1]
                server_port_read = 1
            elif line[0] == "send_path" and send_path_read == 0:
                send_path = line[1]
                send_path_read = 1
            elif line[0] == "server_port" and server_port_read:
                sys.exit(2)
            elif line[0] == "send_path" and send_path_read:
                sys.exit(2)

    if '' in (server_port, send_path):
        sys.exit(2)

    if not server_port.isdigit():
        sys.exit(2)

    if not os.access(path_parse(send_path), os.R_OK) or int(server_port) <= 1024:
        sys.exit(2)

    logging.debug("server_port: " + str(server_port) + ", send_path: " + str(path_parse(send_path)))
    return [int(server_port), str(path_parse(send_path))]

def response_server_parse(data: str) -> list[str]:
    return [data[0:3], data[4:]]

def path_parse(path: str):
    if path[0:2] == '~/':
        path = path[2:]
        logging.debug("path_parser: " + str(Path.home() / Path(path)))

    return Path.home() / Path(path)

def print_server_stdout(str_to_print: str, pid='', order=''):
    if str(pid).isdigit() and str(order).isdigit():
        print(f"[{pid}][{order}]S: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')
    else:
        print(f"S: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')


def print_client_stdout(str_to_print: str, pid='', order=''):
    if str(pid).isdigit() and str(order).isdigit():
        print(f"[{pid}][{order}]C: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')
    else:
        print(f"C: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')

def print_eavesdropper_server_stdout(str_to_print: str):
    print(f"AS: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')

def print_eavesdropper_client_stdout(str_to_print: str):
    print(f"AC: {str_to_print}\r\n", file=sys.stdout, flush=True, end='')

def smtp_decode(str_to_decode: str) -> str:
    return str_to_decode.decode('utf-8', errors='ignore').strip('\r\n')

def smtp_encode(str_to_encode: str) -> str:
    return (str_to_encode + '\r\n').encode()

def construct_message(code: str, parameter: str) -> str:
    return code + " " + parameter

def rfc5322_to_utc(date: str) -> str:
    return str(int(time.mktime(time.strptime(date, "%a, %d %b %Y %H:%M:%S %z"))))

def mail_write(src: list[str], dst: list[str], body: list[str], inbox: str, authentication: int, pid='', order=''):
    # Scan the body for the date and subject
    date_read = 0
    subject_read = 0
    txt_file = "unknown.txt"
    subject = ""
    for line in body:
        if not date_read and line.startswith("Date: "):
            date = line[6:]
            txt_file = rfc5322_to_utc(date)
            body.remove(line)
            date_read = 1

    for line in body:
        if not subject_read and line.startswith("Subject: "):
            subject = line[9:]
            body.remove(line)
            subject_read = 1

    # Check for authentication by client
    if authentication:
        txt_file = "auth." + txt_file

    # Check for pid and order
    if str(pid).isdigit() and str(order).isdigit():
        txt_file = f"[{pid}][{order}]" + txt_file

    # Write to the text file
    txt_file = inbox + "/" + txt_file + ".txt"
    with open(txt_file, mode='w', encoding='utf-8') as f:
        f.write("From: " + src[0] + "\n")
        f.write("To: " + ', '.join(dst) + "\n")
        f.write("Date: " + date + "\n")
        f.write("Subject: " + subject + "\n")
        if len(body) > 0:
            f.write('\n'.join(body))
            f.write('\n')

LET_DIG = "[a-zA-Z0-9]+"
ATOM = LET_DIG + "([a-zA-Z0-9]+|-)*"
DOT_STRING = "(" + ATOM + ")" + "(\.[a-zA-Z0-9]+([a-zA-Z0-9]+|-)*)*"
ADDRESS_LITERAL = "\[((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\]"
SUB_DOMAIN = "(" + LET_DIG + ")" + "(([a-zA-Z0-9]+|-)*[a-zA-Z0-9]+)?"
DOMAIN = "(" + SUB_DOMAIN + "(\.([a-zA-Z0-9]+)(([a-zA-Z0-9]+|-)*[a-zA-Z0-9]+)?)+" +")" + "|" + ADDRESS_LITERAL
EMAIL = DOT_STRING + "@" + DOMAIN

LOCALHOST = '127.0.0.1'
EHLO_REGEX = re.compile(r'^(EHLO)\s(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})$')
MAILFROM_REGEX = re.compile(rf'^(MAIL FROM:)(<({EMAIL})>)$')
RCPTTO_REGEX = re.compile(rf'^(RCPT TO:)(<({EMAIL})>)$')
DATE_RFC5322_REGEX = re.compile(r'^(((Mon|Tue|Wed|Thu|Fri|Sat|Sun))[,]?\s[0-9]{1,2})\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s([0-9]{4})\s([0-9]{2}):([0-9]{2})(:([0-9]{2}))?\s([\+|\-][0-9]{4})\s?$')
EMAIL_ABNF_REGEX = re.compile(rf'^(<({EMAIL})>)$')
