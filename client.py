from typing import Type
from pathlib import Path

import os
import socket
import sys
import logging
import secrets
import hmac
import base64

from util import (
    read_config_client,
    response_server_parse,
    smtp_decode,
    smtp_encode,
    print_server_stdout,
    print_client_stdout,
    EMAIL_ABNF_REGEX,
    DATE_RFC5322_REGEX,
    LOCALHOST,
    construct_message,
)

logging.disable(logging.CRITICAL)

PERSONAL_ID = '9B27EF'
PERSONAL_SECRET = 'e9a5afdcac596ed06ab6825601b7b0de'

def main(arg):
    if len(arg) < 2:
        sys.exit(1)

    # Only 1 send_path valid
    server_port, send_path = read_config_client(arg[1])
    mailbox = [ f for f in os.listdir(send_path) if os.path.isfile(os.path.join(send_path, f)) ] # Sorted emails

    for mail in sorted(mailbox):
        logging.debug("mail: " + str(mail))
        authenticated_p, sender_info, recipient_info, date, subject, body = mail_format(send_path, mail)
        # Bad format in mail, go to next valid email
        if None in (sender_info, recipient_info, date, subject, body):
            print_client_stdout(f"{send_path}/{mail}: Bad formation")
            continue
        mail_transaction(authenticated_p, sender_info, recipient_info, date, subject, body, server_port)

def mail_transaction(auth: int, sender: list[str], recipient: list[str], date: str, subject: str, body: list[str], port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect(('localhost', port))
        except socket.error:
            print_client_stdout("Cannot establish connection")
            sys.exit(3)

        while True:
            server_response = s.recv(1024)
            raw_server_response = smtp_decode(server_response)

            if raw_server_response.endswith("250 AUTH CRAM-MD5"):
                raw_server_response = raw_server_response.split("\r\n")
                print_server_stdout(raw_server_response[0])
                print_server_stdout(raw_server_response[1])
                smtp_code, smtp_parameter = response_server_parse(raw_server_response[0])
            else:
                print_server_stdout(raw_server_response)
                smtp_code, smtp_parameter = response_server_parse(raw_server_response)

            if smtp_code == "220":
                s.sendall(smtp_encode(f"EHLO {LOCALHOST}"))
                print_client_stdout(f"EHLO {LOCALHOST}")
            elif smtp_code == "250":
                if auth:
                    s.sendall(smtp_encode("AUTH CRAM-MD5"))
                    print_client_stdout("AUTH CRAM-MD5")
                elif smtp_parameter == LOCALHOST:
                    source_buffer = "MAIL FROM:" + sender[0]
                    s.sendall(smtp_encode(source_buffer))
                    print_client_stdout(source_buffer)
                elif smtp_parameter == "Requested mail action okay completed":
                    if len(recipient) != 0:
                        destination_buffer = "RCPT TO:" + recipient[0]
                        s.sendall(smtp_encode(destination_buffer))
                        print_client_stdout(destination_buffer)
                        recipient.remove(recipient[0])
                    elif len(recipient) == 0 and len(body) == 0 and len(date) == 0 and len(subject) == 0:
                        s.sendall(smtp_encode("QUIT"))
                        print_client_stdout("QUIT")
                        smtp_code, smtp_parameter = response_server_parse(smtp_decode(s.recv(1024)))
                        print_server_stdout(construct_message(smtp_code, smtp_parameter))
                        return
                    elif len(recipient) == 0:
                        s.sendall(smtp_encode("DATA"))
                        print_client_stdout("DATA")
            elif smtp_code == "235":
                source_buffer = "MAIL FROM:" + sender[0]
                s.sendall(smtp_encode(source_buffer))
                print_client_stdout(source_buffer)
            elif smtp_code == "334":
                md5digest_client = PERSONAL_ID + " " + md5digest_client + hmac.new(PERSONAL_SECRET.encode(), base64.b64decode(smtp_parameter), 'md5').hexdigest()
                s.sendall(smtp_encode(md5digest_client.encode()))
                print_client_stdout(md5digest_client)
            elif smtp_code == "354":
                if date != '':
                    s.sendall(smtp_encode("Date: " + date))
                    print_client_stdout("Date: " + date)
                    date = ''
                elif subject != '':
                    s.sendall(smtp_encode("Subject: " + subject))
                    print_client_stdout("Subject: " + subject)
                    subject = ''
                elif len(body) != 0:
                    s.sendall(smtp_encode(body[0]))
                    print_client_stdout(body[0])
                    body.remove(body[0])
                elif len(body) == 0:
                    s.sendall(smtp_encode("."))
                    print_client_stdout(".")

def mail_format(path, mail: str) -> list[str]:
    body = []
    authenticated_p = 0
    if mail.startswith("auth-"):
        authenticated_p = 1

    with open(path / Path(mail), mode='r', encoding='utf-8') as m:
        for i, line in enumerate(m):
            line = line.strip('\n')
            if i == 0:
                sender_info = sender_info_parse(line)
            elif i == 1:
                recipient_info = recipient_info_parse(line)
            elif i == 2:
                date = date_parse(line)
            elif i == 3:
                subject = subject_parse(line)
            else:
                body.append(line)
    logging.debug("body: " + str(body))
    return [authenticated_p, sender_info, recipient_info, date, subject, body]

def sender_info_parse(line: str) -> list[str]:
    if line.startswith("From: "):
        if EMAIL_ABNF_REGEX.search(line[6:]) is not None:
            return [EMAIL_ABNF_REGEX.search(line[6:]).group()]
    return None

def recipient_info_parse(line: str) -> list[str]:
    if line.startswith("To: "):
        list_of_email = line[4:].split(',')
        if len(list_of_email) <= 0:
            return None
        recipient_info = [EMAIL_ABNF_REGEX.search(email).group() for email in list_of_email]
        if None in recipient_info:
            return None
        return recipient_info
    return None

def date_parse(line: str) -> str:
    if line.startswith("Date: "):
        if DATE_RFC5322_REGEX.search(line[6:]) is not None:
            return DATE_RFC5322_REGEX.search(line[6:]).group()
    return None

def subject_parse(line: str) -> str:
    if line.startswith("Subject: "):
        return line[9:]
    return None

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    main(sys.argv)
