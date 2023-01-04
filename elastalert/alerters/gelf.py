import json
import socket
import ssl

import requests
from requests import RequestException

from elastalert.alerts import Alerter
from elastalert.util import EAException, elastalert_logger


class GelfAlerter(Alerter):
    required_options = set(['gelf_type'])

    def __init__(self, rule):
        super(GelfAlerter, self).__init__(rule)
        self.gelf_type = self.rule.get('gelf_type')
        self.gelf_endpoint = self.rule.get('gelf_endpoint')
        self.gelf_host = self.rule.get('gelf_host')
        self.gelf_port = self.rule.get('gelf_port')
        if 'http' in self.gelf_type:
            if self.gelf_endpoint is None:
                raise EAException('Error! Gelf http required "gelf_endpoint" variable')
        elif 'tcp':
            if self.gelf_host is None or self.gelf_port is None:
                raise EAException('Error! Gelf tcp required "gelf_host" and "gelf_port" variables')
        self.fields = self.rule.get('gelf_payload', {})
        self.headers = {
            'Content-Type': 'application/json'
        }
        self.gelf_version = self.rule.get('gelf_version', '1.1')
        self.gelf_log_level = self.rule.get('gelf_log_level', 5)
        self.additional_headers = self.rule.get('gelf_http_headers')
        self.ca_cert = self.rule.get('gelf_ca_cert', False)
        self.http_ignore_ssl_errors = self.rule.get('gelf_http_ignore_ssl_errors', False)
        self.timeout = self.rule.get('gelf_timeout', 30)

    def send_http(self, gelf_msg):

        if self.additional_headers:
            self.headers.update(self.additional_headers)

        if self.ca_cert:
            verify = self.ca_cert
        else:
            verify = False

        if self.http_ignore_ssl_errors:
            requests.packages.urllib3.disable_warnings()

        try:
            requests.post(url=self.gelf_endpoint, headers=self.headers, json=gelf_msg, verify=verify,
                          timeout=self.timeout)

        except RequestException as e:
            raise EAException("Error posting GELF message via HTTP: %s" % e)
        elastalert_logger.info("GELF message sent via HTTP.")

    def sent_tcp(self, gelf_msg):
        bytes_msg = json.dumps(gelf_msg).encode('utf-8') + b'\x00'
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(self.timeout)

        tcp_socket.connect((self.gelf_host, self.gelf_port))

        try:
            if self.ca_cert:
                tcp_socket = ssl.wrap_socket(tcp_socket, ca_certs=self.ca_cert)
                tcp_socket.sendall(bytes_msg)
            else:
                tcp_socket.sendall(bytes_msg)

        except socket.error as e:
            raise EAException("Error posting GELF message via TCP: %s" % e)
        elastalert_logger.info("GELF message sent via TCP.")

    def alert(self, matches):
        """
        Each match will trigger a POST GELF message to the endpoint.
        """
        alert_message = {
            'Title': self.rule.get('name')
        }

        for match in matches:
            for key, value in self.fields.items():
                alert_message.update(
                    {
                        key: match.get(value)
                    }
                )

        gelf_msg = {
            'version': self.gelf_version,
            'host': socket.getfqdn(),
            'short_message': json.dumps(alert_message),
            'level': self.gelf_log_level,
        }

        if self.gelf_type == 'http':
            return self.send_http(gelf_msg)
        elif self.gelf_type == 'tcp':
            return self.sent_tcp(gelf_msg)

    def get_info(self):
        return {'type': 'gelf',
                'gelf_type': self.gelf_type}
