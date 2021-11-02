import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import lookup_es_key, EAException, elastalert_logger
from jinja2 import Template


class HTTPPost2Alerter(Alerter):
    """ Requested elasticsearch indices are sent by HTTP POST. Encoded with JSON. """
    required_options = frozenset(['http_post2_url'])

    def __init__(self, rule):
        super(HTTPPost2Alerter, self).__init__(rule)
        post_url = self.rule.get('http_post2_url', None)
        if isinstance(post_url, str):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('http_post2_proxy', None)
        self.post_payload = self.rule.get('http_post2_payload', {})
        self.post_raw_fields = self.rule.get('http_post2_raw_fields', {})
        self.post_all_values = self.rule.get('http_post2_all_values', not self.post_payload)
        self.post_http_headers = self.rule.get('http_post2_headers', {})
        self.post_ca_certs = self.rule.get('http_post2_ca_certs')
        self.post_ignore_ssl_errors = self.rule.get('http_post2_ignore_ssl_errors', False)
        self.timeout = self.rule.get('http_post2_timeout', 10)

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """
        for match in matches:
            payload = match if self.post_all_values else {}
            for post_key, post_value in list(self.post_payload.items()):
                post_key_template = Template(post_key)
                post_key_res = post_key_template.render(**match)
                post_value_template = Template(post_value)
                post_value_res = post_value_template.render(**match)
                payload[post_key_res] = post_value_res

            for post_key, es_key in list(self.post_raw_fields.items()):
                payload[post_key] = lookup_es_key(match, es_key)

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json;charset=utf-8"
            }
            if self.post_ca_certs:
                verify = self.post_ca_certs
            else:
                verify = not self.post_ignore_ssl_errors
            if self.post_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()

            for header_key, header_value in list(self.post_http_headers.items()):
                header_key_template = Template(header_key)
                header_key_res = header_key_template.render(**match)
                header_value_template = Template(header_value)
                header_value_res = header_value_template.render(**match)
                headers[header_key_res] = header_value_res

            proxies = {'https': self.post_proxy} if self.post_proxy else None
            for url in self.post_url:
                try:
                    response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                             headers=headers, proxies=proxies, timeout=self.timeout,
                                             verify=verify)
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting HTTP Post 2 alert: %s" % e)
            elastalert_logger.info("HTTP Post 2 alert sent.")

    def get_info(self):
        return {'type': 'http_post2',
                'http_post2_webhook_url': self.post_url}
