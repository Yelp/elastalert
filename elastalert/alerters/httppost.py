import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import lookup_es_key, EAException, elastalert_logger


class HTTPPostAlerter(Alerter):
    """ Requested elasticsearch indices are sent by HTTP POST. Encoded with JSON. """
    required_options = frozenset(['http_post_url'])

    def __init__(self, rule):
        super(HTTPPostAlerter, self).__init__(rule)
        post_url = self.rule.get('http_post_url', None)
        if isinstance(post_url, str):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('http_post_proxy', None)
        self.post_payload = self.rule.get('http_post_payload', {})
        self.post_static_payload = self.rule.get('http_post_static_payload', {})
        self.post_all_values = self.rule.get('http_post_all_values', not self.post_payload)
        self.post_http_headers = self.rule.get('http_post_headers', {})
        self.post_ca_certs = self.rule.get('http_post_ca_certs')
        self.post_ignore_ssl_errors = self.rule.get('http_post_ignore_ssl_errors', False)
        self.timeout = self.rule.get('http_post_timeout', 10)

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """
        for match in matches:
            payload = match if self.post_all_values else {}
            payload.update(self.post_static_payload)
            for post_key, es_key in list(self.post_payload.items()):
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

            headers.update(self.post_http_headers)
            proxies = {'https': self.post_proxy} if self.post_proxy else None
            for url in self.post_url:
                try:
                    response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                             headers=headers, proxies=proxies, timeout=self.timeout,
                                             verify=verify)
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting HTTP Post alert: %s" % e)
            elastalert_logger.info("HTTP Post alert sent.")

    def get_info(self):
        return {'type': 'http_post',
                'http_post_webhook_url': self.post_url}
