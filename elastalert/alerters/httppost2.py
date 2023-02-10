import json
from json import JSONDecodeError

import requests
from jinja2 import Template, TemplateSyntaxError
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import lookup_es_key, EAException, elastalert_logger


def _json_escape(s):
    return json.encoder.encode_basestring(s)[1:-1]


def _escape_all_values(x):
    """recursively rebuilds, and escapes all strings for json, the given dict/list"""
    if isinstance(x, dict):
        x = { k:_escape_all_values(v) for k, v in x.items() }
    elif isinstance(x, list):
        x = [ _escape_all_values(v) for v in x ]
    elif isinstance(x, str):
        x = _json_escape(x)
    return x


def _render_json_template(template, match):
    if not isinstance(template, str):
        template = json.dumps(template)
    template = Template(template)

    return json.loads(template.render(**match))


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
        self.jinja_root_name = self.rule.get('jinja_root_name', None)

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """
        for match in matches:
            match_js_esc = _escape_all_values(match)
            args = {**match_js_esc}
            if self.jinja_root_name:
                args[self.jinja_root_name] = match_js_esc

            try:
                field = 'payload'
                payload = match if self.post_all_values else {}
                payload_res = _render_json_template(self.post_payload, args)
                payload = {**payload, **payload_res}

                field = 'headers'
                header_res = _render_json_template(self.post_http_headers, args)
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json;charset=utf-8",
                    **header_res
                }
            except TemplateSyntaxError as e:
                raise ValueError(f"HTTP Post 2: The value of 'http_post2_{field}' has an invalid Jinja2 syntax. "
                                 f"Please check your template syntax: {e}")

            except JSONDecodeError as e:
                raise ValueError(f"HTTP Post 2: The rendered value for 'http_post2_{field}' contains invalid JSON. "
                                 f"Please check your template syntax: {e}")

            except Exception as e:
                raise ValueError(f"HTTP Post 2: An unexpected error occurred with the 'http_post2_{field}' value. "
                                 f"Please check your template syntax: {e}")

            for post_key, es_key in list(self.post_raw_fields.items()):
                payload[post_key] = lookup_es_key(match, es_key)

            if self.post_ca_certs:
                verify = self.post_ca_certs
            else:
                verify = not self.post_ignore_ssl_errors
            if self.post_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()

            for key, value in headers.items():
                if type(value) in [type(None), list, dict]:
                    raise ValueError(f"HTTP Post 2: Can't send a header value which is not a string! "
                                     f"Forbidden header {key}: {value}")

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
