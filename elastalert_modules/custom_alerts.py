import datetime
import json
import requests
from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import elastalert_logger
from elastalert.util import lookup_es_key
from requests.exceptions import RequestException


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class HttpPostAlerter(Alerter):

    """ Requested elasticsearch indices are sent by HTTP POST. Encoded with JSON. """

    required_options = frozenset(
        ['http_post_url', 'siem_manager_alert_body', 'siem_manager_alert_subject'])

    def __init__(self, rule):
        super(HttpPostAlerter, self).__init__(rule)
        post_url = self.rule.get('http_post_url')
        if isinstance(post_url, str):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('http_post_proxy')
        self.post_payload = self.rule.get('http_post_payload', {})
        self.post_static_payload = self.rule.get('http_post_static_payload', {})
        self.post_all_values = self.rule.get('http_post_all_values', not self.post_payload)
        self.post_http_headers = self.rule.get('http_post_headers', {})
        self.timeout = self.rule.get('http_post_timeout', 10)

    def create_text_from_params(self, matches, type_message):
        if type_message == 'body':
            message = 'siem_manager_alert_body'
            message_args = 'siem_manager_alert_body_args'
        elif type_message == 'subject':
            message = 'siem_manager_alert_subject'
            message_args = 'siem_manager_alert_subject_args'
        else:
            return ''

        alert_subject = str(self.rule[message])
        alert_subject_max_len = int(self.rule.get('alert_subject_max_len', 2048))

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule[message_args]
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, subject_value in enumerate(alert_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            alert_subject_values = [missing if val is None else val for val in alert_subject_values]
            alert_subject = alert_subject.format(*alert_subject_values)

        if len(alert_subject) > alert_subject_max_len:
            alert_subject = alert_subject[:alert_subject_max_len]

        return alert_subject

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """

        body = self.create_text_from_params(matches, "body")
        subject = self.create_text_from_params(matches, "subject")

        for match in matches:
            payload = match if self.post_all_values else {}
            payload.update(self.post_static_payload)
            for post_key, es_key in list(self.post_payload.items()):
                payload[post_key] = lookup_es_key(match, es_key)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json;charset=utf-8"
            }

            payload["title"] = subject
            payload["description"] = body

            headers.update(self.post_http_headers)
            proxies = {'https': self.post_proxy} if self.post_proxy else None
            for url in self.post_url:
                try:
                    response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                             headers=headers, proxies=proxies, timeout=self.timeout)
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting HTTP Post alert: %s" % e)
            elastalert_logger.info("HTTP Post alert sent.")

    def get_info(self):
        return {'type': 'http_post',
                'http_post_webhook_url': self.post_url}

