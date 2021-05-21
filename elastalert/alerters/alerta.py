import datetime
import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import lookup_es_key, EAException, elastalert_logger, resolve_string, ts_to_dt


class AlertaAlerter(Alerter):
    """ Creates an Alerta event for each alert """
    required_options = frozenset(['alerta_api_url'])

    def __init__(self, rule):
        super(AlertaAlerter, self).__init__(rule)

        # Setup defaul parameters
        self.url = self.rule.get('alerta_api_url', None)
        self.api_key = self.rule.get('alerta_api_key', None)
        self.timeout = self.rule.get('alerta_timeout', 86400)
        self.use_match_timestamp = self.rule.get('alerta_use_match_timestamp', False)
        self.use_qk_as_resource = self.rule.get('alerta_use_qk_as_resource', False)
        self.verify_ssl = not self.rule.get('alerta_api_skip_ssl', False)
        self.missing_text = self.rule.get('alert_missing_value', '<MISSING VALUE>')

        # Fill up default values of the API JSON payload
        self.severity = self.rule.get('alerta_severity', 'warning')
        self.resource = self.rule.get('alerta_resource', 'elastalert')
        self.environment = self.rule.get('alerta_environment', 'Production')
        self.origin = self.rule.get('alerta_origin', 'elastalert')
        self.service = self.rule.get('alerta_service', ['elastalert'])
        self.text = self.rule.get('alerta_text', 'elastalert')
        self.type = self.rule.get('alerta_type', 'elastalert')
        self.event = self.rule.get('alerta_event', 'elastalert')
        self.correlate = self.rule.get('alerta_correlate', [])
        self.tags = self.rule.get('alerta_tags', [])
        self.group = self.rule.get('alerta_group', '')
        self.attributes_keys = self.rule.get('alerta_attributes_keys', [])
        self.attributes_values = self.rule.get('alerta_attributes_values', [])
        self.value = self.rule.get('alerta_value', '')

    def alert(self, matches):
        # Override the resource if requested
        if self.use_qk_as_resource and 'query_key' in self.rule and lookup_es_key(matches[0], self.rule['query_key']):
            self.resource = lookup_es_key(matches[0], self.rule['query_key'])

        headers = {'content-type': 'application/json'}
        if self.api_key is not None:
            headers['Authorization'] = 'Key %s' % (self.rule['alerta_api_key'])
        alerta_payload = self.get_json_payload(matches[0])

        try:
            response = requests.post(self.url, data=alerta_payload, headers=headers, verify=self.verify_ssl)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Alerta: %s" % e)
        elastalert_logger.info("Alert sent to Alerta")

    def create_default_title(self, matches):
        title = '%s' % (self.rule['name'])
        # If the rule has a query_key, add that value
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                title += '.%s' % (qk)
        return title

    def get_info(self):
        return {'type': 'alerta',
                'alerta_url': self.url}

    def get_json_payload(self, match):
        """
            Builds the API Create Alert body, as in
            http://alerta.readthedocs.io/en/latest/api/reference.html#create-an-alert

            For the values that could have references to fields on the match, resolve those references.

        """

        # Using default text and event title if not defined in rule
        alerta_text = self.rule['type'].get_match_str([match]) if self.text == '' else resolve_string(self.text, match, self.missing_text)
        alerta_event = self.create_default_title([match]) if self.event == '' else resolve_string(self.event, match, self.missing_text)

        match_timestamp = lookup_es_key(match, self.rule.get('timestamp_field', '@timestamp'))
        if match_timestamp is None:
            match_timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if self.use_match_timestamp:
            createTime = ts_to_dt(match_timestamp).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            createTime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        alerta_payload_dict = {
            'resource': resolve_string(self.resource, match, self.missing_text),
            'severity': resolve_string(self.severity, match),
            'timeout': self.timeout,
            'createTime': createTime,
            'type': self.type,
            'environment': resolve_string(self.environment, match, self.missing_text),
            'origin': resolve_string(self.origin, match, self.missing_text),
            'group': resolve_string(self.group, match, self.missing_text),
            'event': alerta_event,
            'text': alerta_text,
            'value': resolve_string(self.value, match, self.missing_text),
            'service': [resolve_string(a_service, match, self.missing_text) for a_service in self.service],
            'tags': [resolve_string(a_tag, match, self.missing_text) for a_tag in self.tags],
            'correlate': [resolve_string(an_event, match, self.missing_text) for an_event in self.correlate],
            'attributes': dict(list(zip(self.attributes_keys,
                                        [resolve_string(a_value, match, self.missing_text) for a_value in self.attributes_values]))),
            'rawData': self.create_alert_body([match]),
        }

        try:
            payload = json.dumps(alerta_payload_dict, cls=DateTimeEncoder)
        except Exception as e:
            raise Exception("Error building Alerta request: %s" % e)
        return payload
