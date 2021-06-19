import json
import requests

from elastalert.util import EAException, lookup_es_key, elastalert_logger
from elastalert.alerts import Alerter, DateTimeEncoder
from requests import RequestException


class PagerDutyAlerter(Alerter):
    """ Create an incident on PagerDuty for each alert """
    required_options = frozenset(['pagerduty_service_key', 'pagerduty_client_name'])

    def __init__(self, rule):
        super(PagerDutyAlerter, self).__init__(rule)
        self.pagerduty_service_key = self.rule.get('pagerduty_service_key', None)
        self.pagerduty_client_name = self.rule.get('pagerduty_client_name', None)
        self.pagerduty_incident_key = self.rule.get('pagerduty_incident_key', '')
        self.pagerduty_incident_key_args = self.rule.get('pagerduty_incident_key_args', None)
        self.pagerduty_event_type = self.rule.get('pagerduty_event_type', 'trigger')
        self.pagerduty_proxy = self.rule.get('pagerduty_proxy', None)

        self.pagerduty_api_version = self.rule.get('pagerduty_api_version', 'v1')
        self.pagerduty_v2_payload_class = self.rule.get('pagerduty_v2_payload_class', '')
        self.pagerduty_v2_payload_class_args = self.rule.get('pagerduty_v2_payload_class_args', None)
        self.pagerduty_v2_payload_component = self.rule.get('pagerduty_v2_payload_component', '')
        self.pagerduty_v2_payload_component_args = self.rule.get('pagerduty_v2_payload_component_args', None)
        self.pagerduty_v2_payload_group = self.rule.get('pagerduty_v2_payload_group', '')
        self.pagerduty_v2_payload_group_args = self.rule.get('pagerduty_v2_payload_group_args', None)
        self.pagerduty_v2_payload_severity = self.rule.get('pagerduty_v2_payload_severity', 'critical')
        self.pagerduty_v2_payload_source = self.rule.get('pagerduty_v2_payload_source', 'ElastAlert')
        self.pagerduty_v2_payload_source_args = self.rule.get('pagerduty_v2_payload_source_args', None)
        self.pagerduty_v2_payload_custom_details = self.rule.get('pagerduty_v2_payload_custom_details', {})
        self.pagerduty_v2_payload_include_all_info = self.rule.get('pagerduty_v2_payload_include_all_info', True)

        if self.pagerduty_api_version == 'v2':
            self.url = 'https://events.pagerduty.com/v2/enqueue'
        else:
            self.url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to pagerduty
        headers = {'content-type': 'application/json'}
        if self.pagerduty_api_version == 'v2':

            custom_details_payload = {'information': body} if self.pagerduty_v2_payload_include_all_info else {}
            if self.pagerduty_v2_payload_custom_details:
                for match in matches:
                    for custom_details_key, es_key in list(self.pagerduty_v2_payload_custom_details.items()):
                        custom_details_payload[custom_details_key] = lookup_es_key(match, es_key)

            payload = {
                'routing_key': self.pagerduty_service_key,
                'event_action': self.pagerduty_event_type,
                'dedup_key': self.get_incident_key(matches),
                'client': self.pagerduty_client_name,
                'payload': {
                    'class': self.resolve_formatted_key(self.pagerduty_v2_payload_class,
                                                        self.pagerduty_v2_payload_class_args,
                                                        matches),
                    'component': self.resolve_formatted_key(self.pagerduty_v2_payload_component,
                                                            self.pagerduty_v2_payload_component_args,
                                                            matches),
                    'group': self.resolve_formatted_key(self.pagerduty_v2_payload_group,
                                                        self.pagerduty_v2_payload_group_args,
                                                        matches),
                    'severity': self.pagerduty_v2_payload_severity,
                    'source': self.resolve_formatted_key(self.pagerduty_v2_payload_source,
                                                         self.pagerduty_v2_payload_source_args,
                                                         matches),
                    'summary': self.create_title(matches),
                    'custom_details': custom_details_payload,
                },
            }
            match_timestamp = lookup_es_key(matches[0], self.rule.get('timestamp_field', '@timestamp'))
            if match_timestamp:
                payload['payload']['timestamp'] = match_timestamp
        else:
            payload = {
                'service_key': self.pagerduty_service_key,
                'description': self.create_title(matches),
                'event_type': self.pagerduty_event_type,
                'incident_key': self.get_incident_key(matches),
                'client': self.pagerduty_client_name,
                'details': {
                    "information": body,
                },
            }

        # set https proxy, if it was provided
        proxies = {'https': self.pagerduty_proxy} if self.pagerduty_proxy else None
        try:
            response = requests.post(
                self.url,
                data=json.dumps(payload, cls=DateTimeEncoder, ensure_ascii=False),
                headers=headers,
                proxies=proxies
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to pagerduty: %s" % e)

        if self.pagerduty_event_type == 'trigger':
            elastalert_logger.info("Trigger sent to PagerDuty")
        if self.pagerduty_event_type == 'resolve':
            elastalert_logger.info("Resolve sent to PagerDuty")
        if self.pagerduty_event_type == 'acknowledge':
            elastalert_logger.info("acknowledge sent to PagerDuty")

    def resolve_formatted_key(self, key, args, matches):
        if args:
            key_values = [lookup_es_key(matches[0], arg) for arg in args]

            # Populate values with rule level properties too
            for i in range(len(key_values)):
                if key_values[i] is None:
                    key_value = self.rule.get(args[i])
                    if key_value:
                        key_values[i] = key_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            key_values = [missing if val is None else val for val in key_values]
            return key.format(*key_values)
        else:
            return key

    def get_incident_key(self, matches):
        if self.pagerduty_incident_key_args:
            incident_key_values = [lookup_es_key(matches[0], arg) for arg in self.pagerduty_incident_key_args]

            # Populate values with rule level properties too
            for i in range(len(incident_key_values)):
                if incident_key_values[i] is None:
                    key_value = self.rule.get(self.pagerduty_incident_key_args[i])
                    if key_value:
                        incident_key_values[i] = key_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            incident_key_values = [missing if val is None else val for val in incident_key_values]
            return self.pagerduty_incident_key.format(*incident_key_values)
        else:
            return self.pagerduty_incident_key

    def get_info(self):
        return {'type': 'pagerduty',
                'pagerduty_client_name': self.pagerduty_client_name}
