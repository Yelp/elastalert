import json
import time
import uuid

import requests
from requests import RequestException

from elastalert.alerts import Alerter
from elastalert.util import lookup_es_key, EAException, elastalert_logger


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """
    required_options = set(['hive_connection', 'hive_alert_config'])

    def lookup_field(self, match: dict, field_name: str, default):
        """Populates a field with values depending on the contents of the Elastalert match
        provided to it.

        Uses a similar algorithm to that implemented to populate the `alert_text_args`.
        First checks any fields found in the match provided, then any fields defined in
        the rule, finally returning the default value provided if no value can be found.
        """
        field_value = lookup_es_key(match, field_name)
        if field_value is None:
            field_value = self.rule.get(field_name, default)

        return field_value

    # Iterate through the matches, building up a list of observables
    def load_observable_artifacts(self, match: dict):
        artifacts = []
        for mapping in self.rule.get('hive_observable_data_mapping', []):
            for observable_type, mapping_key in mapping.items():
                data = str(self.lookup_field(match, mapping_key, ''))
                if len(data) != 0:
                    artifact = {'tlp': 2,
                                'tags': [],
                                'message': None,
                                'dataType': observable_type,
                                'data': data}
                    artifacts.append(artifact)

        return artifacts

    def load_custom_fields(self, custom_fields_raw: list, match: dict):
        custom_fields = {}
        position = 0

        for field in custom_fields_raw:
            if (isinstance(field['value'], str)):
                value = self.lookup_field(match, field['value'], field['value'])
            else:
                value = field['value']

            custom_fields[field['name']] = {'order': position, field['type']: value}
            position += 1

        return custom_fields

    def load_tags(self, tag_names: list, match: dict):
        tag_values = set()
        for tag in tag_names:
            tag_value = self.lookup_field(match, tag, tag)
            if isinstance(tag_value, list):
                for sub_tag in tag_value:
                    tag_values.add(str(sub_tag))
            else:
                tag_values.add(str(tag_value))

        return tag_values

    def alert(self, matches):
        # Build TheHive alert object, starting with some defaults, updating with any
        # user-specified config
        alert_config = {
            'artifacts': [],
            'customFields': {},
            'date': int(time.time()) * 1000,
            'description': self.create_alert_body(matches),
            'sourceRef': str(uuid.uuid4())[0:6],
            'tags': [],
            'title': self.create_title(matches),
        }
        alert_config.update(self.rule.get('hive_alert_config', {}))

        # Iterate through each match found, populating the alert tags and observables as required
        tags = set()
        artifacts = []
        for match in matches:
            artifacts = artifacts + self.load_observable_artifacts(match)
            tags.update(self.load_tags(alert_config['tags'], match))

        alert_config['artifacts'] = artifacts
        alert_config['tags'] = list(tags)

        # Populate the customFields
        alert_config['customFields'] = self.load_custom_fields(alert_config['customFields'],
                                                               matches[0])

        # POST the alert to TheHive
        connection_details = self.rule['hive_connection']

        api_key = connection_details.get('hive_apikey', '')
        hive_host = connection_details.get('hive_host', 'http://localhost')
        hive_port = connection_details.get('hive_port', 9000)
        proxies = connection_details.get('hive_proxies', {'http': '', 'https': ''})
        verify = connection_details.get('hive_verify', False)

        alert_body = json.dumps(alert_config, indent=4, sort_keys=True)
        req = f'{hive_host}:{hive_port}/api/alert'
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'Bearer {api_key}'}

        try:
            response = requests.post(req,
                                     headers=headers,
                                     data=alert_body,
                                     proxies=proxies,
                                     verify=verify)
            response.raise_for_status()
        except RequestException as e:
            raise EAException(f"Error posting to TheHive: {e}")
        elastalert_logger.info("Alert sent to TheHive")

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
