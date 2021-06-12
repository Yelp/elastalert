import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class DatadogAlerter(Alerter):
    """ Creates a Datadog Event for each alert """
    required_options = frozenset(['datadog_api_key', 'datadog_app_key'])

    def __init__(self, rule):
        super(DatadogAlerter, self).__init__(rule)
        self.dd_api_key = self.rule.get('datadog_api_key', None)
        self.dd_app_key = self.rule.get('datadog_app_key', None)

    def alert(self, matches):
        url = 'https://api.datadoghq.com/api/v1/events'
        headers = {
            'Content-Type': 'application/json',
            'DD-API-KEY': self.dd_api_key,
            'DD-APPLICATION-KEY': self.dd_app_key
        }
        payload = {
            'title': self.create_title(matches),
            'text': self.create_alert_body(matches)
        }
        try:
            response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException('Error posting event to Datadog: %s' % e)
        elastalert_logger.info('Alert sent to Datadog')

    def get_info(self):
        return {'type': 'datadog'}
