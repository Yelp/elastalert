import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, BasicMatchString, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class ServiceNowAlerter(Alerter):
    """ Creates a ServiceNow alert """
    required_options = set([
        'username',
        'password',
        'servicenow_rest_url',
        'short_description',
        'comments',
        'assignment_group',
        'category',
        'subcategory',
        'cmdb_ci',
        'caller_id'
    ])

    def __init__(self, rule):
        super(ServiceNowAlerter, self).__init__(rule)
        self.servicenow_rest_url = self.rule.get('servicenow_rest_url', None)
        self.servicenow_proxy = self.rule.get('servicenow_proxy', None)
        self.impact = self.rule.get('servicenow_impact', None)
        self.urgency = self.rule.get('servicenow_urgency', None)

    def alert(self, matches):
        for match in matches:
            # Parse everything into description.
            description = str(BasicMatchString(self.rule, match))

        # Set proper headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8"
        }
        proxies = {'https': self.servicenow_proxy} if self.servicenow_proxy else None
        payload = {
            "description": description,
            "short_description": self.rule['short_description'],
            "comments": self.rule['comments'],
            "assignment_group": self.rule['assignment_group'],
            "category": self.rule['category'],
            "subcategory": self.rule['subcategory'],
            "cmdb_ci": self.rule['cmdb_ci'],
            "caller_id": self.rule["caller_id"]
        }
        if self.impact != None:
            payload["impact"] = self.impact
        if self.urgency != None:
            payload["urgency"] = self.urgency
        try:
            response = requests.post(
                self.servicenow_rest_url,
                auth=(self.rule['username'], self.rule['password']),
                headers=headers,
                data=json.dumps(payload, cls=DateTimeEncoder),
                proxies=proxies
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to ServiceNow: %s" % e)
        elastalert_logger.info("Alert sent to ServiceNow")

    def get_info(self):
        return {'type': 'ServiceNow',
                'self.servicenow_rest_url': self.servicenow_rest_url}
