import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class VictorOpsAlerter(Alerter):
    """ Creates a VictorOps Incident for each alert """
    required_options = frozenset(['victorops_api_key', 'victorops_routing_key', 'victorops_message_type'])

    def __init__(self, rule):
        super(VictorOpsAlerter, self).__init__(rule)
        self.victorops_api_key = self.rule.get('victorops_api_key', None)
        self.victorops_routing_key = self.rule.get('victorops_routing_key', None)
        self.victorops_message_type = self.rule.get('victorops_message_type', None)
        self.victorops_entity_id = self.rule.get('victorops_entity_id', None)
        self.victorops_entity_display_name = self.rule.get('victorops_entity_display_name', None) # set entity_display_name from alert_subject by default
        self.url = 'https://alert.victorops.com/integrations/generic/20131114/alert/%s/%s' % (
            self.victorops_api_key, self.victorops_routing_key)
        self.victorops_proxy = self.rule.get('victorops_proxy', None)

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to victorops
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.victorops_proxy} if self.victorops_proxy else None
        # set title with alert_subject
        self.victorops_entity_display_name = self.create_title(matches) if \
            self.victorops_entity_display_name is None else self.victorops_entity_display_name
        payload = {
            "message_type": self.victorops_message_type,
            "entity_display_name": self.victorops_entity_display_name,
            "monitoring_tool": "ElastAlert",
            "state_message": body
        }
        # add all data from event payload
        payload.update(matches[0])
        if self.victorops_entity_id:
            payload["entity_id"] = self.victorops_entity_id

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to VictorOps: %s" % e)
        elastalert_logger.info("Trigger sent to VictorOps")

    def get_info(self):
        return {'type': 'victorops',
                'victorops_routing_key': self.victorops_routing_key}
