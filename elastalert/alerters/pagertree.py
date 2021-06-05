import json
import uuid

import requests
from requests import RequestException

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class PagerTreeAlerter(Alerter):
    """ Creates a PagerTree Incident for each alert """
    required_options = frozenset(['pagertree_integration_url'])

    def __init__(self, rule):
        super(PagerTreeAlerter, self).__init__(rule)
        self.url = self.rule.get('pagertree_integration_url', None)
        self.pagertree_proxy = self.rule.get('pagertree_proxy', None)

    def alert(self, matches):
        # post to pagertree
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.pagertree_proxy} if self.pagertree_proxy else None
        payload = {
            "event_type": "create",
            "Id": str(uuid.uuid4()),
            "Title": self.create_title(matches),
            "Description": self.create_alert_body(matches)
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to PagerTree: %s" % e)
        elastalert_logger.info("Trigger sent to PagerTree")

    def get_info(self):
        return {'type': 'pagertree',
                'pagertree_integration_url': self.url}
