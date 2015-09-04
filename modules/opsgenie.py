# -*- coding: utf-8 -*-
import json
import logging
import requests

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString


class OpsGenieAlerter(Alerter):
    '''Sends a http request to the OpsGenie API to signal for an alert'''
    required_options = frozenset(['opsgenie_key', 'opsgenie_account', 'opsgenie_recipients'])

    def __init__(self, *args):
        super(OpsGenieAlerter, self).__init__(*args)

        self.account = self.rule.get('opsgenie_account', 'genie')
        self.api_key = self.rule.get('opsgenie_key', 'key')
        self.recipients = self.rule.get('opsgenie_recipients', ['genies'])
        self.to_addr = self.rule.get('opsgenie_addr', 'example.opsgenie.net')

    def alert(self, matches):
        body = ''
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        post = {}
        post['apiKey'] = self.api_key
        post['message'] = self.create_default_title(matches)
        post['recipients'] = self.recipients
        post['description'] = body
        post['source'] = 'ElastAlert'
        post['tags'] = ['ElastAlert', self.rule['name']]
        logging.debug(json.dumps(post))

        try:
            r = requests.post(self.to_addr, json=post)

            logging.debug('request response: {0}'.format(r))
            if r.status_code != 200:
                logging.error("Error sending alert request to OpsGenie! {0}".format(r.json()))
                r.raise_for_status()
            logging.info("Alert sent to OpsGenie")
        except Exception as err:
            logging.error("Error sending alert to OpsGenie: {0}".format(err))
            return

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'opsgenie',
                'recipients': self.recipients}
