# -*- coding: utf-8 -*-
import json
import logging
import requests
from alerts import Alerter
from alerts import BasicMatchString
from util import EAException
from util import elastalert_logger
from util import lookup_es_key


class OpsGenieAlerter(Alerter):
    '''Sends a http request to the OpsGenie API to signal for an alert'''
    required_options = frozenset(['opsgenie_key'])

    def __init__(self, *args):
        super(OpsGenieAlerter, self).__init__(*args)

        self.account = self.rule.get('opsgenie_account')
        self.api_key = self.rule.get('opsgenie_key', 'key')
        self.recipients = self.rule.get('opsgenie_recipients')
        self.teams = self.rule.get('opsgenie_teams')
        self.tags = self.rule.get('opsgenie_tags', []) + ['ElastAlert', self.rule['name']]
        self.to_addr = self.rule.get('opsgenie_addr', 'https://api.opsgenie.com/v2/alerts')
        self.custom_message = self.rule.get('opsgenie_message')
        self.opsgenie_subject = self.rule.get('opsgenie_subject')
        self.opsgenie_subject_args = self.rule.get('opsgenie_subject_args')
        self.alias = self.rule.get('opsgenie_alias')
        self.opsgenie_proxy = self.rule.get('opsgenie_proxy', None)
        self.priority = self.rule.get('opsgenie_priority')

    def _fill_responders(self, responders, type_):
        return [{'id': r, 'type': type_} for r in responders]

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        if self.custom_message is None:
            self.message = self.create_title(matches)
        else:
            self.message = self.custom_message.format(**matches[0])

        post = {}
        post['message'] = self.message
        if self.account:
            post['user'] = self.account
        if self.recipients:
            post['responders'] = self._fill_responders(self.recipients, 'user')
        if self.teams:
            post['teams'] = self._fill_responders(self.teams, 'team')
        post['description'] = body
        post['source'] = 'ElastAlert'
        post['tags'] = self.tags
        if self.priority and self.priority not in ('P1', 'P2', 'P3', 'P4', 'P5'):
            logging.warn("Priority level does not appear to be specified correctly. \
                         Please make sure to set it to a value between P1 and P5")
        else:
            post['priority'] = self.priority

        if self.alias is not None:
            post['alias'] = self.alias.format(**matches[0])

        logging.debug(json.dumps(post))

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey {}'.format(self.api_key),
        }
        # set https proxy, if it was provided
        proxies = {'https': self.opsgenie_proxy} if self.opsgenie_proxy else None

        try:
            r = requests.post(self.to_addr, json=post, headers=headers, proxies=proxies)

            logging.debug('request response: {0}'.format(r))
            if r.status_code != 202:
                elastalert_logger.info("Error response from {0} \n "
                                       "API Response: {1}".format(self.to_addr, r))
                r.raise_for_status()
            logging.info("Alert sent to OpsGenie")
        except Exception as err:
            raise EAException("Error sending alert: {0}".format(err))

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def create_title(self, matches):
        """ Creates custom alert title to be used as subject for opsgenie alert."""
        if self.opsgenie_subject:
            return self.create_custom_title(matches)

        return self.create_default_title(matches)

    def create_custom_title(self, matches):
        opsgenie_subject = unicode(self.rule['opsgenie_subject'])

        if self.opsgenie_subject_args:
            opsgenie_subject_values = [lookup_es_key(matches[0], arg) for arg in self.opsgenie_subject_args]

            for i, subject_value in enumerate(opsgenie_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(self.opsgenie_subject_args[i])
                    if alert_value:
                        opsgenie_subject_values[i] = alert_value

            opsgenie_subject_values = ['<MISSING VALUE>' if val is None else val for val in opsgenie_subject_values]
            return opsgenie_subject.format(*opsgenie_subject_values)

        return opsgenie_subject

    def get_info(self):
        ret = {'type': 'opsgenie'}
        if self.recipients:
            ret['recipients'] = self.recipients
        if self.account:
            ret['account'] = self.account
        if self.teams:
            ret['teams'] = self.teams

        return ret
