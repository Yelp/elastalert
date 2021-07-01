# -*- coding: utf-8 -*-
import json
import os.path
import requests

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger, lookup_es_key


class OpsGenieAlerter(Alerter):
    '''Sends a http request to the OpsGenie API to signal for an alert'''
    required_options = frozenset(['opsgenie_key'])

    def __init__(self, *args):
        super(OpsGenieAlerter, self).__init__(*args)
        self.account = self.rule.get('opsgenie_account')
        self.api_key = self.rule.get('opsgenie_key', 'key')
        self.default_reciepients = self.rule.get('opsgenie_default_receipients', None)
        self.recipients = self.rule.get('opsgenie_recipients')
        self.recipients_args = self.rule.get('opsgenie_recipients_args')
        self.default_teams = self.rule.get('opsgenie_default_teams', None)
        self.teams = self.rule.get('opsgenie_teams')
        self.teams_args = self.rule.get('opsgenie_teams_args')
        self.tags = self.rule.get('opsgenie_tags', []) + ['ElastAlert', self.rule['name']]
        self.to_addr = self.rule.get('opsgenie_addr', 'https://api.opsgenie.com/v2/alerts')
        self.custom_message = self.rule.get('opsgenie_message')
        self.opsgenie_subject = self.rule.get('opsgenie_subject')
        self.opsgenie_subject_args = self.rule.get('opsgenie_subject_args')
        self.alias = self.rule.get('opsgenie_alias')
        self.opsgenie_proxy = self.rule.get('opsgenie_proxy', None)
        self.priority = self.rule.get('opsgenie_priority')
        self.opsgenie_details = self.rule.get('opsgenie_details', {})
        self.entity = self.rule.get('opsgenie_entity', None)
        self.source = self.rule.get('opsgenie_source', 'ElastAlert')

    def _parse_responders(self, responders, responder_args, matches, default_responders):
        if responder_args:
            formated_responders = list()
            responders_values = dict((k, lookup_es_key(matches[0], v)) for k, v in responder_args.items())
            responders_values = dict((k, v) for k, v in responders_values.items() if v)

            for responder in responders:
                responder = str(responder)
                try:
                    formated_responders.append(responder.format(**responders_values))
                except KeyError as error:
                    elastalert_logger.warning("OpsGenieAlerter: Cannot create responder for OpsGenie Alert. Key not foud: %s. " % (error))
            if not formated_responders:
                elastalert_logger.warning("OpsGenieAlerter: no responders can be formed. Trying the default responder ")
                if not default_responders:
                    elastalert_logger.warning("OpsGenieAlerter: default responder not set. Falling back")
                    formated_responders = responders
                else:
                    formated_responders = default_responders
            responders = formated_responders
        return responders

    def alert(self, matches):
        body = ''
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        if self.custom_message is None:
            self.message = self.create_title(matches)
        else:
            self.message = self.custom_message.format(**matches[0])
        self.recipients = self._parse_responders(self.recipients, self.recipients_args, matches, self.default_reciepients)
        self.teams = self._parse_responders(self.teams, self.teams_args, matches, self.default_teams)
        post = {}
        post['message'] = self.message
        if self.account:
            post['user'] = self.account
        if self.recipients:
            post['responders'] = [{'username': r, 'type': 'user'} for r in self.recipients]
        if self.teams:
            post['teams'] = [{'name': r, 'type': 'team'} for r in self.teams]
        post['description'] = body
        if self.entity:
            post['entity'] = self.entity.format(**matches[0])
        if self.source:
            post['source'] = self.source.format(**matches[0])

        for i, tag in enumerate(self.tags):
            self.tags[i] = tag.format(**matches[0])
        post['tags'] = self.tags

        priority = self.priority
        if priority:
            priority = priority.format(**matches[0])
        if priority and priority not in ('P1', 'P2', 'P3', 'P4', 'P5'):
            elastalert_logger.warning("Priority level does not appear to be specified correctly. \
                        Please make sure to set it to a value between P1 and P5")
        else:
            post['priority'] = priority

        if self.alias is not None:
            post['alias'] = self.alias.format(**matches[0])

        details = self.get_details(matches)
        if details:
            post['details'] = details

        elastalert_logger.debug(json.dumps(post))

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey {}'.format(self.api_key),
        }
        # set https proxy, if it was provided
        proxies = {'https': self.opsgenie_proxy} if self.opsgenie_proxy else None

        try:
            r = requests.post(self.to_addr, json=post, headers=headers, proxies=proxies)

            elastalert_logger.debug('request response: {0}'.format(r))
            if r.status_code != 202:
                elastalert_logger.info("Error response from {0} \n "
                                       "API Response: {1}".format(self.to_addr, r))
                r.raise_for_status()
            elastalert_logger.info("Alert sent to OpsGenie")
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
        opsgenie_subject = str(self.rule['opsgenie_subject'])

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

    def get_details(self, matches):
        details = {}

        for key, value in self.opsgenie_details.items():

            if type(value) is dict:
                if 'field' in value:
                    field_value = lookup_es_key(matches[0], value['field'])
                    if field_value is not None:
                        details[key] = str(field_value)

            elif type(value) is str:
                details[key] = os.path.expandvars(value)

        return details
