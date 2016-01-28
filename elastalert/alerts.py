# -*- coding: utf-8 -*-
import datetime
import json
import logging
import subprocess
from email.mime.text import MIMEText
from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException
from socket import error

import boto.sns as sns
import requests
import simplejson
from jira.client import JIRA
from jira.exceptions import JIRAError
from requests.exceptions import RequestException
from staticconf.loader import yaml_loader
from util import EAException
from util import elastalert_logger
from util import lookup_es_key
from util import pretty_ts
import warnings


class BasicMatchString(object):

    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        alert_text = unicode(self.rule.get('alert_text', ''))
        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]
            alert_text_values = ['<MISSING VALUE>' if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        self.text += alert_text

    def _add_rule_text(self):
        self.text += self.rule['type'].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in self.match.items():
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = counts.items()
                top_events.sort(key=lambda x: x[1], reverse=True)
                for term, count in top_events:
                    self.text += '%s: %s\n' % (term, count)
                self.text += '\n'

    def _add_match_items(self):
        match_items = self.match.items()
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith('top_events_'):
                continue
            value_str = unicode(value)
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return simplejson.dumps(blob, sort_keys=True, indent=4, ensure_ascii=False)
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-1 to show something
            return simplejson.dumps(blob, sort_keys=True, indent=4, encoding='Latin-1', ensure_ascii=False)

    def __str__(self):
        self.text = self.rule['name'] + '\n\n'
        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get('alert_text_type') != 'alert_text_only':
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get('top_count_keys'):
                self._add_top_counts()
            if self.rule.get('alert_text_type') != 'exclude_fields':
                self._add_match_items()
        return self.text


class JiraFormattedMatchString(BasicMatchString):

    def _add_match_items(self):
        match_items = dict([(x, y) for x, y in self.match.items() if not x.startswith('top_events_')])
        json_blob = self._pretty_print_as_json(match_items)
        preformatted_text = '{{code:json}}{0}{{code}}'.format(json_blob)
        self.text += preformatted_text


class Alerter(object):
    """ Base class for types of alerts.

    :param rule: The rule configuration.
    """
    required_options = frozenset([])

    def __init__(self, rule):
        self.rule = rule
        # pipeline object is created by ElastAlerter.send_alert()
        # and attached to each alerters used by a rule before calling alert()
        self.pipeline = None

    def alert(self, match):
        """ Send an alert. Match is a dictionary of information about the alert.

        :param match: A dictionary of relevant information to the alert.
        """
        raise NotImplementedError()

    def get_info(self):
        """ Returns a dictionary of data related to this alert. At minimum, this should contain
        a field type corresponding to the type of Alerter. """
        return {'type': 'Unknown'}

    def create_title(self, matches):
        """ Creates custom alert title to be used, e.g. as an e-mail subject or JIRA issue summary.

        :param matches: A list of dictionaries of relevant information to the alert.
        """
        if 'alert_subject' in self.rule:
            return self.create_custom_title(matches)

        return self.create_default_title(matches)

    def create_custom_title(self, matches):
        alert_subject = self.rule['alert_subject']

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]
            alert_subject_values = ['<MISSING VALUE>' if val is None else val for val in alert_subject_values]
            return alert_subject.format(*alert_subject_values)

        return alert_subject

    def create_default_title(self, matches):
        return self.rule['name']

    def get_account(self, account_file):
        """ Gets the username and password from an account file.

        :param account_file: Name of the file which contains user and password information.
        """
        account_conf = yaml_loader(account_file)
        if 'user' not in account_conf or 'password' not in account_conf:
            raise EAException('Account file must have user and password fields')
        self.user = account_conf['user']
        self.password = account_conf['password']


class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal). """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                elastalert_logger.info('Alert for %s, %s at %s:' % (self.rule['name'], match[qk], match[self.rule['timestamp_field']]))
            else:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'], match[self.rule['timestamp_field']]))
            elastalert_logger.info(unicode(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}


class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], str):
            self.rule['email'] = [self.rule['email']]
        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('cc')
        if cc and isinstance(cc, str):
            self.rule['cc'] = [self.rule['cc']]
        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('bcc')
        if bcc and isinstance(bcc, str):
            self.rule['bcc'] = [self.rule['bcc']]

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        # Add JIRA ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJIRA ticket: %s' % (url)

        to_addr = self.rule['email']
        email_msg = MIMEText(body.encode('UTF-8'), _charset='UTF-8')
        email_msg['Subject'] = self.create_title(matches)
        email_msg['To'] = ', '.join(self.rule['email'])
        email_msg['From'] = self.from_addr
        email_msg['Reply-To'] = self.rule.get('email_reply_to', email_msg['To'])
        if self.rule.get('cc'):
            email_msg['CC'] = ','.join(self.rule['cc'])
            to_addr = to_addr + self.rule['cc']
        if self.rule.get('bcc'):
            to_addr = to_addr + self.rule['bcc']

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP_SSL(self.smtp_host)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls()
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.close()

        elastalert_logger.info("Sent email to %s" % (self.rule['email']))

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'email',
                'recipients': self.rule['email']}


class JiraAlerter(Alerter):
    """ Creates a Jira ticket for each alert """
    required_options = frozenset(['jira_server', 'jira_account_file', 'jira_project', 'jira_issuetype'])

    def __init__(self, rule):
        super(JiraAlerter, self).__init__(rule)
        self.server = self.rule['jira_server']
        self.get_account(self.rule['jira_account_file'])
        self.project = self.rule['jira_project']
        self.issue_type = self.rule['jira_issuetype']
        self.component = self.rule.get('jira_component')
        self.label = self.rule.get('jira_label')
        self.description = self.rule.get('jira_description', '')
        self.assignee = self.rule.get('jira_assignee')
        self.max_age = self.rule.get('jira_max_age', 30)
        self.priority = self.rule.get('jira_priority')
        self.bump_tickets = self.rule.get('jira_bump_tickets', False)
        self.bump_not_in_statuses = self.rule.get('jira_bump_not_in_statuses')
        self.bump_in_statuses = self.rule.get('jira_bump_in_statuses')

        if self.bump_in_statuses and self.bump_not_in_statuses:
            msg = 'Both jira_bump_in_statuses (%s) and jira_bump_not_in_statuses (%s) are set.' % \
                  (','.join(self.bump_in_statuses), ','.join(self.bump_not_in_statuses))
            intersection = list(set(self.bump_in_statuses) & set(self.bump_in_statuses))
            if intersection:
                msg = '%s Both have common statuses of (%s). As such, no tickets will ever be found.' % (msg, ','.join(intersection))
            msg += ' This should be simplified to use only one or the other.'
            logging.warning(msg)

        self.jira_args = {'project': {'key': self.project},
                          'issuetype': {'name': self.issue_type}}

        if self.component:
            self.jira_args['components'] = [{'name': self.component}]
        if self.label:
            self.jira_args['labels'] = [self.label]
        if self.assignee:
            self.jira_args['assignee'] = {'name': self.assignee}

        try:
            self.client = JIRA(self.server, basic_auth=(self.user, self.password))
            self.get_priorities()
        except JIRAError as e:
            # JIRAError may contain HTML, pass along only first 1024 chars
            raise EAException("Error connecting to JIRA: %s" % (str(e)[:1024]))

        try:
            if self.priority is not None:
                self.jira_args['priority'] = {'id': self.priority_ids[self.priority]}
        except KeyError:
            logging.error("Priority %s not found. Valid priorities are %s" % (self.priority, self.priority_ids.keys()))

    def get_priorities(self):
        """ Creates a mapping of priority index to id. """
        priorities = self.client.priorities()
        self.priority_ids = {}
        for x in range(len(priorities)):
            self.priority_ids[x] = priorities[x].id

    def set_assignee(self, assignee):
        self.assignee = assignee
        if assignee:
            self.jira_args['assignee'] = {'name': assignee}
        elif 'assignee' in self.jira_args:
            self.jira_args.pop('assignee')

    def find_existing_ticket(self, matches):
        # Default title, get stripped search version
        if 'alert_subject' not in self.rule:
            title = self.create_default_title(matches, True)
        else:
            title = self.create_title(matches)

        # This is necessary for search for work. Other special characters and dashes
        # directly adjacent to words appear to be ok
        title = title.replace(' - ', ' ')

        date = (datetime.datetime.now() - datetime.timedelta(days=self.max_age)).strftime('%Y-%m-%d')
        jql = 'project=%s AND summary~"%s" and created >= "%s"' % (self.project, title, date)
        if self.bump_in_statuses:
            jql = '%s and status in (%s)' % (jql, ','.join(self.bump_in_statuses))
        if self.bump_not_in_statuses:
            jql = '%s and status not in (%s)' % (jql, ','.join(self.bump_not_in_statuses))
        try:
            issues = self.client.search_issues(jql)
        except JIRAError as e:
            logging.exception("Error while searching for JIRA ticket using jql '%s': %s" % (jql, e))
            return None

        if len(issues):
            return issues[0]

    def comment_on_ticket(self, ticket, match):
        text = unicode(JiraFormattedMatchString(self.rule, match))
        timestamp = pretty_ts(match[self.rule['timestamp_field']])
        comment = "This alert was triggered again at %s\n%s" % (timestamp, text)
        self.client.add_comment(ticket, comment)

    def alert(self, matches):
        title = self.create_title(matches)

        if self.bump_tickets:
            ticket = self.find_existing_ticket(matches)
            if ticket:
                elastalert_logger.info('Commenting on existing ticket %s' % (ticket.key))
                for match in matches:
                    try:
                        self.comment_on_ticket(ticket, match)
                    except JIRAError as e:
                        logging.exception("Error while commenting on ticket %s: %s" % (ticket, e))
                if self.pipeline is not None:
                    self.pipeline['jira_ticket'] = ticket
                    self.pipeline['jira_server'] = self.server
                return

        description = self.description + '\n'
        for match in matches:
            description += unicode(JiraFormattedMatchString(self.rule, match))
            if len(matches) > 1:
                description += '\n----------------------------------------\n'

        self.jira_args['summary'] = title
        self.jira_args['description'] = description

        try:
            self.issue = self.client.create_issue(**self.jira_args)
        except JIRAError as e:
            raise EAException("Error creating JIRA ticket: %s" % (e))
        elastalert_logger.info("Opened Jira ticket: %s" % (self.issue))

        if self.pipeline is not None:
            self.pipeline['jira_ticket'] = self.issue
            self.pipeline['jira_server'] = self.server

    def create_default_title(self, matches, for_search=False):
        # If there is a query_key, use that in the title
        if 'query_key' in self.rule and self.rule['query_key'] in matches[0]:
            title = 'ElastAlert: %s matched %s' % (matches[0][self.rule['query_key']], self.rule['name'])
        else:
            title = 'ElastAlert: %s' % (self.rule['name'])

        if for_search:
            return title

        title += ' - %s' % (pretty_ts(matches[0][self.rule['timestamp_field']], self.rule.get('use_local_time')))

        # Add count for spikes
        count = matches[0].get('spike_count')
        if count:
            title += ' - %s+ events' % (count)

        return title

    def get_info(self):
        return {'type': 'jira'}


class CommandAlerter(Alerter):
    required_options = set(['command'])

    def __init__(self, *args):
        super(CommandAlerter, self).__init__(*args)
        self.last_command = []
        if isinstance(self.rule['command'], basestring) and '%' in self.rule['command']:
            logging.warning('Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

    def alert(self, matches):
        # Format the command and arguments
        try:
            command = [command_arg % matches[0] for command_arg in self.rule['command']]
            self.last_command = command
        except KeyError as e:
            raise EAException("Error formatting command: %s" % (e))

        # Run command and pipe data
        try:
            subp = subprocess.Popen(command, stdin=subprocess.PIPE)

            if self.rule.get('pipe_match_json'):
                match_json = json.dumps(matches) + '\n'
                stdout, stderr = subp.communicate(input=match_json)
        except OSError as e:
            raise EAException("Error while running command %s: %s" % (' '.join(command), e))

    def get_info(self):
        return {'type': 'command',
                'command': ' '.join(self.last_command)}


class SnsAlerter(Alerter):
    """send alert using AWS SNS service"""
    required_options = frozenset(['sns_topic_arn'])

    def __init__(self, *args):
        super(SnsAlerter, self).__init__(*args)
        self.sns_topic_arn = self.rule.get('sns_topic_arn', '')
        self.aws_access_key = self.rule.get('aws_access_key', '')
        self.aws_secret_key = self.rule.get('aws_secret_key', '')
        self.aws_region = self.rule.get('aws_region', 'us-east-1')

    def create_default_title(self):
        subject = 'ElastAlert: %s' % (self.rule['name'])
        return subject

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        # use instance role if aws_access_key and aws_secret_key are not specified
        if not self.aws_access_key and not self.aws_secret_key:
            sns_client = sns.connect_to_region(self.aws_region)
        else:
            sns_client = sns.connect_to_region(self.aws_region,
                                               aws_access_key_id=self.aws_access_key,
                                               aws_secret_access_key=self.aws_secret_key)
        sns_client.publish(self.sns_topic_arn, body, subject=self.create_default_title())
        elastalert_logger.info("Sent sns notification to %s" % (self.sns_topic_arn))


class HipChatAlerter(Alerter):
    """ Creates a HipChat room notification for each alert """
    required_options = frozenset(['hipchat_auth_token', 'hipchat_room_id'])

    def __init__(self, rule):
        super(HipChatAlerter, self).__init__(rule)
        self.hipchat_auth_token = self.rule['hipchat_auth_token']
        self.hipchat_room_id = self.rule['hipchat_room_id']
        self.hipchat_domain = self.rule.get('hipchat_domain', 'api.hipchat.com')
        self.hipchat_ignore_ssl_errors = self.rule.get('hipchat_ignore_ssl_errors', False)
        self.url = 'https://%s/v2/room/%s/notification?auth_token=%s' % (self.hipchat_domain, self.hipchat_room_id, self.hipchat_auth_token)

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        # post to hipchat
        headers = {'content-type': 'application/json'}
        payload = {
            'color': 'red',
            'message': body.replace('\n', '<br />'),
            'notify': True
        }

        try:
            if self.hipchat_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()
            response = requests.post(self.url, data=json.dumps(payload), headers=headers, verify=not self.hipchat_ignore_ssl_errors)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to hipchat: %s" % e)
        elastalert_logger.info("Alert sent to HipChat room %s" % self.hipchat_room_id)

    def get_info(self):
        return {'type': 'hipchat',
                'hipchat_room_id': self.hipchat_room_id}


class SlackAlerter(Alerter):
    """ Creates a Slack room message for each alert """
    required_options = frozenset(['slack_webhook_url'])

    def __init__(self, rule):
        super(SlackAlerter, self).__init__(rule)
        self.slack_webhook_url = self.rule['slack_webhook_url']
        self.slack_proxy = self.rule.get('slack_proxy', None)
        self.slack_username_override = self.rule.get('slack_username_override', 'elastalert')
        self.slack_emoji_override = self.rule.get('slack_emoji_override', ':ghost:')
        self.slack_msg_color = self.rule.get('slack_msg_color', 'danger')

    def format_body(self, body):
        # https://api.slack.com/docs/formatting
        body = body.encode('UTF-8')
        body = body.replace('&', '&amp;')
        body = body.replace('<', '&lt;')
        body = body.replace('>', '&gt;')
        return body

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        body = self.format_body(body)
        # post to slack
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.slack_proxy} if self.slack_proxy else None
        payload = {
            'username': self.slack_username_override,
            'icon_emoji': self.slack_emoji_override,
            'attachments': [
                {
                    'color': self.slack_msg_color,
                    'title': self.rule['name'],
                    'text': body,
                    'fields': []
                }
            ]
        }

        try:
            response = requests.post(self.slack_webhook_url, data=json.dumps(payload), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to slack: %s" % e)
        elastalert_logger.info("Alert sent to Slack")

    def get_info(self):
        return {'type': 'slack',
                'slack_username_override': self.slack_username_override,
                'slack_webhook_url': self.slack_webhook_url}


class PagerDutyAlerter(Alerter):
    """ Create an incident on PagerDuty for each alert """
    required_options = frozenset(['pagerduty_service_key', 'pagerduty_client_name'])

    def __init__(self, rule):
        super(PagerDutyAlerter, self).__init__(rule)
        self.pagerduty_service_key = self.rule['pagerduty_service_key']
        self.pagerduty_client_name = self.rule['pagerduty_client_name']
        self.url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        # post to pagerduty
        headers = {'content-type': 'application/json'}
        payload = {
            'service_key': self.pagerduty_service_key,
            'description': self.rule['name'],
            'event_type': 'trigger',
            'client': self.pagerduty_client_name,
            'details': {
                "information": body.encode('UTF-8'),
            },
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload, ensure_ascii=False), headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to pagerduty: %s" % e)
        elastalert_logger.info("Trigger sent to PagerDuty")

    def get_info(self):
        return {'type': 'pagerduty',
                'pagerduty_client_name': self.pagerduty_client_name}


class VictorOpsAlerter(Alerter):
    """ Creates a VictorOps Incident for each alert """
    required_options = frozenset(['victorops_api_key', 'victorops_routing_key', 'victorops_message_type'])

    def __init__(self, rule):
        super(VictorOpsAlerter, self).__init__(rule)
        self.victorops_api_key = self.rule['victorops_api_key']
        self.victorops_routing_key = self.rule['victorops_routing_key']
        self.victorops_message_type = self.rule['victorops_message_type']
        self.victorops_entity_display_name = self.rule.get('victorops_entity_display_name', 'no entity display name')
        self.url = 'https://alert.victorops.com/integrations/generic/20131114/alert/%s/%s' % (self.victorops_api_key, self.victorops_routing_key)

    def alert(self, matches):
        body = ''
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        # post to victorops
        headers = {'content-type': 'application/json'}
        payload = {
            "message_type": self.victorops_message_type,
            "entity_display_name": self.victorops_entity_display_name,
            "monitoring_tool": "Elastalert",
            "state_message": body
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to VictorOps: %s" % e)
        elastalert_logger.info("Trigger sent to VictorOps")

    def get_info(self):
        return {'type': 'victorops',
                'victorops_routing_key': self.victorops_routing_key}
