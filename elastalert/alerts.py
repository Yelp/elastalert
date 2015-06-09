# -*- coding: utf-8 -*-
import datetime
import json
import logging
import subprocess
from email.mime.text import MIMEText
from smtplib import SMTP
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException
from socket import error

import simplejson
from jira.client import JIRA
from jira.exceptions import JIRAError
from staticconf.loader import yaml_loader
from util import EAException
from util import pretty_ts


class BasicMatchString(object):

    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        alert_text = self.rule.get('alert_text', '')
        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [self.match.get(arg, '<MISSING VALUE>') for arg in alert_text_args]
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
            value_str = str(value)
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        return simplejson.dumps(blob, sort_keys=True, indent=4)

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
            alert_subject_values = [matches[0].get(arg, '<MISSING VALUE>') for arg in alert_subject_args]
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
        logging.info('%d match(es)' % (len(matches)))
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                logging.info('%s matched %s at %s' % (match[qk], self.rule['name'], match[self.rule['timestamp_field']]))
            else:
                logging.info('%s at %s' % (self.rule['name'], match[self.rule['timestamp_field']]))
            logging.info(str(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}


class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
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

            body += str(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'

        # Add JIRA ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.rule['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJIRA ticket: %s' % (url)

        to_addr = self.rule['email']

        email_msg = MIMEText(body)
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
            self.smtp = SMTP(self.smtp_host)
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError:
            raise EAException("SMTP username/password rejected: %s" % (e))
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.close()

        logging.info("Sent email to %s" % (self.rule['email']))

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
        self.assignee = self.rule.get('jira_assignee')
        self.max_age = self.rule.get('jira_max_age', 30)
        self.bump_tickets = self.rule.get('jira_bump_tickets', False)

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
        except JIRAError as e:
            # JIRAError may contain HTML, pass along only first 1024 chars
            raise EAException("Error connecting to JIRA: %s" % (str(e)[:1024]))

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

        date = (datetime.datetime.now() - datetime.timedelta(days=self.max_age)).strftime('%Y/%m/%d')
        jql = 'project=%s AND summary~"%s" and created >= "%s"' % (self.project, title, date)
        try:
            issues = self.client.search_issues(jql)
        except JIRAError as e:
            logging.exception("Error while searching for JIRA ticket using jql '%s': %s" % (jql, e))
            return None

        if len(issues):
            return issues[0]

    def comment_on_ticket(self, ticket, match):
        text = str(JiraFormattedMatchString(self.rule, match))
        timestamp = pretty_ts(match[self.rule['timestamp_field']])
        comment = "This alert was triggered again at %s\n%s" % (timestamp, text)
        self.client.add_comment(ticket, comment)

    def alert(self, matches):
        title = self.create_title(matches)

        if self.bump_tickets:
            ticket = self.find_existing_ticket(matches)
            if ticket:
                logging.info('Commenting on existing ticket %s' % (ticket.key))
                for match in matches:
                    self.comment_on_ticket(ticket, match)
                if self.pipeline is not None:
                    self.pipeline['jira_ticket'] = ticket
                return

        description = ''
        for match in matches:
            description += str(JiraFormattedMatchString(self.rule, match))
            if len(matches) > 1:
                description += '\n----------------------------------------\n'

        self.jira_args['summary'] = title
        self.jira_args['description'] = description

        try:
            self.issue = self.client.create_issue(**self.jira_args)
        except JIRAError as e:
            raise EAException("Error creating JIRA ticket: %s" % (e))
        logging.info("Opened Jira ticket: %s" % (self.issue))

        if self.pipeline is not None:
            self.pipeline['jira_ticket'] = self.issue

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
        if isinstance(self.rule['command'], basestring) and '%' in self.rule['command']:
            logging.warning('Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

    def alert(self, matches):
        for match in matches:
            # Format the command and arguments
            try:
                command = [command_arg % match for command_arg in self.rule['command']]
                self.last_command = command
            except KeyError as e:
                raise EAException("Error formatting command: %s" % (e))

            # Run command and pipe data
            try:
                subp = subprocess.Popen(command, stdin=subprocess.PIPE)

                if self.rule.get('pipe_match_json'):
                    match_json = json.dumps(match)
                    stdout, stderr = subp.communicate(input=match_json)
            except OSError as e:
                raise EAException("Error while running command %s: %s" % (' '.join(command), e))

    def get_info(self):
        return {'type': 'command',
                'command': ' '.join(self.last_command)}
