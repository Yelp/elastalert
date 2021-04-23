# -*- coding: utf-8 -*-
import copy
import datetime
import json
import os
import re
import subprocess
import sys
import time
import uuid
import warnings
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formatdate
from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException
from socket import error

import boto3
import requests
import stomp
from exotel import Exotel
from jira.client import JIRA
from jira.exceptions import JIRAError
from requests.auth import HTTPProxyAuth
from requests.exceptions import RequestException
from staticconf.loader import yaml_loader
from texttable import Texttable
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from .util import EAException
from .util import elastalert_logger
from .util import lookup_es_key
from .util import pretty_ts
from .util import resolve_string
from .util import ts_now
from .util import ts_to_dt


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class BasicMatchString(object):
    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
        alert_text = str(self.rule.get('alert_text', ''))
        if 'alert_text_jinja' == self.rule.get('alert_text_type'):
            #  Top fields are accessible via `{{field_name}}` or `{{jinja_root_name['field_name']}}`
            #  `jinja_root_name` dict is useful when accessing *fields with dots in their keys*,
            #  as Jinja treat dot as a nested field.
            alert_text = self.rule.get("jinja_template").render(**self.match,
                                                                **{self.rule['jinja_root_name']: self.match})
        elif 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in list(self.rule.get('alert_text_kw').items()):
                val = lookup_es_key(self.match, name)

                # Support referencing other top-level rule properties
                # This technically may not work if there is a top-level rule property with the same name
                # as an es result key, since it would have been matched in the lookup_es_key call above
                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            alert_text = alert_text.format(**kw)

        self.text += alert_text

    def _add_rule_text(self):
        self.text += self.rule['type'].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in list(self.match.items()):
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = list(counts.items())

                if not top_events:
                    self.text += 'No events found.\n'
                else:
                    top_events.sort(key=lambda x: x[1], reverse=True)
                    for term, count in top_events:
                        self.text += '%s: %s\n' % (term, count)

                self.text += '\n'

    def _add_match_items(self):
        match_items = list(self.match.items())
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith('top_events_'):
                continue
            value_str = str(value)
            value_str.replace('\\n', '\n')
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, ensure_ascii=False)
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-1 to show something
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, encoding='Latin-1', ensure_ascii=False)

    def __str__(self):
        self.text = ''
        if 'alert_text' not in self.rule:
            self.text += self.rule['name'] + '\n\n'

        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get('alert_text_type') != 'alert_text_only' and self.rule.get('alert_text_type') != 'alert_text_jinja':
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get('top_count_keys'):
                self._add_top_counts()
            if self.rule.get('alert_text_type') != 'exclude_fields':
                self._add_match_items()
        return self.text


class JiraFormattedMatchString(BasicMatchString):
    def _add_match_items(self):
        match_items = dict([(x, y) for x, y in list(self.match.items()) if not x.startswith('top_events_')])
        json_blob = self._pretty_print_as_json(match_items)
        preformatted_text = '{{code}}{0}{{code}}'.format(json_blob)
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
        self.resolve_rule_references(self.rule)

    def resolve_rule_references(self, root):
        # Support referencing other top-level rule properties to avoid redundant copy/paste
        if type(root) == list:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for i, item in enumerate(copy.copy(root)):
                if type(item) == dict or type(item) == list:
                    self.resolve_rule_references(root[i])
                else:
                    root[i] = self.resolve_rule_reference(item)
        elif type(root) == dict:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for key, value in root.copy().items():
                if type(value) == dict or type(value) == list:
                    self.resolve_rule_references(root[key])
                else:
                    root[key] = self.resolve_rule_reference(value)

    def resolve_rule_reference(self, value):
        strValue = str(value)
        if strValue.startswith('$') and strValue.endswith('$') and strValue[1:-1] in self.rule:
            if type(value) == int:
                return int(self.rule[strValue[1:-1]])
            else:
                return self.rule[strValue[1:-1]]
        else:
            return value

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
        alert_subject = str(self.rule['alert_subject'])
        alert_subject_max_len = int(self.rule.get('alert_subject_max_len', 2048))

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, subject_value in enumerate(alert_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            alert_subject_values = [missing if val is None else val for val in alert_subject_values]
            alert_subject = alert_subject.format(*alert_subject_values)

        if len(alert_subject) > alert_subject_max_len:
            alert_subject = alert_subject[:alert_subject_max_len]

        return alert_subject

    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text__maximum_width(self):
        """Get maximum width allowed for summary text."""
        return 80

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            text = self.rule.get('summary_prefix', '')
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]
            # Include a count aggregation so that we can see at a glance how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )
            text_table = Texttable(max_width=self.get_aggregation_summary_text__maximum_width())
            text_table.header(summary_table_fields_with_count)
            # Format all fields as 'text' to avoid long numbers being shown as scientific notation
            text_table.set_cols_dtype(['t' for i in summary_table_fields_with_count])
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([str(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1
            for keys, count in match_aggregation.items():
                text_table.add_row([key for key in keys] + [count])
            text += text_table.draw() + '\n\n'
            text += self.rule.get('summary_prefix', '')
        return str(text)

    def create_default_title(self, matches):
        return self.rule['name']

    def get_account(self, account_file):
        """ Gets the username and password from an account file.

        :param account_file: Path to the file which contains user and password information.
        It can be either an absolute file path or one that is relative to the given rule.
        """
        if os.path.isabs(account_file):
            account_file_path = account_file
        else:
            account_file_path = os.path.join(os.path.dirname(self.rule['rule_file']), account_file)
        account_conf = yaml_loader(account_file_path)
        if 'user' not in account_conf or 'password' not in account_conf:
            raise EAException('Account file must have user and password fields')
        self.user = account_conf['user']
        self.password = account_conf['password']


class StompAlerter(Alerter):
    """ The stomp alerter publishes alerts via stomp to a broker. """
    required_options = frozenset(
        ['stomp_hostname', 'stomp_hostport', 'stomp_login', 'stomp_password'])

    def alert(self, matches):
        alerts = []

        qk = self.rule.get('query_key', None)

        fullmessage = {}
        for match in matches:
            if qk is not None:
                resmatch = lookup_es_key(match, qk)
            else:
                resmatch = None

            if resmatch is not None:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], resmatch, lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    'Alert for %s, %s at %s:' % (self.rule['name'], resmatch, lookup_es_key(
                        match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = resmatch
            else:
                elastalert_logger.info('Rule %s generated an alert at %s:' % (
                    self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    'Rule %s generated an alert at %s:' % (self.rule['name'], lookup_es_key(
                        match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = lookup_es_key(
                    match, self.rule['timestamp_field'])
            elastalert_logger.info(str(BasicMatchString(self.rule, match)))

        fullmessage['alerts'] = alerts
        fullmessage['rule'] = self.rule['name']
        fullmessage['rule_file'] = self.rule['rule_file']

        fullmessage['matching'] = str(BasicMatchString(self.rule, match))
        fullmessage['alertDate'] = datetime.datetime.now(
        ).strftime("%Y-%m-%d %H:%M:%S")
        fullmessage['body'] = self.create_alert_body(matches)

        fullmessage['matches'] = matches

        self.stomp_hostname = self.rule.get('stomp_hostname', 'localhost')
        self.stomp_hostport = self.rule.get('stomp_hostport', '61613')
        self.stomp_login = self.rule.get('stomp_login', 'admin')
        self.stomp_password = self.rule.get('stomp_password', 'admin')
        self.stomp_destination = self.rule.get(
            'stomp_destination', '/queue/ALERT')
        self.stomp_ssl = self.rule.get('stomp_ssl', False)

        conn = stomp.Connection([(self.stomp_hostname, self.stomp_hostport)], use_ssl=self.stomp_ssl)

        conn.connect(self.stomp_login, self.stomp_password)
        # Ensures that the CONNECTED frame is received otherwise, the disconnect call will fail.
        time.sleep(1)
        conn.send(self.stomp_destination, json.dumps(fullmessage))
        conn.disconnect()

    def get_info(self):
        return {'type': 'stomp'}


class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal). """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field'])))
            else:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
            elastalert_logger.info(str(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}


class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.assets_dir = self.rule.get('assets_dir', '/tmp')
        self.images_dictionary = dict(zip(self.rule.get('email_image_keys', []),  self.rule.get('email_image_values', [])))
        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        self.smtp_key_file = self.rule.get('smtp_key_file')
        self.smtp_cert_file = self.rule.get('smtp_cert_file')
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
        add_suffix = self.rule.get('email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # Add JIRA ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJIRA ticket: %s' % (url)

        to_addr = self.rule['email']
        if 'email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['email_from_field'])
            if isinstance(recipient, str):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'email_add_domain' in self.rule:
                    to_addr = [name + self.rule['email_add_domain'] for name in to_addr]
        if self.rule.get('email_format') == 'html':
            # email_msg = MIMEText(body, 'html', _charset='UTF-8') # old way
            email_msg = MIMEMultipart()
            msgText = MIMEText(body, 'html', _charset='UTF-8')
            email_msg.attach(msgText)   # Added, and edited the previous line

            for image_key in self.images_dictionary:
                fp = open(os.path.join(self.assets_dir, self.images_dictionary[image_key]), 'rb')
                img = MIMEImage(fp.read())
                fp.close()
                img.add_header('Content-ID', '<{}>'.format(image_key))
                email_msg.attach(img)
        else:
            email_msg = MIMEText(body, _charset='UTF-8')
        email_msg['Subject'] = self.create_title(matches)
        email_msg['To'] = ', '.join(to_addr)
        email_msg['From'] = self.from_addr
        email_msg['Reply-To'] = self.rule.get('email_reply_to', email_msg['To'])
        email_msg['Date'] = formatdate()
        if self.rule.get('cc'):
            email_msg['CC'] = ','.join(self.rule['cc'])
            to_addr = to_addr + self.rule['cc']
        if self.rule.get('bcc'):
            to_addr = to_addr + self.rule['bcc']

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
                else:
                    self.smtp = SMTP_SSL(self.smtp_host, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls(keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.quit()

        elastalert_logger.info("Sent email to %s" % (to_addr))

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

    # Maintain a static set of built-in fields that we explicitly know how to set
    # For anything else, we will do best-effort and try to set a string value
    known_field_list = [
        'jira_account_file',
        'jira_assignee',
        'jira_bump_after_inactivity',
        'jira_bump_in_statuses',
        'jira_bump_not_in_statuses',
        'jira_bump_only',
        'jira_bump_tickets',
        'jira_component',
        'jira_components',
        'jira_description',
        'jira_ignore_in_title',
        'jira_issuetype',
        'jira_label',
        'jira_labels',
        'jira_max_age',
        'jira_priority',
        'jira_project',
        'jira_server',
        'jira_transition_to',
        'jira_watchers',
    ]

    # Some built-in jira types that can be used as custom fields require special handling
    # Here is a sample of one of them:
    # {"id":"customfield_12807","name":"My Custom Field","custom":true,"orderable":true,"navigable":true,"searchable":true,
    # "clauseNames":["cf[12807]","My Custom Field"],"schema":{"type":"array","items":"string",
    # "custom":"com.atlassian.jira.plugin.system.customfieldtypes:multiselect","customId":12807}}
    # There are likely others that will need to be updated on a case-by-case basis
    custom_string_types_with_special_handling = [
        'com.atlassian.jira.plugin.system.customfieldtypes:multicheckboxes',
        'com.atlassian.jira.plugin.system.customfieldtypes:multiselect',
        'com.atlassian.jira.plugin.system.customfieldtypes:radiobuttons',
    ]

    def __init__(self, rule):
        super(JiraAlerter, self).__init__(rule)
        self.server = self.rule['jira_server']
        self.get_account(self.rule['jira_account_file'])
        self.project = self.rule['jira_project']
        self.issue_type = self.rule['jira_issuetype']

        # Deferred settings refer to values that can only be resolved when a match
        # is found and as such loading them will be delayed until we find a match
        self.deferred_settings = []

        # We used to support only a single component. This allows us to maintain backwards compatibility
        # while also giving the user-facing API a more representative name
        self.components = self.rule.get('jira_components', self.rule.get('jira_component'))

        # We used to support only a single label. This allows us to maintain backwards compatibility
        # while also giving the user-facing API a more representative name
        self.labels = self.rule.get('jira_labels', self.rule.get('jira_label'))

        self.description = self.rule.get('jira_description', '')
        self.assignee = self.rule.get('jira_assignee')
        self.max_age = self.rule.get('jira_max_age', 30)
        self.priority = self.rule.get('jira_priority')
        self.bump_tickets = self.rule.get('jira_bump_tickets', False)
        self.bump_not_in_statuses = self.rule.get('jira_bump_not_in_statuses')
        self.bump_in_statuses = self.rule.get('jira_bump_in_statuses')
        self.bump_after_inactivity = self.rule.get('jira_bump_after_inactivity', 0)
        self.bump_only = self.rule.get('jira_bump_only', False)
        self.transition = self.rule.get('jira_transition_to', False)
        self.watchers = self.rule.get('jira_watchers')
        self.client = None

        if self.bump_in_statuses and self.bump_not_in_statuses:
            msg = 'Both jira_bump_in_statuses (%s) and jira_bump_not_in_statuses (%s) are set.' % \
                  (','.join(self.bump_in_statuses), ','.join(self.bump_not_in_statuses))
            intersection = list(set(self.bump_in_statuses) & set(self.bump_in_statuses))
            if intersection:
                msg = '%s Both have common statuses of (%s). As such, no tickets will ever be found.' % (
                    msg, ','.join(intersection))
            msg += ' This should be simplified to use only one or the other.'
            elastalert_logger.warning(msg)

        self.reset_jira_args()

        try:
            self.client = JIRA(self.server, basic_auth=(self.user, self.password))
            self.get_priorities()
            self.jira_fields = self.client.fields()
            self.get_arbitrary_fields()
        except JIRAError as e:
            # JIRAError may contain HTML, pass along only first 1024 chars
            raise EAException("Error connecting to JIRA: %s" % (str(e)[:1024])).with_traceback(sys.exc_info()[2])

        self.set_priority()

    def set_priority(self):
        try:
            if self.priority is not None and self.client is not None:
                self.jira_args['priority'] = {'id': self.priority_ids[self.priority]}
        except KeyError:
            elastalert_logger.error("Priority %s not found. Valid priorities are %s" % (self.priority, list(self.priority_ids.keys())))

    def reset_jira_args(self):
        self.jira_args = {'project': {'key': self.project},
                          'issuetype': {'name': self.issue_type}}

        if self.components:
            # Support single component or list
            if type(self.components) != list:
                self.jira_args['components'] = [{'name': self.components}]
            else:
                self.jira_args['components'] = [{'name': component} for component in self.components]
        if self.labels:
            # Support single label or list
            if type(self.labels) != list:
                self.labels = [self.labels]
            self.jira_args['labels'] = self.labels
        if self.watchers:
            # Support single watcher or list
            if type(self.watchers) != list:
                self.watchers = [self.watchers]
        if self.assignee:
            self.jira_args['assignee'] = {'name': self.assignee}

        self.set_priority()

    def set_jira_arg(self, jira_field, value, fields):
        # Remove the jira_ part.  Convert underscores to spaces
        normalized_jira_field = jira_field[5:].replace('_', ' ').lower()
        # All jira fields should be found in the 'id' or the 'name' field. Therefore, try both just in case
        for identifier in ['name', 'id']:
            field = next((f for f in fields if normalized_jira_field == f[identifier].replace('_', ' ').lower()), None)
            if field:
                break
        if not field:
            # Log a warning to ElastAlert saying that we couldn't find that type?
            # OR raise and fail to load the alert entirely? Probably the latter...
            raise Exception("Could not find a definition for the jira field '{0}'".format(normalized_jira_field))
        arg_name = field['id']
        # Check the schema information to decide how to set the value correctly
        # If the schema information is not available, raise an exception since we don't know how to set it
        # Note this is only the case for two built-in types, id: issuekey and id: thumbnail
        if not ('schema' in field or 'type' in field['schema']):
            raise Exception("Could not determine schema information for the jira field '{0}'".format(normalized_jira_field))
        arg_type = field['schema']['type']

        # Handle arrays of simple types like strings or numbers
        if arg_type == 'array':
            # As a convenience, support the scenario wherein the user only provides
            # a single value for a multi-value field e.g. jira_labels: Only_One_Label
            if type(value) != list:
                value = [value]
            array_items = field['schema']['items']
            # Simple string types
            if array_items in ['string', 'date', 'datetime']:
                # Special case for multi-select custom types (the JIRA metadata says that these are strings, but
                # in reality, they are required to be provided as an object.
                if 'custom' in field['schema'] and field['schema']['custom'] in self.custom_string_types_with_special_handling:
                    self.jira_args[arg_name] = [{'value': v} for v in value]
                else:
                    self.jira_args[arg_name] = value
            elif array_items == 'number':
                self.jira_args[arg_name] = [int(v) for v in value]
            # Also attempt to handle arrays of complex types that have to be passed as objects with an identifier 'key'
            elif array_items == 'option':
                self.jira_args[arg_name] = [{'value': v} for v in value]
            else:
                # Try setting it as an object, using 'name' as the key
                # This may not work, as the key might actually be 'key', 'id', 'value', or something else
                # If it works, great!  If not, it will manifest itself as an API error that will bubble up
                self.jira_args[arg_name] = [{'name': v} for v in value]
        # Handle non-array types
        else:
            # Simple string types
            if arg_type in ['string', 'date', 'datetime']:
                # Special case for custom types (the JIRA metadata says that these are strings, but
                # in reality, they are required to be provided as an object.
                if 'custom' in field['schema'] and field['schema']['custom'] in self.custom_string_types_with_special_handling:
                    self.jira_args[arg_name] = {'value': value}
                else:
                    self.jira_args[arg_name] = value
            # Number type
            elif arg_type == 'number':
                self.jira_args[arg_name] = int(value)
            elif arg_type == 'option':
                self.jira_args[arg_name] = {'value': value}
            # Complex type
            else:
                self.jira_args[arg_name] = {'name': value}

    def get_arbitrary_fields(self):
        # Clear jira_args
        self.reset_jira_args()

        for jira_field, value in self.rule.items():
            # If we find a field that is not covered by the set that we are aware of, it means it is either:
            # 1. A built-in supported field in JIRA that we don't have on our radar
            # 2. A custom field that a JIRA admin has configured
            if jira_field.startswith('jira_') and jira_field not in self.known_field_list and str(value)[:1] != '#':
                self.set_jira_arg(jira_field, value, self.jira_fields)
            if jira_field.startswith('jira_') and jira_field not in self.known_field_list and str(value)[:1] == '#':
                self.deferred_settings.append(jira_field)

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

        if 'jira_ignore_in_title' in self.rule:
            title = title.replace(matches[0].get(self.rule['jira_ignore_in_title'], ''), '')

        # This is necessary for search to work. Other special characters and dashes
        # directly adjacent to words appear to be ok
        title = title.replace(' - ', ' ')
        title = title.replace('\\', '\\\\')

        date = (datetime.datetime.now() - datetime.timedelta(days=self.max_age)).strftime('%Y-%m-%d')
        jql = 'project=%s AND summary~"%s" and created >= "%s"' % (self.project, title, date)
        if self.bump_in_statuses:
            jql = '%s and status in (%s)' % (jql, ','.join(["\"%s\"" % status if ' ' in status else status for status
                                                            in self.bump_in_statuses]))
        if self.bump_not_in_statuses:
            jql = '%s and status not in (%s)' % (jql, ','.join(["\"%s\"" % status if ' ' in status else status
                                                                for status in self.bump_not_in_statuses]))
        try:
            issues = self.client.search_issues(jql)
        except JIRAError as e:
            elastalert_logger.exception("Error while searching for JIRA ticket using jql '%s': %s" % (jql, e))
            return None

        if len(issues):
            return issues[0]

    def comment_on_ticket(self, ticket, match):
        text = str(JiraFormattedMatchString(self.rule, match))
        timestamp = pretty_ts(lookup_es_key(match, self.rule['timestamp_field']))
        comment = "This alert was triggered again at %s\n%s" % (timestamp, text)
        self.client.add_comment(ticket, comment)

    def transition_ticket(self, ticket):
        transitions = self.client.transitions(ticket)
        for t in transitions:
            if t['name'] == self.transition:
                self.client.transition_issue(ticket, t['id'])

    def alert(self, matches):
        # Reset arbitrary fields to pick up changes
        self.get_arbitrary_fields()
        if len(self.deferred_settings) > 0:
            fields = self.client.fields()
            for jira_field in self.deferred_settings:
                value = lookup_es_key(matches[0], self.rule[jira_field][1:])
                self.set_jira_arg(jira_field, value, fields)

        title = self.create_title(matches)

        if self.bump_tickets:
            ticket = self.find_existing_ticket(matches)
            if ticket:
                inactivity_datetime = ts_now() - datetime.timedelta(days=self.bump_after_inactivity)
                if ts_to_dt(ticket.fields.updated) >= inactivity_datetime:
                    if self.pipeline is not None:
                        self.pipeline['jira_ticket'] = None
                        self.pipeline['jira_server'] = self.server
                    return None
                elastalert_logger.info('Commenting on existing ticket %s' % (ticket.key))
                for match in matches:
                    try:
                        self.comment_on_ticket(ticket, match)
                    except JIRAError as e:
                        elastalert_logger.exception("Error while commenting on ticket %s: %s" % (ticket, e))
                    if self.labels:
                        for label in self.labels:
                            try:
                                ticket.fields.labels.append(label)
                            except JIRAError as e:
                                elastalert_logger.exception("Error while appending labels to ticket %s: %s" % (ticket, e))
                if self.transition:
                    elastalert_logger.info('Transitioning existing ticket %s' % (ticket.key))
                    try:
                        self.transition_ticket(ticket)
                    except JIRAError as e:
                        elastalert_logger.exception("Error while transitioning ticket %s: %s" % (ticket, e))

                if self.pipeline is not None:
                    self.pipeline['jira_ticket'] = ticket
                    self.pipeline['jira_server'] = self.server
                return None
        if self.bump_only:
            return None

        self.jira_args['summary'] = title
        self.jira_args['description'] = self.create_alert_body(matches)

        try:
            self.issue = self.client.create_issue(**self.jira_args)

            # You can not add watchers on initial creation. Only as a follow-up action
            if self.watchers:
                for watcher in self.watchers:
                    try:
                        self.client.add_watcher(self.issue.key, watcher)
                    except Exception as ex:
                        # Re-raise the exception, preserve the stack-trace, and give some
                        # context as to which watcher failed to be added
                        raise Exception(
                            "Exception encountered when trying to add '{0}' as a watcher. Does the user exist?\n{1}" .format(
                                watcher,
                                ex
                            )).with_traceback(sys.exc_info()[2])

        except JIRAError as e:
            raise EAException("Error creating JIRA ticket using jira_args (%s): %s" % (self.jira_args, e))
        elastalert_logger.info("Opened Jira ticket: %s" % (self.issue))

        if self.pipeline is not None:
            self.pipeline['jira_ticket'] = self.issue
            self.pipeline['jira_server'] = self.server

    def create_alert_body(self, matches):
        body = self.description + '\n'
        body += self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(JiraFormattedMatchString(self.rule, match))
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text(self, matches):
        text = super(JiraAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '{{noformat}}{0}{{noformat}}'.format(text)
        return text

    def create_default_title(self, matches, for_search=False):
        # If there is a query_key, use that in the title

        if 'query_key' in self.rule and lookup_es_key(matches[0], self.rule['query_key']):
            title = 'ElastAlert: %s matched %s' % (lookup_es_key(matches[0], self.rule['query_key']), self.rule['name'])
        else:
            title = 'ElastAlert: %s' % (self.rule['name'])

        if for_search:
            return title

        timestamp = matches[0].get(self.rule['timestamp_field'])
        if timestamp:
            title += ' - %s' % (pretty_ts(timestamp, self.rule.get('use_local_time')))

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

        self.shell = False
        if isinstance(self.rule['command'], str):
            self.shell = True
            if '%' in self.rule['command']:
                elastalert_logger.warning('Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

    def alert(self, matches):
        # Format the command and arguments
        try:
            command = [resolve_string(command_arg, matches[0]) for command_arg in self.rule['command']]
            self.last_command = command
        except KeyError as e:
            raise EAException("Error formatting command: %s" % (e))

        # Run command and pipe data
        try:
            subp = subprocess.Popen(command, stdin=subprocess.PIPE, shell=self.shell)

            if self.rule.get('pipe_match_json'):
                match_json = json.dumps(matches, cls=DateTimeEncoder) + '\n'
                stdout, stderr = subp.communicate(input=match_json.encode())
            elif self.rule.get('pipe_alert_text'):
                alert_text = self.create_alert_body(matches)
                stdout, stderr = subp.communicate(input=alert_text.encode())
            if self.rule.get("fail_on_non_zero_exit", False) and subp.wait():
                raise EAException("Non-zero exit code while running command %s" % (' '.join(command)))
        except OSError as e:
            raise EAException("Error while running command %s: %s" % (' '.join(command), e))

    def get_info(self):
        return {'type': 'command',
                'command': ' '.join(self.last_command)}


class SnsAlerter(Alerter):
    """ Send alert using AWS SNS service """
    required_options = frozenset(['sns_topic_arn'])

    def __init__(self, *args):
        super(SnsAlerter, self).__init__(*args)
        self.sns_topic_arn = self.rule.get('sns_topic_arn', '')
        self.sns_aws_access_key_id = self.rule.get('sns_aws_access_key_id')
        self.sns_aws_secret_access_key = self.rule.get('sns_aws_secret_access_key')
        self.sns_aws_region = self.rule.get('sns_aws_region', 'us-east-1')
        self.profile = self.rule.get('boto_profile', None)  # Deprecated
        self.profile = self.rule.get('sns_aws_profile', None)

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])
        return subject

    def alert(self, matches):
        body = self.create_alert_body(matches)

        if self.profile is None:
            session = boto3.Session(
                aws_access_key_id=self.sns_aws_access_key_id,
                aws_secret_access_key=self.sns_aws_access_key_id,
                region_name=self.sns_aws_region
            )
        else:
            session = boto3.Session(profile_name=self.profile)

        sns_client = session.client('sns')
        sns_client.publish(
            TopicArn=self.sns_topic_arn,
            Message=body,
            Subject=self.create_title(matches)
        )
        elastalert_logger.info("Sent sns notification to %s" % (self.sns_topic_arn))


class MsTeamsAlerter(Alerter):
    """ Creates a Microsoft Teams Conversation Message for each alert """
    required_options = frozenset(['ms_teams_webhook_url', 'ms_teams_alert_summary'])

    def __init__(self, rule):
        super(MsTeamsAlerter, self).__init__(rule)
        self.ms_teams_webhook_url = self.rule['ms_teams_webhook_url']
        if isinstance(self.ms_teams_webhook_url, str):
            self.ms_teams_webhook_url = [self.ms_teams_webhook_url]
        self.ms_teams_proxy = self.rule.get('ms_teams_proxy', None)
        self.ms_teams_alert_summary = self.rule.get('ms_teams_alert_summary', 'ElastAlert Message')
        self.ms_teams_alert_fixed_width = self.rule.get('ms_teams_alert_fixed_width', False)
        self.ms_teams_theme_color = self.rule.get('ms_teams_theme_color', '')

    def format_body(self, body):
        if self.ms_teams_alert_fixed_width:
            body = body.replace('`', "'")
            body = "```{0}```".format('```\n\n```'.join(x for x in body.split('\n'))).replace('\n``````', '')
        return body

    def alert(self, matches):
        body = self.create_alert_body(matches)

        body = self.format_body(body)
        # post to Teams
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.ms_teams_proxy} if self.ms_teams_proxy else None
        payload = {
            '@type': 'MessageCard',
            '@context': 'http://schema.org/extensions',
            'summary': self.ms_teams_alert_summary,
            'title': self.create_title(matches),
            'text': body
        }
        if self.ms_teams_theme_color != '':
            payload['themeColor'] = self.ms_teams_theme_color

        for url in self.ms_teams_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to ms teams: %s" % e)
        elastalert_logger.info("Alert sent to MS Teams")

    def get_info(self):
        return {'type': 'ms_teams',
                'ms_teams_webhook_url': self.ms_teams_webhook_url}


class SlackAlerter(Alerter):
    """ Creates a Slack room message for each alert """
    required_options = frozenset(['slack_webhook_url'])

    def __init__(self, rule):
        super(SlackAlerter, self).__init__(rule)
        self.slack_webhook_url = self.rule['slack_webhook_url']
        if isinstance(self.slack_webhook_url, str):
            self.slack_webhook_url = [self.slack_webhook_url]
        self.slack_proxy = self.rule.get('slack_proxy', None)
        self.slack_username_override = self.rule.get('slack_username_override', 'elastalert')
        self.slack_channel_override = self.rule.get('slack_channel_override', '')
        if isinstance(self.slack_channel_override, str):
            self.slack_channel_override = [self.slack_channel_override]
        self.slack_title_link = self.rule.get('slack_title_link', '')
        self.slack_title = self.rule.get('slack_title', '')
        self.slack_emoji_override = self.rule.get('slack_emoji_override', ':ghost:')
        self.slack_icon_url_override = self.rule.get('slack_icon_url_override', '')
        self.slack_msg_color = self.rule.get('slack_msg_color', 'danger')
        self.slack_parse_override = self.rule.get('slack_parse_override', 'none')
        self.slack_text_string = self.rule.get('slack_text_string', '')
        self.slack_alert_fields = self.rule.get('slack_alert_fields', '')
        self.slack_ignore_ssl_errors = self.rule.get('slack_ignore_ssl_errors', False)
        self.slack_timeout = self.rule.get('slack_timeout', 10)
        self.slack_ca_certs = self.rule.get('slack_ca_certs')
        self.slack_attach_kibana_discover_url = self.rule.get('slack_attach_kibana_discover_url', False)
        self.slack_kibana_discover_color = self.rule.get('slack_kibana_discover_color', '#ec4b98')
        self.slack_kibana_discover_title = self.rule.get('slack_kibana_discover_title', 'Discover in Kibana')

    def format_body(self, body):
        # https://api.slack.com/docs/formatting
        return body

    def get_aggregation_summary_text__maximum_width(self):
        width = super(SlackAlerter, self).get_aggregation_summary_text__maximum_width()
        # Reduced maximum width for prettier Slack display.
        return min(width, 75)

    def get_aggregation_summary_text(self, matches):
        text = super(SlackAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '```\n{0}```\n'.format(text)
        return text

    def populate_fields(self, matches):
        alert_fields = []
        for arg in self.slack_alert_fields:
            arg = copy.copy(arg)
            arg['value'] = lookup_es_key(matches[0], arg['value'])
            alert_fields.append(arg)
        return alert_fields

    def alert(self, matches):
        body = self.create_alert_body(matches)

        body = self.format_body(body)
        # post to slack
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.slack_proxy} if self.slack_proxy else None
        payload = {
            'username': self.slack_username_override,
            'parse': self.slack_parse_override,
            'text': self.slack_text_string,
            'attachments': [
                {
                    'color': self.slack_msg_color,
                    'title': self.create_title(matches),
                    'text': body,
                    'mrkdwn_in': ['text', 'pretext'],
                    'fields': []
                }
            ]
        }

        # if we have defined fields, populate noteable fields for the alert
        if self.slack_alert_fields != '':
            payload['attachments'][0]['fields'] = self.populate_fields(matches)

        if self.slack_icon_url_override != '':
            payload['icon_url'] = self.slack_icon_url_override
        else:
            payload['icon_emoji'] = self.slack_emoji_override

        if self.slack_title != '':
            payload['attachments'][0]['title'] = self.slack_title

        if self.slack_title_link != '':
            payload['attachments'][0]['title_link'] = self.slack_title_link

        if self.slack_attach_kibana_discover_url:
            kibana_discover_url = lookup_es_key(matches[0], 'kibana_discover_url')
            if kibana_discover_url:
                payload['attachments'].append({
                    'color': self.slack_kibana_discover_color,
                    'title': self.slack_kibana_discover_title,
                    'title_link': kibana_discover_url
                })

        for url in self.slack_webhook_url:
            for channel_override in self.slack_channel_override:
                try:
                    if self.slack_ca_certs:
                        verify = self.slack_ca_certs
                    else:
                        verify = not self.slack_ignore_ssl_errors
                    if self.slack_ignore_ssl_errors:
                        requests.packages.urllib3.disable_warnings()
                    payload['channel'] = channel_override
                    response = requests.post(
                        url, data=json.dumps(payload, cls=DateTimeEncoder),
                        headers=headers, verify=verify,
                        proxies=proxies,
                        timeout=self.slack_timeout)
                    warnings.resetwarnings()
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting to slack: %s" % e)
        elastalert_logger.info("Alert '%s' sent to Slack" % self.rule['name'])

    def get_info(self):
        return {'type': 'slack',
                'slack_username_override': self.slack_username_override}


class MattermostAlerter(Alerter):
    """ Creates a Mattermsot post for each alert """
    required_options = frozenset(['mattermost_webhook_url'])

    def __init__(self, rule):
        super(MattermostAlerter, self).__init__(rule)

        # HTTP config
        self.mattermost_webhook_url = self.rule['mattermost_webhook_url']
        if isinstance(self.mattermost_webhook_url, str):
            self.mattermost_webhook_url = [self.mattermost_webhook_url]
        self.mattermost_proxy = self.rule.get('mattermost_proxy', None)
        self.mattermost_ignore_ssl_errors = self.rule.get('mattermost_ignore_ssl_errors', False)

        # Override webhook config
        self.mattermost_username_override = self.rule.get('mattermost_username_override', 'elastalert')
        self.mattermost_channel_override = self.rule.get('mattermost_channel_override', '')
        self.mattermost_icon_url_override = self.rule.get('mattermost_icon_url_override', '')

        # Message properties
        self.mattermost_msg_pretext = self.rule.get('mattermost_msg_pretext', '')
        self.mattermost_msg_color = self.rule.get('mattermost_msg_color', 'danger')
        self.mattermost_msg_fields = self.rule.get('mattermost_msg_fields', '')

    def get_aggregation_summary_text__maximum_width(self):
        width = super(MattermostAlerter, self).get_aggregation_summary_text__maximum_width()
        # Reduced maximum width for prettier Mattermost display.
        return min(width, 75)

    def get_aggregation_summary_text(self, matches):
        text = super(MattermostAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '```\n{0}```\n'.format(text)
        return text

    def populate_fields(self, matches):
        alert_fields = []
        missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
        for field in self.mattermost_msg_fields:
            field = copy.copy(field)
            if 'args' in field:
                args_values = [lookup_es_key(matches[0], arg) or missing for arg in field['args']]
                if 'value' in field:
                    field['value'] = field['value'].format(*args_values)
                else:
                    field['value'] = "\n".join(str(arg) for arg in args_values)
                del(field['args'])
            alert_fields.append(field)
        return alert_fields

    def alert(self, matches):
        body = self.create_alert_body(matches)
        title = self.create_title(matches)

        # post to mattermost
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.mattermost_proxy} if self.mattermost_proxy else None
        payload = {
            'attachments': [
                {
                    'fallback': "{0}: {1}".format(title, self.mattermost_msg_pretext),
                    'color': self.mattermost_msg_color,
                    'title': title,
                    'pretext': self.mattermost_msg_pretext,
                    'fields': []
                }
            ]
        }

        if self.rule.get('alert_text_type') == 'alert_text_only':
            payload['attachments'][0]['text'] = body
        else:
            payload['text'] = body

        if self.mattermost_msg_fields != '':
            payload['attachments'][0]['fields'] = self.populate_fields(matches)

        if self.mattermost_icon_url_override != '':
            payload['icon_url'] = self.mattermost_icon_url_override

        if self.mattermost_username_override != '':
            payload['username'] = self.mattermost_username_override

        if self.mattermost_channel_override != '':
            payload['channel'] = self.mattermost_channel_override

        for url in self.mattermost_webhook_url:
            try:
                if self.mattermost_ignore_ssl_errors:
                    requests.urllib3.disable_warnings()

                response = requests.post(
                    url, data=json.dumps(payload, cls=DateTimeEncoder),
                    headers=headers, verify=not self.mattermost_ignore_ssl_errors,
                    proxies=proxies)

                warnings.resetwarnings()
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to Mattermost: %s" % e)
        elastalert_logger.info("Alert sent to Mattermost")

    def get_info(self):
        return {'type': 'mattermost',
                'mattermost_username_override': self.mattermost_username_override,
                'mattermost_webhook_url': self.mattermost_webhook_url}


class PagerDutyAlerter(Alerter):
    """ Create an incident on PagerDuty for each alert """
    required_options = frozenset(['pagerduty_service_key', 'pagerduty_client_name'])

    def __init__(self, rule):
        super(PagerDutyAlerter, self).__init__(rule)
        self.pagerduty_service_key = self.rule['pagerduty_service_key']
        self.pagerduty_client_name = self.rule['pagerduty_client_name']
        self.pagerduty_incident_key = self.rule.get('pagerduty_incident_key', '')
        self.pagerduty_incident_key_args = self.rule.get('pagerduty_incident_key_args', None)
        self.pagerduty_event_type = self.rule.get('pagerduty_event_type', 'trigger')
        self.pagerduty_proxy = self.rule.get('pagerduty_proxy', None)

        self.pagerduty_api_version = self.rule.get('pagerduty_api_version', 'v1')
        self.pagerduty_v2_payload_class = self.rule.get('pagerduty_v2_payload_class', '')
        self.pagerduty_v2_payload_class_args = self.rule.get('pagerduty_v2_payload_class_args', None)
        self.pagerduty_v2_payload_component = self.rule.get('pagerduty_v2_payload_component', '')
        self.pagerduty_v2_payload_component_args = self.rule.get('pagerduty_v2_payload_component_args', None)
        self.pagerduty_v2_payload_group = self.rule.get('pagerduty_v2_payload_group', '')
        self.pagerduty_v2_payload_group_args = self.rule.get('pagerduty_v2_payload_group_args', None)
        self.pagerduty_v2_payload_severity = self.rule.get('pagerduty_v2_payload_severity', 'critical')
        self.pagerduty_v2_payload_source = self.rule.get('pagerduty_v2_payload_source', 'ElastAlert')
        self.pagerduty_v2_payload_source_args = self.rule.get('pagerduty_v2_payload_source_args', None)
        self.pagerduty_v2_payload_custom_details = self.rule.get('pagerduty_v2_payload_custom_details', {})
        self.pagerduty_v2_payload_include_all_info = self.rule.get('pagerduty_v2_payload_include_all_info', True)

        if self.pagerduty_api_version == 'v2':
            self.url = 'https://events.pagerduty.com/v2/enqueue'
        else:
            self.url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to pagerduty
        headers = {'content-type': 'application/json'}
        if self.pagerduty_api_version == 'v2':

            custom_details_payload = {'information': body} if self.pagerduty_v2_payload_include_all_info else {}
            if self.pagerduty_v2_payload_custom_details:
                for match in matches:
                    for custom_details_key, es_key in list(self.pagerduty_v2_payload_custom_details.items()):
                        custom_details_payload[custom_details_key] = lookup_es_key(match, es_key)

            payload = {
                'routing_key': self.pagerduty_service_key,
                'event_action': self.pagerduty_event_type,
                'dedup_key': self.get_incident_key(matches),
                'client': self.pagerduty_client_name,
                'payload': {
                    'class': self.resolve_formatted_key(self.pagerduty_v2_payload_class,
                                                        self.pagerduty_v2_payload_class_args,
                                                        matches),
                    'component': self.resolve_formatted_key(self.pagerduty_v2_payload_component,
                                                            self.pagerduty_v2_payload_component_args,
                                                            matches),
                    'group': self.resolve_formatted_key(self.pagerduty_v2_payload_group,
                                                        self.pagerduty_v2_payload_group_args,
                                                        matches),
                    'severity': self.pagerduty_v2_payload_severity,
                    'source': self.resolve_formatted_key(self.pagerduty_v2_payload_source,
                                                         self.pagerduty_v2_payload_source_args,
                                                         matches),
                    'summary': self.create_title(matches),
                    'custom_details': custom_details_payload,
                },
            }
            match_timestamp = lookup_es_key(matches[0], self.rule.get('timestamp_field', '@timestamp'))
            if match_timestamp:
                payload['payload']['timestamp'] = match_timestamp
        else:
            payload = {
                'service_key': self.pagerduty_service_key,
                'description': self.create_title(matches),
                'event_type': self.pagerduty_event_type,
                'incident_key': self.get_incident_key(matches),
                'client': self.pagerduty_client_name,
                'details': {
                    "information": body,
                },
            }

        # set https proxy, if it was provided
        proxies = {'https': self.pagerduty_proxy} if self.pagerduty_proxy else None
        try:
            response = requests.post(
                self.url,
                data=json.dumps(payload, cls=DateTimeEncoder, ensure_ascii=False),
                headers=headers,
                proxies=proxies
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to pagerduty: %s" % e)

        if self.pagerduty_event_type == 'trigger':
            elastalert_logger.info("Trigger sent to PagerDuty")
        elif self.pagerduty_event_type == 'resolve':
            elastalert_logger.info("Resolve sent to PagerDuty")
        elif self.pagerduty_event_type == 'acknowledge':
            elastalert_logger.info("acknowledge sent to PagerDuty")

    def resolve_formatted_key(self, key, args, matches):
        if args:
            key_values = [lookup_es_key(matches[0], arg) for arg in args]

            # Populate values with rule level properties too
            for i in range(len(key_values)):
                if key_values[i] is None:
                    key_value = self.rule.get(args[i])
                    if key_value:
                        key_values[i] = key_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            key_values = [missing if val is None else val for val in key_values]
            return key.format(*key_values)
        else:
            return key

    def get_incident_key(self, matches):
        if self.pagerduty_incident_key_args:
            incident_key_values = [lookup_es_key(matches[0], arg) for arg in self.pagerduty_incident_key_args]

            # Populate values with rule level properties too
            for i in range(len(incident_key_values)):
                if incident_key_values[i] is None:
                    key_value = self.rule.get(self.pagerduty_incident_key_args[i])
                    if key_value:
                        incident_key_values[i] = key_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            incident_key_values = [missing if val is None else val for val in incident_key_values]
            return self.pagerduty_incident_key.format(*incident_key_values)
        else:
            return self.pagerduty_incident_key

    def get_info(self):
        return {'type': 'pagerduty',
                'pagerduty_client_name': self.pagerduty_client_name}


class PagerTreeAlerter(Alerter):
    """ Creates a PagerTree Incident for each alert """
    required_options = frozenset(['pagertree_integration_url'])

    def __init__(self, rule):
        super(PagerTreeAlerter, self).__init__(rule)
        self.url = self.rule['pagertree_integration_url']
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


class ExotelAlerter(Alerter):
    required_options = frozenset(['exotel_account_sid', 'exotel_auth_token', 'exotel_to_number', 'exotel_from_number'])

    def __init__(self, rule):
        super(ExotelAlerter, self).__init__(rule)
        self.exotel_account_sid = self.rule['exotel_account_sid']
        self.exotel_auth_token = self.rule['exotel_auth_token']
        self.exotel_to_number = self.rule['exotel_to_number']
        self.exotel_from_number = self.rule['exotel_from_number']
        self.sms_body = self.rule.get('exotel_message_body', '')

    def alert(self, matches):
        client = Exotel(self.exotel_account_sid, self.exotel_auth_token)

        try:
            message_body = self.rule['name'] + self.sms_body
            response = client.sms(self.rule['exotel_from_number'], self.rule['exotel_to_number'], message_body)
            if response != 200:
                raise EAException("Error posting to Exotel, response code is %s" % response)
        except RequestException:
            raise EAException("Error posting to Exotel").with_traceback(sys.exc_info()[2])
        elastalert_logger.info("Trigger sent to Exotel")

    def get_info(self):
        return {'type': 'exotel', 'exotel_account': self.exotel_account_sid}


class TwilioAlerter(Alerter):
    required_options = frozenset(['twilio_account_sid', 'twilio_auth_token', 'twilio_to_number', 'twilio_from_number'])

    def __init__(self, rule):
        super(TwilioAlerter, self).__init__(rule)
        self.twilio_account_sid = self.rule['twilio_account_sid']
        self.twilio_auth_token = self.rule['twilio_auth_token']
        self.twilio_to_number = self.rule['twilio_to_number']
        self.twilio_from_number = self.rule['twilio_from_number']

    def alert(self, matches):
        client = TwilioClient(self.twilio_account_sid, self.twilio_auth_token)

        try:
            client.messages.create(body=self.rule['name'],
                                   to=self.twilio_to_number,
                                   from_=self.twilio_from_number)

        except TwilioRestException as e:
            raise EAException("Error posting to twilio: %s" % e)

        elastalert_logger.info("Trigger sent to Twilio")

    def get_info(self):
        return {'type': 'twilio',
                'twilio_client_name': self.twilio_from_number}


class VictorOpsAlerter(Alerter):
    """ Creates a VictorOps Incident for each alert """
    required_options = frozenset(['victorops_api_key', 'victorops_routing_key', 'victorops_message_type'])

    def __init__(self, rule):
        super(VictorOpsAlerter, self).__init__(rule)
        self.victorops_api_key = self.rule['victorops_api_key']
        self.victorops_routing_key = self.rule['victorops_routing_key']
        self.victorops_message_type = self.rule['victorops_message_type']
        self.victorops_entity_id = self.rule.get('victorops_entity_id', None)
        self.victorops_entity_display_name = self.rule.get('victorops_entity_display_name', 'no entity display name')
        self.url = 'https://alert.victorops.com/integrations/generic/20131114/alert/%s/%s' % (
            self.victorops_api_key, self.victorops_routing_key)
        self.victorops_proxy = self.rule.get('victorops_proxy', None)

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to victorops
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.victorops_proxy} if self.victorops_proxy else None
        payload = {
            "message_type": self.victorops_message_type,
            "entity_display_name": self.victorops_entity_display_name,
            "monitoring_tool": "ElastAlert",
            "state_message": body
        }
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


class TelegramAlerter(Alerter):
    """ Send a Telegram message via bot api for each alert """
    required_options = frozenset(['telegram_bot_token', 'telegram_room_id'])

    def __init__(self, rule):
        super(TelegramAlerter, self).__init__(rule)
        self.telegram_bot_token = self.rule['telegram_bot_token']
        self.telegram_room_id = self.rule['telegram_room_id']
        self.telegram_api_url = self.rule.get('telegram_api_url', 'api.telegram.org')
        self.url = 'https://%s/bot%s/%s' % (self.telegram_api_url, self.telegram_bot_token, "sendMessage")
        self.telegram_proxy = self.rule.get('telegram_proxy', None)
        self.telegram_proxy_login = self.rule.get('telegram_proxy_login', None)
        self.telegram_proxy_password = self.rule.get('telegram_proxy_pass', None)

    def alert(self, matches):
        body = '⚠ *%s* ⚠ ```\n' % (self.create_title(matches))
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        if len(body) > 4095:
            body = body[0:4000] + "\n⚠ *message was cropped according to telegram limits!* ⚠"
        body += ' ```'

        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.telegram_proxy} if self.telegram_proxy else None
        auth = HTTPProxyAuth(self.telegram_proxy_login, self.telegram_proxy_password) if self.telegram_proxy_login else None
        payload = {
            'chat_id': self.telegram_room_id,
            'text': body,
            'parse_mode': 'markdown',
            'disable_web_page_preview': True
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies, auth=auth)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Telegram: %s. Details: %s" % (e, "" if e.response is None else e.response.text))

        elastalert_logger.info(
            "Alert sent to Telegram room %s" % self.telegram_room_id)

    def get_info(self):
        return {'type': 'telegram',
                'telegram_room_id': self.telegram_room_id}


class GoogleChatAlerter(Alerter):
    """ Send a notification via Google Chat webhooks """
    required_options = frozenset(['googlechat_webhook_url'])

    def __init__(self, rule):
        super(GoogleChatAlerter, self).__init__(rule)
        self.googlechat_webhook_url = self.rule['googlechat_webhook_url']
        if isinstance(self.googlechat_webhook_url, str):
            self.googlechat_webhook_url = [self.googlechat_webhook_url]
        self.googlechat_format = self.rule.get('googlechat_format', 'basic')
        self.googlechat_header_title = self.rule.get('googlechat_header_title', None)
        self.googlechat_header_subtitle = self.rule.get('googlechat_header_subtitle', None)
        self.googlechat_header_image = self.rule.get('googlechat_header_image', None)
        self.googlechat_footer_kibanalink = self.rule.get('googlechat_footer_kibanalink', None)

    def create_header(self):
        header = None
        if self.googlechat_header_title:
            header = {
                "title": self.googlechat_header_title,
                "subtitle": self.googlechat_header_subtitle,
                "imageUrl": self.googlechat_header_image
            }
        return header

    def create_footer(self):
        footer = None
        if self.googlechat_footer_kibanalink:
            footer = {"widgets": [{
                "buttons": [{
                    "textButton": {
                        "text": "VISIT KIBANA",
                        "onClick": {
                            "openLink": {
                                "url": self.googlechat_footer_kibanalink
                            }
                        }
                    }
                }]
            }]
            }
        return footer

    def create_card(self, matches):
        card = {"cards": [{
            "sections": [{
                "widgets": [
                    {"textParagraph": {"text": self.create_alert_body(matches)}}
                ]}
            ]}
        ]}

        # Add the optional header
        header = self.create_header()
        if header:
            card['cards'][0]['header'] = header

        # Add the optional footer
        footer = self.create_footer()
        if footer:
            card['cards'][0]['sections'].append(footer)
        return card

    def create_basic(self, matches):
        body = self.create_alert_body(matches)
        return {'text': body}

    def alert(self, matches):
        # Format message
        if self.googlechat_format == 'card':
            message = self.create_card(matches)
        else:
            message = self.create_basic(matches)

        # Post to webhook
        headers = {'content-type': 'application/json'}
        for url in self.googlechat_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(message), headers=headers)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to google chat: {}".format(e))
        elastalert_logger.info("Alert sent to Google Chat!")

    def get_info(self):
        return {'type': 'googlechat',
                'googlechat_webhook_url': self.googlechat_webhook_url}


class GitterAlerter(Alerter):
    """ Creates a Gitter activity message for each alert """
    required_options = frozenset(['gitter_webhook_url'])

    def __init__(self, rule):
        super(GitterAlerter, self).__init__(rule)
        self.gitter_webhook_url = self.rule['gitter_webhook_url']
        self.gitter_proxy = self.rule.get('gitter_proxy', None)
        self.gitter_msg_level = self.rule.get('gitter_msg_level', 'error')

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to Gitter
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.gitter_proxy} if self.gitter_proxy else None
        payload = {
            'message': body,
            'level': self.gitter_msg_level
        }

        try:
            response = requests.post(self.gitter_webhook_url, json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Gitter: %s" % e)
        elastalert_logger.info("Alert sent to Gitter")

    def get_info(self):
        return {'type': 'gitter',
                'gitter_webhook_url': self.gitter_webhook_url}


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
        self.servicenow_rest_url = self.rule['servicenow_rest_url']
        self.servicenow_proxy = self.rule.get('servicenow_proxy', None)

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


class AlertaAlerter(Alerter):
    """ Creates an Alerta event for each alert """
    required_options = frozenset(['alerta_api_url'])

    def __init__(self, rule):
        super(AlertaAlerter, self).__init__(rule)

        # Setup defaul parameters
        self.url = self.rule.get('alerta_api_url', None)
        self.api_key = self.rule.get('alerta_api_key', None)
        self.timeout = self.rule.get('alerta_timeout', 86400)
        self.use_match_timestamp = self.rule.get('alerta_use_match_timestamp', False)
        self.use_qk_as_resource = self.rule.get('alerta_use_qk_as_resource', False)
        self.verify_ssl = not self.rule.get('alerta_api_skip_ssl', False)
        self.missing_text = self.rule.get('alert_missing_value', '<MISSING VALUE>')

        # Fill up default values of the API JSON payload
        self.severity = self.rule.get('alerta_severity', 'warning')
        self.resource = self.rule.get('alerta_resource', 'elastalert')
        self.environment = self.rule.get('alerta_environment', 'Production')
        self.origin = self.rule.get('alerta_origin', 'elastalert')
        self.service = self.rule.get('alerta_service', ['elastalert'])
        self.text = self.rule.get('alerta_text', 'elastalert')
        self.type = self.rule.get('alerta_type', 'elastalert')
        self.event = self.rule.get('alerta_event', 'elastalert')
        self.correlate = self.rule.get('alerta_correlate', [])
        self.tags = self.rule.get('alerta_tags', [])
        self.group = self.rule.get('alerta_group', '')
        self.attributes_keys = self.rule.get('alerta_attributes_keys', [])
        self.attributes_values = self.rule.get('alerta_attributes_values', [])
        self.value = self.rule.get('alerta_value', '')

    def alert(self, matches):
        # Override the resource if requested
        if self.use_qk_as_resource and 'query_key' in self.rule and lookup_es_key(matches[0], self.rule['query_key']):
            self.resource = lookup_es_key(matches[0], self.rule['query_key'])

        headers = {'content-type': 'application/json'}
        if self.api_key is not None:
            headers['Authorization'] = 'Key %s' % (self.rule['alerta_api_key'])
        alerta_payload = self.get_json_payload(matches[0])

        try:
            response = requests.post(self.url, data=alerta_payload, headers=headers, verify=self.verify_ssl)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Alerta: %s" % e)
        elastalert_logger.info("Alert sent to Alerta")

    def create_default_title(self, matches):
        title = '%s' % (self.rule['name'])
        # If the rule has a query_key, add that value
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                title += '.%s' % (qk)
        return title

    def get_info(self):
        return {'type': 'alerta',
                'alerta_url': self.url}

    def get_json_payload(self, match):
        """
            Builds the API Create Alert body, as in
            http://alerta.readthedocs.io/en/latest/api/reference.html#create-an-alert

            For the values that could have references to fields on the match, resolve those references.

        """

        # Using default text and event title if not defined in rule
        alerta_text = self.rule['type'].get_match_str([match]) if self.text == '' else resolve_string(self.text, match, self.missing_text)
        alerta_event = self.create_default_title([match]) if self.event == '' else resolve_string(self.event, match, self.missing_text)

        match_timestamp = lookup_es_key(match, self.rule.get('timestamp_field', '@timestamp'))
        if match_timestamp is None:
            match_timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if self.use_match_timestamp:
            createTime = ts_to_dt(match_timestamp).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            createTime = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        alerta_payload_dict = {
            'resource': resolve_string(self.resource, match, self.missing_text),
            'severity': resolve_string(self.severity, match),
            'timeout': self.timeout,
            'createTime': createTime,
            'type': self.type,
            'environment': resolve_string(self.environment, match, self.missing_text),
            'origin': resolve_string(self.origin, match, self.missing_text),
            'group': resolve_string(self.group, match, self.missing_text),
            'event': alerta_event,
            'text': alerta_text,
            'value': resolve_string(self.value, match, self.missing_text),
            'service': [resolve_string(a_service, match, self.missing_text) for a_service in self.service],
            'tags': [resolve_string(a_tag, match, self.missing_text) for a_tag in self.tags],
            'correlate': [resolve_string(an_event, match, self.missing_text) for an_event in self.correlate],
            'attributes': dict(list(zip(self.attributes_keys,
                                        [resolve_string(a_value, match, self.missing_text) for a_value in self.attributes_values]))),
            'rawData': self.create_alert_body([match]),
        }

        try:
            payload = json.dumps(alerta_payload_dict, cls=DateTimeEncoder)
        except Exception as e:
            raise Exception("Error building Alerta request: %s" % e)
        return payload


class HTTPPostAlerter(Alerter):
    """ Requested elasticsearch indices are sent by HTTP POST. Encoded with JSON. """

    def __init__(self, rule):
        super(HTTPPostAlerter, self).__init__(rule)
        post_url = self.rule.get('http_post_url')
        if isinstance(post_url, str):
            post_url = [post_url]
        self.post_url = post_url
        self.post_proxy = self.rule.get('http_post_proxy')
        self.post_payload = self.rule.get('http_post_payload', {})
        self.post_static_payload = self.rule.get('http_post_static_payload', {})
        self.post_all_values = self.rule.get('http_post_all_values', not self.post_payload)
        self.post_http_headers = self.rule.get('http_post_headers', {})
        self.post_ca_certs = self.rule.get('http_post_ca_certs')
        self.post_ignore_ssl_errors = self.rule.get('http_post_ignore_ssl_errors', False)
        self.timeout = self.rule.get('http_post_timeout', 10)

    def alert(self, matches):
        """ Each match will trigger a POST to the specified endpoint(s). """
        for match in matches:
            payload = match if self.post_all_values else {}
            payload.update(self.post_static_payload)
            for post_key, es_key in list(self.post_payload.items()):
                payload[post_key] = lookup_es_key(match, es_key)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json;charset=utf-8"
            }
            if self.post_ca_certs:
                verify = self.post_ca_certs
            else:
                verify = not self.post_ignore_ssl_errors

            headers.update(self.post_http_headers)
            proxies = {'https': self.post_proxy} if self.post_proxy else None
            for url in self.post_url:
                try:
                    response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                             headers=headers, proxies=proxies, timeout=self.timeout,
                                             verify=verify)
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting HTTP Post alert: %s" % e)
            elastalert_logger.info("HTTP Post alert sent.")

    def get_info(self):
        return {'type': 'http_post',
                'http_post_webhook_url': self.post_url}


class LineNotifyAlerter(Alerter):
    """ Created a Line Notify for each alert """
    required_option = frozenset(["linenotify_access_token"])

    def __init__(self, rule):
        super(LineNotifyAlerter, self).__init__(rule)
        self.linenotify_access_token = self.rule["linenotify_access_token"]

    def alert(self, matches):
        body = self.create_alert_body(matches)
        # post to Line Notify
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer {}".format(self.linenotify_access_token)
        }
        payload = {
            "message": body
        }
        try:
            response = requests.post("https://notify-api.line.me/api/notify", data=payload, headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Line Notify: %s" % e)
        elastalert_logger.info("Alert sent to Line Notify")

    def get_info(self):
        return {"type": "linenotify", "linenotify_access_token": self.linenotify_access_token}


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = set(['hive_connection', 'hive_alert_config'])

    def alert(self, matches):

        connection_details = self.rule['hive_connection']

        for match in matches:
            context = {'rule': self.rule, 'match': match}

            artifacts = []
            for mapping in self.rule.get('hive_observable_data_mapping', []):
                for observable_type, match_data_key in mapping.items():
                    try:
                        match_data_keys = re.findall(r'\{match\[([^\]]*)\]', match_data_key)
                        rule_data_keys = re.findall(r'\{rule\[([^\]]*)\]', match_data_key)
                        data_keys = match_data_keys + rule_data_keys
                        context_keys = list(context['match'].keys()) + list(context['rule'].keys())
                        if all([True if k in context_keys else False for k in data_keys]):
                            artifact = {'tlp': 2, 'tags': [], 'message': None, 'dataType': observable_type,
                                        'data': match_data_key.format(**context)}
                            artifacts.append(artifact)
                    except KeyError:
                        raise KeyError('\nformat string\n{}\nmatch data\n{}'.format(match_data_key, context))

            alert_config = {
                'artifacts': artifacts,
                'caseTemplate': None,
                'customFields': {},
                'date': int(time.time()) * 1000,
                'description': self.create_alert_body(matches),
                'sourceRef': str(uuid.uuid4())[0:6],
                'title': '{rule[index]}_{rule[name]}'.format(**context),
            }
            alert_config.update(self.rule.get('hive_alert_config', {}))
            custom_fields = {}
            for alert_config_field, alert_config_value in alert_config.items():
                if alert_config_field == 'customFields':
                    n = 0
                    for cf_key, cf_value in alert_config_value.items():
                        cf = {'order': n, cf_value['type']: cf_value['value'].format(**context)}
                        n += 1
                        custom_fields[cf_key] = cf
                elif isinstance(alert_config_value, str):
                    alert_value = alert_config_value.format(**context)
                    if alert_config_field in ['severity', 'tlp']:
                        alert_value = int(alert_value)
                    alert_config[alert_config_field] = alert_value
                elif isinstance(alert_config_value, (list, tuple)):
                    formatted_list = []
                    for element in alert_config_value:
                        try:
                            formatted_list.append(element.format(**context))
                        except (AttributeError, KeyError, IndexError):
                            formatted_list.append(element)
                    alert_config[alert_config_field] = formatted_list
            if custom_fields:
                alert_config['customFields'] = custom_fields

            alert_body = json.dumps(alert_config, indent=4, sort_keys=True)
            req = '{}:{}/api/alert'.format(connection_details['hive_host'], connection_details['hive_port'])
            headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(connection_details.get('hive_apikey', ''))}
            proxies = connection_details.get('hive_proxies', {'http': '', 'https': ''})
            verify = connection_details.get('hive_verify', False)
            response = requests.post(req, headers=headers, data=alert_body, proxies=proxies, verify=verify)

            if response.status_code != 201:
                raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }


class DiscordAlerter(Alerter):

    required_options = frozenset(['discord_webhook_url'])

    def __init__(self, rule):
        super(DiscordAlerter, self).__init__(rule)
        self.discord_webhook_url = self.rule['discord_webhook_url']
        self.discord_emoji_title = self.rule.get('discord_emoji_title', ':warning:')
        self.discord_proxy = self.rule.get('discord_proxy', None)
        self.discord_proxy_login = self.rule.get('discord_proxy_login', None)
        self.discord_proxy_password = self.rule.get('discord_proxy_password', None)
        self.discord_embed_color = self.rule.get('discord_embed_color', 0xffffff)
        self.discord_embed_footer = self.rule.get('discord_embed_footer', None)
        self.discord_embed_icon_url = self.rule.get('discord_embed_icon_url', None)

    def alert(self, matches):
        body = ''
        title = u'%s' % (self.create_title(matches))
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        if len(body) > 2047:
            body = body[0:1950] + '\n *message was cropped according to discord embed description limits!* '

        body += '```'

        proxies = {'https': self.discord_proxy} if self.discord_proxy else None
        auth = HTTPProxyAuth(self.discord_proxy_login, self.discord_proxy_password) if self.discord_proxy_login else None
        headers = {"Content-Type": "application/json"}

        data = {}
        data["content"] = "%s %s %s" % (self.discord_emoji_title, title, self.discord_emoji_title)
        data["embeds"] = []
        embed = {}
        embed["description"] = "%s" % (body)
        embed["color"] = (self.discord_embed_color)

        if self.discord_embed_footer:
            embed["footer"] = {}
            embed["footer"]["text"] = (self.discord_embed_footer) if self.discord_embed_footer else None
            embed["footer"]["icon_url"] = (self.discord_embed_icon_url) if self.discord_embed_icon_url else None
        else:
            None

        data["embeds"].append(embed)

        try:
            response = requests.post(self.discord_webhook_url, data=json.dumps(data), headers=headers, proxies=proxies, auth=auth)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Discord: %s. Details: %s" % (e, "" if e.response is None else e.response.text))

        elastalert_logger.info(
                "Alert sent to the webhook %s" % self.discord_webhook_url)

    def get_info(self):
        return {'type': 'discord',
                'discord_webhook_url': self.discord_webhook_url}


class DingTalkAlerter(Alerter):
    """ Creates a DingTalk room message for each alert """
    required_options = frozenset(['dingtalk_access_token', 'dingtalk_msgtype'])

    def __init__(self, rule):
        super(DingTalkAlerter, self).__init__(rule)
        self.dingtalk_access_token = self.rule.get('dingtalk_access_token')
        self.dingtalk_webhook_url = 'https://oapi.dingtalk.com/robot/send?access_token=%s' % (self.dingtalk_access_token)
        self.dingtalk_msgtype = self.rule.get('dingtalk_msgtype')
        self.dingtalk_single_title = self.rule.get('dingtalk_single_title', 'elastalert')
        self.dingtalk_single_url = self.rule.get('dingtalk_single_url', '')
        self.dingtalk_btn_orientation = self.rule.get('dingtalk_btn_orientation', '')
        self.dingtalk_btns = self.rule.get('dingtalk_btns', [])
        self.dingtalk_proxy = self.rule.get('dingtalk_proxy', None)
        self.dingtalk_proxy_login = self.rule.get('dingtalk_proxy_login', None)
        self.dingtalk_proxy_password = self.rule.get('dingtalk_proxy_pass', None)

    def format_body(self, body):
        return body.encode('utf8')

    def alert(self, matches):
        title = self.create_title(matches)
        body = self.create_alert_body(matches)

        proxies = {'https': self.dingtalk_proxy} if self.dingtalk_proxy else None
        auth = HTTPProxyAuth(self.dingtalk_proxy_login, self.dingtalk_proxy_password) if self.dingtalk_proxy_login else None
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        }

        if self.dingtalk_msgtype == 'text':
            # text
            payload = {
                'msgtype': self.dingtalk_msgtype,
                'text': {
                    'content': body
                }
            }
        elif self.dingtalk_msgtype == 'markdown':
            # markdown
            payload = {
                'msgtype': self.dingtalk_msgtype,
                'markdown': {
                    'title': title,
                    'text': body
                }
            }
        elif self.dingtalk_msgtype == 'single_action_card':
            # singleActionCard
            payload = {
                'msgtype': 'actionCard',
                'actionCard': {
                    'title': title,
                    'text': body,
                    'singleTitle': self.dingtalk_single_title,
                    'singleURL': self.dingtalk_single_url
                }
            }
        elif self.dingtalk_msgtype == 'action_card':
            # actionCard
            payload = {
                'msgtype': 'actionCard',
                'actionCard': {
                    'title': title,
                    'text': body
                }
            }
            if self.dingtalk_btn_orientation != '':
                payload['actionCard']['btnOrientation'] = self.dingtalk_btn_orientation
            if self.dingtalk_btns:
                payload['actionCard']['btns'] = self.dingtalk_btns

        try:
            response = requests.post(self.dingtalk_webhook_url, data=json.dumps(payload,
                                     cls=DateTimeEncoder), headers=headers, proxies=proxies, auth=auth)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to dingtalk: %s" % e)

        elastalert_logger.info("Trigger sent to dingtalk")

    def get_info(self):
        return {
            "type": "dingtalk",
            "dingtalk_webhook_url": self.dingtalk_webhook_url
        }


class ChatworkAlerter(Alerter):
    """ Creates a Chatwork room message for each alert """
    required_options = frozenset(['chatwork_apikey', 'chatwork_room_id'])

    def __init__(self, rule):
        super(ChatworkAlerter, self).__init__(rule)
        self.chatwork_apikey = self.rule.get('chatwork_apikey')
        self.chatwork_room_id = self.rule.get('chatwork_room_id')
        self.url = 'https://api.chatwork.com/v2/rooms/%s/messages' % (self.chatwork_room_id)
        self.chatwork_proxy = self.rule.get('chatwork_proxy', None)
        self.chatwork_proxy_login = self.rule.get('chatwork_proxy_login', None)
        self.chatwork_proxy_pass = self.rule.get('chatwork_proxy_pass', None)

    def alert(self, matches):
        body = self.create_alert_body(matches)

        headers = {'X-ChatWorkToken': self.chatwork_apikey}
        # set https proxy, if it was provided
        proxies = {'https': self.chatwork_proxy} if self.chatwork_proxy else None
        auth = HTTPProxyAuth(self.chatwork_proxy_login, self.chatwork_proxy_pass) if self.chatwork_proxy_login else None
        params = {'body': body}

        try:
            response = requests.post(self.url, params=params, headers=headers, proxies=proxies, auth=auth)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Chattwork: %s. Details: %s" % (e, "" if e.response is None else e.response.text))

        elastalert_logger.info(
            "Alert sent to Chatwork room %s" % self.chatwork_room_id)

    def get_info(self):
        return {
            "type": "chatwork",
            "chatwork_room_id": self.chatwork_room_id
        }


class DatadogAlerter(Alerter):
    ''' Creates a Datadog Event for each alert '''
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
