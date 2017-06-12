# -*- coding: utf-8 -*-
import copy
import datetime
import json
import logging
import subprocess
import sys
import warnings
from email.mime.text import MIMEText
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
from requests.exceptions import RequestException
from staticconf.loader import yaml_loader
from texttable import Texttable
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient
from util import EAException
from util import elastalert_logger
from util import lookup_es_key
from util import pretty_ts


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
        missing = '<MISSING VALUE>'
        alert_text = unicode(self.rule.get('alert_text', ''))
        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i in xrange(len(alert_text_values)):
                if alert_text_values[i] is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in self.rule.get('alert_text_kw').items():
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
        for key, counts in self.match.items():
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = counts.items()

                if not top_events:
                    self.text += 'No events found.\n'
                else:
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
        preformatted_text = u'{{code:json}}{0}{{code}}'.format(json_blob)
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
            for key, value in root.copy().iteritems():
                if type(value) == dict or type(value) == list:
                    self.resolve_rule_references(root[key])
                else:
                    root[key] = self.resolve_rule_reference(value)

    def resolve_rule_reference(self, value):
        strValue = unicode(value)
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
        alert_subject = unicode(self.rule['alert_subject'])

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i in xrange(len(alert_subject_values)):
                if alert_subject_values[i] is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            alert_subject_values = ['<MISSING VALUE>' if val is None else val for val in alert_subject_values]
            return alert_subject.format(*alert_subject_values)

        return alert_subject

    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]
            # Include a count aggregation so that we can see at a glance how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )
            text_table = Texttable()
            text_table.header(summary_table_fields_with_count)
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([unicode(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1
            for keys, count in match_aggregation.iteritems():
                text_table.add_row([key for key in keys] + [count])
            text += text_table.draw() + '\n\n'

        return unicode(text)

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


class StompAlerter(Alerter):
    """ The stomp alerter publishes alerts via stomp to a broker. """
    required_options = frozenset(['stomp_hostname', 'stomp_hostport', 'stomp_login', 'stomp_password'])

    def alert(self, matches):

        alerts = []

        qk = self.rule.get('query_key', None)
        fullmessage = {}
        for match in matches:
            if qk in match:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    '1)Alert for %s, %s at %s:' % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = match[qk]
            else:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    '2)Alert for %s at %s:' % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = lookup_es_key(match, self.rule['timestamp_field'])
            elastalert_logger.info(unicode(BasicMatchString(self.rule, match)))

        fullmessage['alerts'] = alerts
        fullmessage['rule'] = self.rule['name']
        fullmessage['matching'] = unicode(BasicMatchString(self.rule, match))
        fullmessage['alertDate'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fullmessage['body'] = self.create_alert_body(matches)

        self.stomp_hostname = self.rule.get('stomp_hostname', 'localhost')
        self.stomp_hostport = self.rule.get('stomp_hostport', '61613')
        self.stomp_login = self.rule.get('stomp_login', 'admin')
        self.stomp_password = self.rule.get('stomp_password', 'admin')
        self.stomp_destination = self.rule.get('stomp_destination', '/queue/ALERT')

        conn = stomp.Connection([(self.stomp_hostname, self.stomp_hostport)])

        conn.start()
        conn.connect(self.stomp_login, self.stomp_password)
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
        if isinstance(self.rule['email'], basestring):
            self.rule['email'] = [self.rule['email']]
        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('cc')
        if cc and isinstance(cc, basestring):
            self.rule['cc'] = [self.rule['cc']]
        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('bcc')
        if bcc and isinstance(bcc, basestring):
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
            if isinstance(recipient, basestring):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'email_add_domain' in self.rule:
                    to_addr = [name + self.rule['email_add_domain'] for name in to_addr]
        email_msg = MIMEText(body.encode('UTF-8'), _charset='UTF-8')
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
        'jira_bump_in_statuses',
        'jira_bump_not_in_statuses',
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
        self.watchers = self.rule.get('jira_watchers')

        if self.bump_in_statuses and self.bump_not_in_statuses:
            msg = 'Both jira_bump_in_statuses (%s) and jira_bump_not_in_statuses (%s) are set.' % \
                  (','.join(self.bump_in_statuses), ','.join(self.bump_not_in_statuses))
            intersection = list(set(self.bump_in_statuses) & set(self.bump_in_statuses))
            if intersection:
                msg = '%s Both have common statuses of (%s). As such, no tickets will ever be found.' % (
                    msg, ','.join(intersection))
            msg += ' This should be simplified to use only one or the other.'
            logging.warning(msg)

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

        try:
            self.client = JIRA(self.server, basic_auth=(self.user, self.password))
            self.get_priorities()
            self.get_arbitrary_fields()
        except JIRAError as e:
            # JIRAError may contain HTML, pass along only first 1024 chars
            raise EAException("Error connecting to JIRA: %s" % (str(e)[:1024]))

        try:
            if self.priority is not None:
                self.jira_args['priority'] = {'id': self.priority_ids[self.priority]}
        except KeyError:
            logging.error("Priority %s not found. Valid priorities are %s" % (self.priority, self.priority_ids.keys()))

    def get_arbitrary_fields(self):
        # This API returns metadata about all the fields defined on the jira server (built-ins and custom ones)
        fields = self.client.fields()
        for jira_field, value in self.rule.iteritems():
            # If we find a field that is not covered by the set that we are aware of, it means it is either:
            # 1. A built-in supported field in JIRA that we don't have on our radar
            # 2. A custom field that a JIRA admin has configured
            if jira_field.startswith('jira_') and jira_field not in self.known_field_list:
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
        timestamp = pretty_ts(lookup_es_key(match, self.rule['timestamp_field']))
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
                            )), None, sys.exc_info()[2]

        except JIRAError as e:
            raise EAException("Error creating JIRA ticket using jira_args (%s): %s" % (self.jira_args, e))
        elastalert_logger.info("Opened Jira ticket: %s" % (self.issue))

        if self.pipeline is not None:
            self.pipeline['jira_ticket'] = self.issue
            self.pipeline['jira_server'] = self.server

    def create_alert_body(self, matches):
        body = self.description + '\n'
        body += self.get_aggregation_summary_text(matches)
        for match in matches:
            body += unicode(JiraFormattedMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text(self, matches):
        text = super(JiraAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = u'{{noformat}}{0}{{noformat}}'.format(text)
        return text

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

        self.shell = False
        if isinstance(self.rule['command'], basestring):
            self.shell = True
            if '%' in self.rule['command']:
                logging.warning('Warning! You could be vulnerable to shell injection!')
            self.rule['command'] = [self.rule['command']]

        self.new_style_string_format = False
        if 'new_style_string_format' in self.rule and self.rule['new_style_string_format']:
            self.new_style_string_format = True

    def alert(self, matches):
        # Format the command and arguments
        try:
            if self.new_style_string_format:
                command = [command_arg.format(match=matches[0]) for command_arg in self.rule['command']]
            else:
                command = [command_arg % matches[0] for command_arg in self.rule['command']]
            self.last_command = command
        except KeyError as e:
            raise EAException("Error formatting command: %s" % (e))

        # Run command and pipe data
        try:
            subp = subprocess.Popen(command, stdin=subprocess.PIPE, shell=self.shell)

            if self.rule.get('pipe_match_json'):
                match_json = json.dumps(matches, cls=DateTimeEncoder) + '\n'
                stdout, stderr = subp.communicate(input=match_json)
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
        self.aws_access_key_id = self.rule.get('aws_access_key_id')
        self.aws_secret_access_key = self.rule.get('aws_secret_access_key')
        self.aws_region = self.rule.get('aws_region', 'us-east-1')
        self.profile = self.rule.get('boto_profile', None)  # Deprecated
        self.profile = self.rule.get('aws_profile', None)

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])
        return subject

    def alert(self, matches):
        body = self.create_alert_body(matches)

        session = boto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.aws_region,
            profile_name=self.profile
        )
        sns_client = session.client('sns')
        sns_client.publish(
            TopicArn=self.sns_topic_arn,
            Message=body,
            Subject=self.create_title(matches)
        )
        elastalert_logger.info("Sent sns notification to %s" % (self.sns_topic_arn))


class HipChatAlerter(Alerter):
    """ Creates a HipChat room notification for each alert """
    required_options = frozenset(['hipchat_auth_token', 'hipchat_room_id'])

    def __init__(self, rule):
        super(HipChatAlerter, self).__init__(rule)
        self.hipchat_msg_color = self.rule.get('hipchat_msg_color', 'red')
        self.hipchat_message_format = self.rule.get('hipchat_message_format', 'html')
        self.hipchat_auth_token = self.rule['hipchat_auth_token']
        self.hipchat_room_id = self.rule['hipchat_room_id']
        self.hipchat_domain = self.rule.get('hipchat_domain', 'api.hipchat.com')
        self.hipchat_ignore_ssl_errors = self.rule.get('hipchat_ignore_ssl_errors', False)
        self.hipchat_notify = self.rule.get('hipchat_notify', True)
        self.hipchat_from = self.rule.get('hipchat_from', '')
        self.url = 'https://%s/v2/room/%s/notification?auth_token=%s' % (
            self.hipchat_domain, self.hipchat_room_id, self.hipchat_auth_token)
        self.hipchat_proxy = self.rule.get('hipchat_proxy', None)

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # HipChat sends 400 bad request on messages longer than 10000 characters
        if (len(body) > 9999):
            body = body[:9980] + '..(truncated)'

        # Use appropriate line ending for text/html
        if self.hipchat_message_format == 'html':
            body = body.replace('\n', '<br />')

        # Post to HipChat
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.hipchat_proxy} if self.hipchat_proxy else None
        payload = {
            'color': self.hipchat_msg_color,
            'message': body,
            'message_format': self.hipchat_message_format,
            'notify': self.hipchat_notify,
            'from': self.hipchat_from
        }

        try:
            if self.hipchat_ignore_ssl_errors:
                requests.packages.urllib3.disable_warnings()
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers,
                                     verify=not self.hipchat_ignore_ssl_errors,
                                     proxies=proxies)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to HipChat: %s" % e)
        elastalert_logger.info("Alert sent to HipChat room %s" % self.hipchat_room_id)

    def get_info(self):
        return {'type': 'hipchat',
                'hipchat_room_id': self.hipchat_room_id}


class MsTeamsAlerter(Alerter):
    """ Creates a Microsoft Teams Conversation Message for each alert """
    required_options = frozenset(['ms_teams_webhook_url', 'ms_teams_alert_summary'])

    def __init__(self, rule):
        super(MsTeamsAlerter, self).__init__(rule)
        self.ms_teams_webhook_url = self.rule['ms_teams_webhook_url']
        if isinstance(self.ms_teams_webhook_url, basestring):
            self.ms_teams_webhook_url = [self.ms_teams_webhook_url]
        self.ms_teams_proxy = self.rule.get('ms_teams_proxy', None)
        self.ms_teams_alert_summary = self.rule.get('ms_teams_alert_summary', 'ElastAlert Message')
        self.ms_teams_alert_fixed_width = self.rule.get('ms_teams_alert_fixed_width', False)
        self.ms_teams_theme_color = self.rule.get('ms_teams_theme_color', '')

    def format_body(self, body):
        body = body.encode('UTF-8')
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
        if isinstance(self.slack_webhook_url, basestring):
            self.slack_webhook_url = [self.slack_webhook_url]
        self.slack_proxy = self.rule.get('slack_proxy', None)
        self.slack_username_override = self.rule.get('slack_username_override', 'elastalert')
        self.slack_channel_override = self.rule.get('slack_channel_override', '')
        self.slack_emoji_override = self.rule.get('slack_emoji_override', ':ghost:')
        self.slack_icon_url_override = self.rule.get('slack_icon_url_override', '')
        self.slack_msg_color = self.rule.get('slack_msg_color', 'danger')
        self.slack_parse_override = self.rule.get('slack_parse_override', 'none')
        self.slack_text_string = self.rule.get('slack_text_string', '')

    def format_body(self, body):
        # https://api.slack.com/docs/formatting
        body = body.encode('UTF-8')
        body = body.replace('&', '&amp;')
        body = body.replace('<', '&lt;')
        body = body.replace('>', '&gt;')
        return body

    def alert(self, matches):
        body = self.create_alert_body(matches)

        body = self.format_body(body)
        # post to slack
        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.slack_proxy} if self.slack_proxy else None
        payload = {
            'username': self.slack_username_override,
            'channel': self.slack_channel_override,
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
        if self.slack_icon_url_override != '':
            payload['icon_url'] = self.slack_icon_url_override
        else:
            payload['icon_emoji'] = self.slack_emoji_override

        for url in self.slack_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
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
        self.pagerduty_incident_key = self.rule.get('pagerduty_incident_key', '')
        self.pagerduty_incident_key_args = self.rule.get('pagerduty_incident_key_args', None)
        self.pagerduty_proxy = self.rule.get('pagerduty_proxy', None)
        self.url = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # post to pagerduty
        headers = {'content-type': 'application/json'}
        payload = {
            'service_key': self.pagerduty_service_key,
            'description': self.rule['name'],
            'event_type': 'trigger',
            'incident_key': self.get_incident_key(matches),
            'client': self.pagerduty_client_name,
            'details': {
                "information": body.encode('UTF-8'),
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
        elastalert_logger.info("Trigger sent to PagerDuty")

    def get_incident_key(self, matches):
        if self.pagerduty_incident_key_args:
            incident_key_values = [lookup_es_key(matches[0], arg) for arg in self.pagerduty_incident_key_args]

            # Populate values with rule level properties too
            for i in range(len(incident_key_values)):
                if incident_key_values[i] is None:
                    key_value = self.rule.get(self.pagerduty_incident_key_args[i])
                    if key_value:
                        incident_key_values[i] = key_value

            incident_key_values = ['<MISSING VALUE>' if val is None else val for val in incident_key_values]
            return self.pagerduty_incident_key.format(*incident_key_values)
        else:
            return self.pagerduty_incident_key

    def get_info(self):
        return {'type': 'pagerduty',
                'pagerduty_client_name': self.pagerduty_client_name}


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
        except:
            raise EAException("Error posting to Exotel"), None, sys.exc_info()[2]
        elastalert_logger.info("Trigger sent to Exotel")

    def get_info(self):
        return {'type': 'exotel', 'exotel_account': self.exotel_account_sid}


class TwilioAlerter(Alerter):
    required_options = frozenset(['twilio_accout_sid', 'twilio_auth_token', 'twilio_to_number', 'twilio_from_number'])

    def __init__(self, rule):
        super(TwilioAlerter, self).__init__(rule)
        self.twilio_accout_sid = self.rule['twilio_accout_sid']
        self.twilio_auth_token = self.rule['twilio_auth_token']
        self.twilio_to_number = self.rule['twilio_to_number']
        self.twilio_from_number = self.rule['twilio_from_number']

    def alert(self, matches):
        client = TwilioClient(self.twilio_accout_sid, self.twilio_auth_token)

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

    def alert(self, matches):
        body = u'⚠ *%s* ⚠ ```\n' % (self.create_title(matches))
        for match in matches:
            body += unicode(BasicMatchString(self.rule, match))
            # Separate text of aggregated alerts with dashes
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        body += u' ```'

        headers = {'content-type': 'application/json'}
        # set https proxy, if it was provided
        proxies = {'https': self.telegram_proxy} if self.telegram_proxy else None
        payload = {
            'chat_id': self.telegram_room_id,
            'text': body,
            'parse_mode': 'markdown',
            'disable_web_page_preview': True
        }

        try:
            response = requests.post(self.url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to Telegram: %s" % e)

        elastalert_logger.info(
            "Alert sent to Telegram room %s" % self.telegram_room_id)

    def get_info(self):
        return {'type': 'telegram',
                'telegram_room_id': self.telegram_room_id}


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


class SimplePostAlerter(Alerter):
    def __init__(self, rule):
        super(SimplePostAlerter, self).__init__(rule)
        simple_webhook_url = self.rule.get('simple_webhook_url')
        if isinstance(simple_webhook_url, basestring):
            simple_webhook_url = [simple_webhook_url]
        self.simple_webhook_url = simple_webhook_url
        self.simple_proxy = self.rule.get('simple_proxy')

    def alert(self, matches):
        payload = {
            'rule': self.rule['name'],
            'matches': matches
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8"
        }
        proxies = {'https': self.simple_proxy} if self.simple_proxy else None
        for url in self.simple_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder), headers=headers, proxies=proxies)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting simple alert: %s" % e)
        elastalert_logger.info("Simple alert sent")

    def get_info(self):
        return {'type': 'simple',
                'simple_webhook_url': self.simple_webhook_url}
