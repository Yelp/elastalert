# -*- coding: utf-8 -*-
import copy
import datetime
import json
import os
import subprocess
import sys
import time
import uuid
import warnings

import boto3
import requests
import stomp
from exotel import Exotel
from requests.auth import HTTPProxyAuth
from requests.exceptions import RequestException
from texttable import Texttable
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from .util import EAException
from .util import elastalert_logger
from .util import lookup_es_key
from .util import resolve_string
from .util import ts_to_dt
from .yaml import read_yaml


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
        account_conf = read_yaml(account_file_path)
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
    required_options = frozenset(['twilio_account_sid', 'twilio_auth_token', 'twilio_to_number'])

    def __init__(self, rule):
        super(TwilioAlerter, self).__init__(rule)
        self.twilio_account_sid = self.rule['twilio_account_sid']
        self.twilio_auth_token = self.rule['twilio_auth_token']
        self.twilio_to_number = self.rule['twilio_to_number']
        self.twilio_from_number = self.rule.get('twilio_from_number')
        self.twilio_message_service_sid = self.rule.get('twilio_message_service_sid')
        self.twilio_use_copilot = self.rule.get('twilio_use_copilot', False)

    def alert(self, matches):
        client = TwilioClient(self.twilio_account_sid, self.twilio_auth_token)

        try:
            if self.twilio_use_copilot:
                if self.twilio_message_service_sid is None:
                    raise EAException("Twilio Copilot requires the 'twilio_message_service_sid' option")

                client.messages.create(body=self.rule['name'],
                                       to=self.twilio_to_number,
                                       messaging_service_sid=self.twilio_message_service_sid)
            else:
                if self.twilio_from_number is None:
                    raise EAException("Twilio SMS requires the 'twilio_from_number' option")

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
    required_options = frozenset(['http_post_url'])

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

    def lookup_field(self, match: dict, field_name: str, default):
        """Populates a field with values depending on the contents of the Elastalert match
        provided to it.

        Uses a similar algorithm to that implemented to populate the `alert_text_args`.
        First checks any fields found in the match provided, then any fields defined in
        the rule, finally returning the default value provided if no value can be found.
        """
        field_value = lookup_es_key(match, field_name)
        if field_value is None:
            field_value = self.rule.get(field_name, default)

        return field_value

    # Iterate through the matches, building up a list of observables
    def load_observable_artifacts(self, match: dict):
        artifacts = []
        for mapping in self.rule.get('hive_observable_data_mapping', []):
            for observable_type, mapping_key in mapping.items():
                data = self.lookup_field(match, mapping_key, '')
                artifact = {'tlp': 2,
                            'tags': [],
                            'message': None,
                            'dataType': observable_type,
                            'data': data}
                artifacts.append(artifact)

        return artifacts

    def load_custom_fields(self, custom_fields_raw: list, match: dict):
        custom_fields = {}
        position = 0

        for field in custom_fields_raw:
            if (isinstance(field['value'], str)):
                value = self.lookup_field(match, field['value'], field['value'])
            else:
                value = field['value']

            custom_fields[field['name']] = {'order': position, field['type']: value}
            position += 1

        return custom_fields

    def load_tags(self, tag_names: list, match: dict):
        tag_values = set()
        for tag in tag_names:
            tag_value = self.lookup_field(match, tag, tag)
            if isinstance(tag_value, list):
                for sub_tag in tag_value:
                    tag_values.add(sub_tag)
            else:
                tag_values.add(tag_value)

        return tag_values

    def alert(self, matches):
        # Build TheHive alert object, starting with some defaults, updating with any
        # user-specified config
        alert_config = {
            'artifacts': [],
            'customFields': {},
            'date': int(time.time()) * 1000,
            'description': self.create_alert_body(matches),
            'sourceRef': str(uuid.uuid4())[0:6],
            'tags': [],
            'title': self.create_title(matches),
        }
        alert_config.update(self.rule.get('hive_alert_config', {}))

        # Iterate through each match found, populating the alert tags and observables as required
        tags = set()
        artifacts = []
        for match in matches:
            artifacts = artifacts + self.load_observable_artifacts(match)
            tags.update(self.load_tags(alert_config['tags'], match))

        alert_config['artifacts'] = artifacts
        alert_config['tags'] = list(tags)

        # Populate the customFields
        alert_config['customFields'] = self.load_custom_fields(alert_config['customFields'],
                                                               matches[0])

        # POST the alert to TheHive
        connection_details = self.rule['hive_connection']

        api_key = connection_details.get('hive_apikey', '')
        hive_host = connection_details.get('hive_host', 'http://localhost')
        hive_port = connection_details.get('hive_port', 9000)
        proxies = connection_details.get('hive_proxies', {'http': '', 'https': ''})
        verify = connection_details.get('hive_verify', False)

        alert_body = json.dumps(alert_config, indent=4, sort_keys=True)
        req = f'{hive_host}:{hive_port}/api/alert'
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'Bearer {api_key}'}

        try:
            response = requests.post(req,
                                     headers=headers,
                                     data=alert_body,
                                     proxies=proxies,
                                     verify=verify)
            response.raise_for_status()
        except RequestException as e:
            raise EAException(f"Error posting to TheHive: {e}")

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }


class DiscordAlerter(Alerter):
    """ Created a Discord for each alert """
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


class SesAlerter(Alerter):
    """ Sends an email alert using AWS SES """
    required_options = frozenset(['ses_email', 'ses_from_addr'])

    def __init__(self, *args):
        super(SesAlerter, self).__init__(*args)

        self.aws_access_key_id = self.rule.get('ses_aws_access_key_id')
        self.aws_secret_access_key = self.rule.get('ses_aws_secret_access_key')
        self.aws_region = self.rule.get('ses_aws_region', 'us-east-1')
        self.aws_profile = self.rule.get('ses_aws_profile', '')

        self.from_addr = self.rule.get('ses_from_addr')

        # Convert email to a list if it isn't already
        if isinstance(self.rule['ses_email'], str):
            self.rule['ses_email'] = [self.rule['ses_email']]

        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('ses_cc')
        if cc and isinstance(cc, str):
            self.rule['ses_cc'] = [self.rule['ses_cc']]

        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('ses_bcc')
        if bcc and isinstance(bcc, str):
            self.rule['ses_bcc'] = [self.rule['ses_bcc']]

        # If there is a email_reply_to then also convert it to a list if it isn't
        reply_to = self.rule.get('ses_email_reply_to')
        if reply_to and isinstance(reply_to, str):
            self.rule['ses_email_reply_to'] = [self.rule['ses_email_reply_to']]

        add_suffix = self.rule.get('ses_email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['ses_email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        body = self.create_alert_body(matches)

        to_addr = self.rule['ses_email']
        if 'ses_email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['ses_email_from_field'])
            if isinstance(recipient, str):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'ses_email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['ses_email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'ses_email_add_domain' in self.rule:
                    to_addr = [name + self.rule['ses_email_add_domain'] for name in to_addr]

        if self.aws_profile != '':
            session = boto3.Session(profile_name=self.aws_profile)
        else:
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.aws_region
            )

        client = session.client('ses')
        try:
            client.send_email(
                Source=self.from_addr,
                Destination={
                    'ToAddresses': to_addr,
                    'CcAddresses': self.rule.get('ses_cc', []),
                    'BccAddresses': self.rule.get('ses_bcc', [])
                },
                Message={
                    'Subject': {
                        'Charset': 'UTF-8',
                        'Data': self.create_title(matches),
                    },
                    'Body': {
                        'Text': {
                            'Charset': 'UTF-8',
                            'Data': body,
                        }
                    }
                },
                ReplyToAddresses=self.rule.get('ses_email_reply_to', []))
        except Exception as e:
            raise EAException("Error sending ses: %s" % (e,))

        elastalert_logger.info("Sent ses to %s" % (to_addr,))

    def create_default_title(self, matches):
        subject = 'ElastAlert 2: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'ses',
                'recipients': self.rule['ses_email']}
