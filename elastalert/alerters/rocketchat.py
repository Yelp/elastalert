# -*- coding: utf-8 -*-
import copy
import json
import requests
from requests.exceptions import RequestException
import warnings

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger, lookup_es_key


class RocketChatAlerter(Alerter):
    """ Creates a RocketChat notification for each alert """
    required_options = set(['rocket_chat_webhook_url'])

    def __init__(self, rule):
        super(RocketChatAlerter, self).__init__(rule)
        self.rocket_chat_webhook_url = self.rule.get('rocket_chat_webhook_url', None)
        if isinstance(self.rocket_chat_webhook_url, str):
            self.rocket_chat_webhook_url = [self.rocket_chat_webhook_url]
        self.rocket_chat_proxy = self.rule.get('rocket_chat_proxy', None)

        self.rocket_chat_username_override = self.rule.get('rocket_chat_username_override', 'elastalert2')
        self.rocket_chat_channel_override = self.rule.get('rocket_chat_channel_override', '')
        if isinstance(self.rocket_chat_channel_override, str):
            self.rocket_chat_channel_override = [self.rocket_chat_channel_override]
        self.rocket_chat_emoji_override = self.rule.get('rocket_chat_emoji_override', ':ghost:')
        self.rocket_chat_msg_color = self.rule.get('rocket_chat_msg_color', 'danger')
        self.rocket_chat_text_string = self.rule.get('rocket_chat_text_string', '')
        self.rocket_chat_alert_fields = self.rule.get('rocket_chat_alert_fields', '')
        self.rocket_chat_attach_kibana_discover_url = self.rule.get('rocket_chat_attach_kibana_discover_url', False)
        self.rocket_chat_kibana_discover_color = self.rule.get('rocket_chat_kibana_discover_color', '#ec4b98')
        self.rocket_chat_kibana_discover_title = self.rule.get('rocket_chat_kibana_discover_title', 'Discover in Kibana')
        self.rocket_chat_ignore_ssl_errors = self.rule.get('rocket_chat_ignore_ssl_errors', False)
        self.rocket_chat_timeout = self.rule.get('rocket_chat_timeout', 10)
        self.rocket_chat_ca_certs = self.rule.get('rocket_chat_ca_certs')

    def format_body(self, body):
        return body

    def get_aggregation_summary_text__maximum_width(self):
        width = super(RocketChatAlerter, self).get_aggregation_summary_text__maximum_width()

        # Reduced maximum width for prettier Slack display.
        return min(width, 75)

    def get_aggregation_summary_text(self, matches):
        text = super(RocketChatAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '```\n{0}```\n'.format(text)
        return text

    def populate_fields(self, matches):
        alert_fields = []
        for arg in self.rocket_chat_alert_fields:
            arg = copy.copy(arg)
            arg['value'] = lookup_es_key(matches[0], arg['value'])
            alert_fields.append(arg)
        return alert_fields

    def alert(self, matches):
        body = self.create_alert_body(matches)
        body = self.format_body(body)
        headers = {'content-type': 'application/json'}
        proxies = {'https': self.rocket_chat_proxy} if self.rocket_chat_proxy else None
        payload = {
            'username': self.rocket_chat_username_override,
            'text': self.rocket_chat_text_string,
            'attachments': [
                {
                    'color': self.rocket_chat_msg_color,
                    'title': self.create_title(matches),
                    'text': body,
                    'fields': []
                }
            ]
        }

        # if we have defined fields, populate noteable fields for the alert
        if self.rocket_chat_alert_fields != '':
            payload['attachments'][0]['fields'] = self.populate_fields(matches)

        if self.rocket_chat_emoji_override != '':
            payload['emoji'] = self.rocket_chat_emoji_override

        if self.rocket_chat_attach_kibana_discover_url:
            kibana_discover_url = lookup_es_key(matches[0], 'kibana_discover_url')
            if kibana_discover_url:
                payload['attachments'].append({
                    'color': self.rocket_chat_kibana_discover_color,
                    'title': self.rocket_chat_kibana_discover_title,
                    'title_link': kibana_discover_url
                })

        for url in self.rocket_chat_webhook_url:
            for channel_override in self.rocket_chat_channel_override:
                try:
                    if self.rocket_chat_ca_certs:
                        verify = self.rocket_chat_ca_certs
                    else:
                        verify = not self.rocket_chat_ignore_ssl_errors
                    if self.rocket_chat_ignore_ssl_errors:
                        requests.packages.urllib3.disable_warnings()
                    payload['channel'] = channel_override
                    response = requests.post(
                        url, data=json.dumps(payload, cls=DateTimeEncoder),
                        headers=headers,
                        verify=verify,
                        proxies=proxies,
                        timeout=self.rocket_chat_timeout)
                    warnings.resetwarnings()
                    response.raise_for_status()
                except RequestException as e:
                    raise EAException("Error posting to Rocket.Chat: %s" % e)
            elastalert_logger.info("Alert sent to Rocket.Chat")

    def get_info(self):
        return {'type': 'rocketchat',
                'rocket_chat_username_override': self.rocket_chat_username_override,
                'rocket_chat_webhook_url': self.rocket_chat_webhook_url}
