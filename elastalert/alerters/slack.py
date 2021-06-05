import copy
import json
import requests
import warnings

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import elastalert_logger, EAException, lookup_es_key
from requests.exceptions import RequestException


class SlackAlerter(Alerter):
    """ Creates a Slack room message for each alert """
    required_options = frozenset(['slack_webhook_url'])

    def __init__(self, rule):
        super(SlackAlerter, self).__init__(rule)
        self.slack_webhook_url = self.rule.get('slack_webhook_url', None)
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
        self.slack_footer = self.rule.get('slack_footer', '')
        self.slack_footer_icon = self.rule.get('slack_footer_icon', '')
        self.slack_image_url = self.rule.get('slack_image_url', '')
        self.slack_thumb_url = self.rule.get('slack_thumb_url', '')
        self.slack_author_name = self.rule.get('slack_author_name', '')
        self.slack_author_link = self.rule.get('slack_author_link', '')
        self.slack_author_icon = self.rule.get('slack_author_icon', '')
        self.slack_msg_pretext = self.rule.get('slack_msg_pretext', '')

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

        if self.slack_footer != '':
            payload['attachments'][0]['footer'] = self.slack_footer

        if self.slack_footer_icon != '':
            payload['attachments'][0]['footer_icon'] = self.slack_footer_icon

        if self.slack_image_url != '':
            payload['attachments'][0]['image_url'] = self.slack_image_url

        if self.slack_thumb_url != '':
            payload['attachments'][0]['thumb_url'] = self.slack_thumb_url

        if self.slack_author_name != '':
            payload['attachments'][0]['author_name'] = self.slack_author_name

        if self.slack_author_link != '':
            payload['attachments'][0]['author_link'] = self.slack_author_link

        if self.slack_author_icon != '':
            payload['attachments'][0]['author_icon'] = self.slack_author_icon

        if self.slack_msg_pretext != '':
            payload['attachments'][0]['pretext'] = self.slack_msg_pretext

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
