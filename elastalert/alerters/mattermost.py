import copy
import json
import requests
import warnings

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import elastalert_logger, lookup_es_key, EAException
from requests import RequestException


class MattermostAlerter(Alerter):
    """ Creates a Mattermsot post for each alert """
    required_options = frozenset(['mattermost_webhook_url'])

    def __init__(self, rule):
        super(MattermostAlerter, self).__init__(rule)

        # HTTP config
        self.mattermost_webhook_url = self.rule.get('mattermost_webhook_url', None)
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
        self.mattermost_image_url = self.rule.get('mattermost_image_url', '')
        self.mattermost_title = self.rule.get('mattermost_title', '')
        self.mattermost_title_link = self.rule.get('mattermost_title_link', '')
        self.mattermost_footer = self.rule.get('mattermost_footer', '')
        self.mattermost_footer_icon = self.rule.get('mattermost_footer_icon', '')
        self.mattermost_image_url = self.rule.get('mattermost_image_url', '')
        self.mattermost_thumb_url = self.rule.get('mattermost_thumb_url', '')
        self.mattermost_author_name = self.rule.get('mattermost_author_name', '')
        self.mattermost_author_link = self.rule.get('mattermost_author_link', '')
        self.mattermost_author_icon = self.rule.get('mattermost_author_icon', '')
        self.mattermost_attach_kibana_discover_url = self.rule.get('mattermost_attach_kibana_discover_url', False)
        self.mattermost_kibana_discover_color = self.rule.get('mattermost_kibana_discover_color', '#ec4b98')
        self.mattermost_kibana_discover_title = self.rule.get('mattermost_kibana_discover_title', 'Discover in Kibana')

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
            'username': self.mattermost_username_override,
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

        if self.mattermost_channel_override != '':
            payload['channel'] = self.mattermost_channel_override

        if self.mattermost_title != '':
            payload['attachments'][0]['title'] = self.mattermost_title

        if self.mattermost_title_link != '':
            payload['attachments'][0]['title_link'] = self.mattermost_title_link

        if self.mattermost_footer != '':
            payload['attachments'][0]['footer'] = self.mattermost_footer

        if self.mattermost_footer_icon != '':
            payload['attachments'][0]['footer_icon'] = self.mattermost_footer_icon

        if self.mattermost_image_url != '':
            payload['attachments'][0]['image_url'] = self.mattermost_image_url

        if self.mattermost_thumb_url != '':
            payload['attachments'][0]['thumb_url'] = self.mattermost_thumb_url

        if self.mattermost_author_name != '':
            payload['attachments'][0]['author_name'] = self.mattermost_author_name

        if self.mattermost_author_link != '':
            payload['attachments'][0]['author_link'] = self.mattermost_author_link

        if self.mattermost_author_icon != '':
            payload['attachments'][0]['author_icon'] = self.mattermost_author_icon

        if self.mattermost_attach_kibana_discover_url:
            kibana_discover_url = lookup_es_key(matches[0], 'kibana_discover_url')
            if kibana_discover_url:
                payload['attachments'].append({
                    'color': self.mattermost_kibana_discover_color,
                    'title': self.mattermost_kibana_discover_title,
                    'title_link': kibana_discover_url
                })

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
