import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter
from elastalert.util import EAException, elastalert_logger


class GoogleChatAlerter(Alerter):
    """ Send a notification via Google Chat webhooks """
    required_options = frozenset(['googlechat_webhook_url'])

    def __init__(self, rule):
        super(GoogleChatAlerter, self).__init__(rule)
        self.googlechat_webhook_url = self.rule.get('googlechat_webhook_url', None)
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
