import json
import warnings

import requests
from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerts import Alerter, BasicMatchString, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class TelegramAlerter(Alerter):
    """ Send a Telegram message via bot api for each alert """
    required_options = frozenset(['telegram_bot_token', 'telegram_room_id'])

    def __init__(self, rule):
        super(TelegramAlerter, self).__init__(rule)
        self.telegram_bot_token = self.rule.get('telegram_bot_token', None)
        self.telegram_room_id = self.rule.get('telegram_room_id', None)
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
