import warnings

import requests
from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger


class ChatworkAlerter(Alerter):
    """ Creates a Chatwork room message for each alert """
    required_options = frozenset(['chatwork_apikey', 'chatwork_room_id'])

    def __init__(self, rule):
        super(ChatworkAlerter, self).__init__(rule)
        self.chatwork_apikey = self.rule.get('chatwork_apikey', None)
        self.chatwork_room_id = self.rule.get('chatwork_room_id', None)
        self.url = 'https://api.chatwork.com/v2/rooms/%s/messages' % (self.chatwork_room_id)
        self.chatwork_proxy = self.rule.get('chatwork_proxy', None)
        self.chatwork_proxy_login = self.rule.get('chatwork_proxy_login', None)
        self.chatwork_proxy_pass = self.rule.get('chatwork_proxy_pass', None)

    def alert(self, matches):
        body = ''
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        if len(body) > 2047:
            body = body[0:1950] + '\n *message was cropped according to chatwork embed description limits!*'
        headers = {'X-ChatWorkToken': self.chatwork_apikey}
        # set https proxy, if it was provided
        proxies = {'https': self.chatwork_proxy} if self.chatwork_proxy else None
        auth = HTTPProxyAuth(self.chatwork_proxy_login, self.chatwork_proxy_pass) if self.chatwork_proxy_login else None
        params = {'body': body}

        try:
            response = requests.post(self.url, params=params, headers=headers, proxies=proxies, auth=auth)
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
