import json
import warnings

import requests
from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class DingTalkAlerter(Alerter):
    """ Creates a DingTalk room message for each alert """
    required_options = frozenset(['dingtalk_access_token'])

    def __init__(self, rule):
        super(DingTalkAlerter, self).__init__(rule)
        self.dingtalk_access_token = self.rule.get('dingtalk_access_token', None)
        self.dingtalk_webhook_url = 'https://oapi.dingtalk.com/robot/send?access_token=%s' % (self.dingtalk_access_token)
        self.dingtalk_msgtype = self.rule.get('dingtalk_msgtype', 'text')
        self.dingtalk_single_title = self.rule.get('dingtalk_single_title', 'elastalert')
        self.dingtalk_single_url = self.rule.get('dingtalk_single_url', '')
        self.dingtalk_btn_orientation = self.rule.get('dingtalk_btn_orientation', '')
        self.dingtalk_btns = self.rule.get('dingtalk_btns', [])
        self.dingtalk_proxy = self.rule.get('dingtalk_proxy', None)
        self.dingtalk_proxy_login = self.rule.get('dingtalk_proxy_login', None)
        self.dingtalk_proxy_password = self.rule.get('dingtalk_proxy_pass', None)

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
        if self.dingtalk_msgtype == 'markdown':
            # markdown
            payload = {
                'msgtype': self.dingtalk_msgtype,
                'markdown': {
                    'title': title,
                    'text': body
                }
            }
        if self.dingtalk_msgtype == 'single_action_card':
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
        if self.dingtalk_msgtype == 'action_card':
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
