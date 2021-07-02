import json
import warnings

import requests
from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger


class DiscordAlerter(Alerter):
    """ Created a Discord for each alert """
    required_options = frozenset(['discord_webhook_url'])

    def __init__(self, rule):
        super(DiscordAlerter, self).__init__(rule)
        self.discord_webhook_url = self.rule.get('discord_webhook_url', None)
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
            body = body[0:1950] + '\n *message was cropped according to discord embed description limits!*'

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
