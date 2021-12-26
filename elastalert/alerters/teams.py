import json
import requests

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger
from requests.exceptions import RequestException


class MsTeamsAlerter(Alerter):
    """ Creates a Microsoft Teams Conversation Message for each alert """
    required_options = frozenset(['ms_teams_webhook_url'])

    def __init__(self, rule):
        super(MsTeamsAlerter, self).__init__(rule)
        self.ms_teams_webhook_url = self.rule.get('ms_teams_webhook_url', None)
        if isinstance(self.ms_teams_webhook_url, str):
            self.ms_teams_webhook_url = [self.ms_teams_webhook_url]
        self.ms_teams_proxy = self.rule.get('ms_teams_proxy', None)
        self.ms_teams_alert_summary = self.rule.get('ms_teams_alert_summary', 'ElastAlert Message')
        self.ms_teams_alert_fixed_width = self.rule.get('ms_teams_alert_fixed_width', False)
        self.ms_teams_theme_color = self.rule.get('ms_teams_theme_color', '')
        self.ms_teams_ca_certs = self.rule.get('ms_teams_ca_certs')
        self.ms_teams_ignore_ssl_errors = self.rule.get('ms_teams_ignore_ssl_errors', False)

    def format_body(self, body):
        if self.ms_teams_alert_fixed_width:
            body = body.replace('`', "'")
            body = "```{0}```".format('```\n\n```'.join(x for x in body.split('\n'))).replace('\n``````', '')
        return body

    def alert(self, matches):
        body = self.create_alert_body(matches)

        body = self.format_body(body)
        # post to Teams
        headers = {'content-type': 'application/json'}
    
        if self.ms_teams_ca_certs:
            verify = self.ms_teams_ca_certs
        else:
            verify = not self.ms_teams_ignore_ssl_errors
        if self.ms_teams_ignore_ssl_errors:
            requests.packages.urllib3.disable_warnings()

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
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                         headers=headers, proxies=proxies, verify=verify)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to ms teams: %s" % e)
        elastalert_logger.info("Alert sent to MS Teams")

    def get_info(self):
        return {'type': 'ms_teams',
                'ms_teams_webhook_url': self.ms_teams_webhook_url}
