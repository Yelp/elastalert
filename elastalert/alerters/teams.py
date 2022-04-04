import copy
import json
import requests

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger, lookup_es_key
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
        self.ms_teams_alert_summary = self.rule.get('ms_teams_alert_summary', None)
        self.ms_teams_alert_fixed_width = self.rule.get('ms_teams_alert_fixed_width', False)
        self.ms_teams_theme_color = self.rule.get('ms_teams_theme_color', '')
        self.ms_teams_ca_certs = self.rule.get('ms_teams_ca_certs')
        self.ms_teams_ignore_ssl_errors = self.rule.get('ms_teams_ignore_ssl_errors', False)
        self.ms_teams_alert_facts = self.rule.get('ms_teams_alert_facts', '')
        self.ms_teams_attach_kibana_discover_url = self.rule.get('ms_teams_attach_kibana_discover_url', False)
        self.ms_teams_kibana_discover_title = self.rule.get('ms_teams_kibana_discover_title', 'Discover in Kibana')

    def format_body(self, body):
        if self.ms_teams_alert_fixed_width:
            body = body.replace('`', "'")
            body = "```{0}```".format('```\n\n```'.join(x for x in body.split('\n'))).replace('\n``````', '')
        return body

    def populate_facts(self, matches):
        alert_facts = []
        for arg in self.ms_teams_alert_facts:
            arg = copy.copy(arg)
            matched_value = lookup_es_key(matches[0], arg['value'])
            arg['value'] = matched_value if matched_value is not None else arg['value']
            alert_facts.append(arg)
        return alert_facts

    def alert(self, matches):
        body = self.create_alert_body(matches)
        body = self.format_body(body)

        title = self.create_title(matches)
        summary = title if self.ms_teams_alert_summary is None else self.ms_teams_alert_summary
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
            'summary': summary ,
            'title': title,
            'sections': [{'text': body}],
        }

        if self.ms_teams_alert_facts != '':
            payload['sections'][0]['facts'] = self.populate_facts(matches)

        if self.ms_teams_theme_color != '':
            payload['themeColor'] = self.ms_teams_theme_color

        if self.ms_teams_attach_kibana_discover_url:
            kibana_discover_url = lookup_es_key(matches[0], 'kibana_discover_url')
            if kibana_discover_url:
                payload['potentialAction'] = [
                    {
                        '@type': 'OpenUri',
                        'name': self.ms_teams_kibana_discover_title,
                        'targets': [
                            {
                                'os': 'default',
                                'uri': kibana_discover_url,
                            }
                        ],
                    }
                ]

        for url in self.ms_teams_webhook_url:
            try:
                response = requests.post(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                         headers=headers, proxies=proxies, verify=verify)
                response.raise_for_status()
            except RequestException as e:
                raise EAException("Error posting to MS Teams: %s" % e)
        elastalert_logger.info("Alert sent to MS Teams")

    def get_info(self):
        return {'type': 'ms_teams',
                'ms_teams_webhook_url': self.ms_teams_webhook_url}
