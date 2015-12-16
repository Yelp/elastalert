import elastalert
import datetime
import json
import logging
import types
import util

import requests
from alerts import Alerter
from jinja2 import Environment
from requests.exceptions import RequestException
from util import EAException
from util import elastalert_logger, pretty_ts, ts_to_dt

class HipChatv1Alerter(Alerter):
    """ Creates a HipChat room notification for each alert """
    required_options = frozenset(['hipchat_auth_token', 'hipchat_room'])

    def __init__(self, rule):
        super(HipChatv1Alerter, self).__init__(rule)
        self.hipchat_auth_token = self.rule['hipchat_auth_token']
        self.hipchat_room_id = self.rule['hipchat_room']
        self.hipchat_matches_template = self.rule['hipchat_matches_template']
        self.hipchat_description = self.rule.get('hipchat_description')
        self.hipchat_from = self.rule.get('hipchat_from', 'Elastalert')
        self.url = 'https://api.hipchat.com/v1/rooms/message?auth_token=%s' % (self.hipchat_auth_token)
        self.es_conn_conf = elastalert.ElastAlerter.build_es_conn_config(self.rule)

    def alert(self, matches):
        env = {
                'rule': self.rule,
                'matches': matches,
                'pipeline': self.pipeline,
                'es': elastalert.ElastAlerter.new_elasticsearch(self.es_conn_conf),
                'json': json,
                'util': util,
                'datetime': datetime,
              }

        if not self.hipchat_description:
            html = """Got %s matches for rule %s: <p>""" % (len(matches), self.rule['name'])
        else:
            html = Environment().from_string(self.hipchat_description).render(**env)

        body = Environment().from_string(self.hipchat_matches_template).render(**env)

        # post to hipchat
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        payload = {
            'room_id': self.hipchat_room_id,
            'from': self.hipchat_from,
            'color': 'yellow',
            'message': "<p>".join([html, body]),
            'notify': True,
        }

        try:
            response = requests.post(self.url, data=payload, headers=headers)
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to hipchat: %s" % e)
        elastalert_logger.info("Alert sent to HipChat room %s for rule %s" % (self.hipchat_room_id, self.rule['name']))

    def get_info(self):
        return {'type': 'hipchat',
                'hipchat_room_id': self.hipchat_room_id}


