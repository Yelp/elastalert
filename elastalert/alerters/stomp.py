import datetime
import json
import time

import stomp

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import lookup_es_key, elastalert_logger, EAException


class StompAlerter(Alerter):
    """ The stomp alerter publishes alerts via stomp to a broker. """
    required_options = frozenset(
        ['stomp_hostname', 'stomp_hostport', 'stomp_login', 'stomp_password'])

    def alert(self, matches):
        alerts = []

        qk = self.rule.get('query_key', None)

        fullmessage = {}
        for match in matches:
            if qk is not None:
                resmatch = lookup_es_key(match, qk)
            else:
                resmatch = None

            if resmatch is not None:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], resmatch, lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    'Alert for %s, %s at %s:' % (self.rule['name'], resmatch, lookup_es_key(
                        match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = resmatch
            else:
                elastalert_logger.info('Rule %s generated an alert at %s:' % (
                    self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
                alerts.append(
                    'Rule %s generated an alert at %s:' % (self.rule['name'], lookup_es_key(
                        match, self.rule['timestamp_field']))
                )
                fullmessage['match'] = lookup_es_key(
                    match, self.rule['timestamp_field'])
            elastalert_logger.info(str(BasicMatchString(self.rule, match)))

        fullmessage['alerts'] = alerts
        fullmessage['rule'] = self.rule['name']
        fullmessage['rule_file'] = self.rule['rule_file']

        fullmessage['matching'] = str(BasicMatchString(self.rule, match))
        fullmessage['alertDate'] = datetime.datetime.now(
        ).strftime("%Y-%m-%d %H:%M:%S")
        fullmessage['body'] = self.create_alert_body(matches)

        fullmessage['matches'] = matches

        self.stomp_hostname = self.rule.get('stomp_hostname', 'localhost')
        self.stomp_hostport = self.rule.get('stomp_hostport', '61613')
        self.stomp_login = self.rule.get('stomp_login', 'admin')
        self.stomp_password = self.rule.get('stomp_password', 'admin')
        self.stomp_destination = self.rule.get(
            'stomp_destination', '/queue/ALERT')
        self.stomp_ssl = self.rule.get('stomp_ssl', False)

        try:
            conn = stomp.Connection([(self.stomp_hostname, self.stomp_hostport)], use_ssl=self.stomp_ssl)

            conn.connect(self.stomp_login, self.stomp_password)
            # Ensures that the CONNECTED frame is received otherwise, the disconnect call will fail.
            time.sleep(1)
            conn.send(self.stomp_destination, json.dumps(fullmessage))
            conn.disconnect()
        except Exception as e:
            raise EAException("Error posting to Stomp: %s" % e)
        elastalert_logger.info("Alert sent to Stomp")

    def get_info(self):
        return {'type': 'stomp'}
