from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import elastalert_logger, lookup_es_key


class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal). """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], match[qk], lookup_es_key(match, self.rule['timestamp_field'])))
            else:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'], lookup_es_key(match, self.rule['timestamp_field'])))
            elastalert_logger.info(str(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}
