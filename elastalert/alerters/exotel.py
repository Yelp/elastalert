import sys

from exotel import Exotel
from requests import RequestException

from elastalert.alerts import Alerter
from elastalert.util import EAException, elastalert_logger


class ExotelAlerter(Alerter):
    """ Sends an exotel alert """
    required_options = frozenset(['exotel_account_sid', 'exotel_auth_token', 'exotel_to_number', 'exotel_from_number'])

    def __init__(self, rule):
        super(ExotelAlerter, self).__init__(rule)
        self.exotel_account_sid = self.rule.get('exotel_account_sid', None)
        self.exotel_auth_token = self.rule.get('exotel_auth_token', None)
        self.exotel_to_number = self.rule.get('exotel_to_number', None)
        self.exotel_from_number = self.rule.get('exotel_from_number', None)
        self.sms_body = self.rule.get('exotel_message_body', '')

    def alert(self, matches):
        client = Exotel(self.exotel_account_sid, self.exotel_auth_token)

        try:
            message_body = self.rule['name'] + self.sms_body
            response = client.sms(self.rule['exotel_from_number'], self.rule['exotel_to_number'], message_body)
            if response != 200:
                raise EAException("Error posting to Exotel, response code is %s" % response)
        except RequestException:
            raise EAException("Error posting to Exotel").with_traceback(sys.exc_info()[2])
        elastalert_logger.info("Trigger sent to Exotel")

    def get_info(self):
        return {'type': 'exotel', 'exotel_account': self.exotel_account_sid}
