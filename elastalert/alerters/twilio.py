from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from elastalert.alerts import Alerter
from elastalert.util import EAException, elastalert_logger


class TwilioAlerter(Alerter):
    required_options = frozenset(['twilio_account_sid', 'twilio_auth_token', 'twilio_to_number'])

    def __init__(self, rule):
        super(TwilioAlerter, self).__init__(rule)
        self.twilio_account_sid = self.rule.get('twilio_account_sid', None)
        self.twilio_auth_token = self.rule.get('twilio_auth_token', None)
        self.twilio_to_number = self.rule.get('twilio_to_number', None)
        self.twilio_from_number = self.rule.get('twilio_from_number', None)
        self.twilio_message_service_sid = self.rule.get('twilio_message_service_sid', None)
        self.twilio_use_copilot = self.rule.get('twilio_use_copilot', False)

    def alert(self, matches):
        client = TwilioClient(self.twilio_account_sid, self.twilio_auth_token)

        try:
            if self.twilio_use_copilot:
                if self.twilio_message_service_sid is None:
                    raise EAException("Twilio Copilot requires the 'twilio_message_service_sid' option")

                client.messages.create(body=self.rule['name'],
                                       to=self.twilio_to_number,
                                       messaging_service_sid=self.twilio_message_service_sid)
            else:
                if self.twilio_from_number is None:
                    raise EAException("Twilio SMS requires the 'twilio_from_number' option")

                client.messages.create(body=self.rule['name'],
                                       to=self.twilio_to_number,
                                       from_=self.twilio_from_number)
        except TwilioRestException as e:
            raise EAException("Error posting to twilio: %s" % e)

        elastalert_logger.info("Trigger sent to Twilio")

    def get_info(self):
        return {'type': 'twilio',
                'twilio_client_name': self.twilio_from_number}
