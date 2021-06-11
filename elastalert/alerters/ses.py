import boto3

from elastalert.alerts import Alerter
from elastalert.util import lookup_es_key, EAException, elastalert_logger


class SesAlerter(Alerter):
    """ Sends an email alert using AWS SES """
    required_options = frozenset(['ses_email', 'ses_from_addr'])

    def __init__(self, *args):
        super(SesAlerter, self).__init__(*args)

        self.aws_access_key_id = self.rule.get('ses_aws_access_key_id')
        self.aws_secret_access_key = self.rule.get('ses_aws_secret_access_key')
        self.aws_region = self.rule.get('ses_aws_region', 'us-east-1')
        self.aws_profile = self.rule.get('ses_aws_profile', '')

        self.email = self.rule.get('ses_email', None)
        self.from_addr = self.rule.get('ses_from_addr', None)

        # Convert email to a list if it isn't already
        if isinstance(self.email, str):
            self.email = [self.email]

        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('ses_cc')
        if cc and isinstance(cc, str):
            self.rule['ses_cc'] = [self.rule['ses_cc']]

        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('ses_bcc')
        if bcc and isinstance(bcc, str):
            self.rule['ses_bcc'] = [self.rule['ses_bcc']]

        # If there is a email_reply_to then also convert it to a list if it isn't
        reply_to = self.rule.get('ses_email_reply_to')
        if reply_to and isinstance(reply_to, str):
            self.rule['ses_email_reply_to'] = [self.rule['ses_email_reply_to']]

        add_suffix = self.rule.get('ses_email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['ses_email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        body = self.create_alert_body(matches)

        to_addr = self.email
        if 'ses_email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['ses_email_from_field'])
            if isinstance(recipient, str):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'ses_email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['ses_email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'ses_email_add_domain' in self.rule:
                    to_addr = [name + self.rule['ses_email_add_domain'] for name in to_addr]

        try:
            if self.aws_profile != '':
                session = boto3.Session(profile_name=self.aws_profile)
            else:
                session = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    region_name=self.aws_region
                )

            client = session.client('ses')

            client.send_email(
                Source=self.from_addr,
                Destination={
                    'ToAddresses': to_addr,
                    'CcAddresses': self.rule.get('ses_cc', []),
                    'BccAddresses': self.rule.get('ses_bcc', [])
                },
                Message={
                    'Subject': {
                        'Charset': 'UTF-8',
                        'Data': self.create_title(matches),
                    },
                    'Body': {
                        'Text': {
                            'Charset': 'UTF-8',
                            'Data': body,
                        }
                    }
                },
                ReplyToAddresses=self.rule.get('ses_email_reply_to', []))
        except Exception as e:
            raise EAException("Error sending Amazon SES: %s" % e)

        elastalert_logger.info("Sent Amazon SES to %s" % (to_addr,))

    def create_default_title(self, matches):
        subject = 'ElastAlert 2: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'ses',
                'recipients': self.email}
