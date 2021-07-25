import os

from elastalert.alerts import Alerter
from elastalert.util import elastalert_logger, lookup_es_key, EAException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formatdate
from socket import error
from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException


class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.assets_dir = self.rule.get('assets_dir', '/tmp')
        self.images_dictionary = dict(zip(self.rule.get('email_image_keys', []),  self.rule.get('email_image_values', [])))
        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        self.smtp_key_file = self.rule.get('smtp_key_file')
        self.smtp_cert_file = self.rule.get('smtp_cert_file')
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], str):
            self.rule['email'] = [self.rule['email']]
        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('cc')
        if cc and isinstance(cc, str):
            self.rule['cc'] = [self.rule['cc']]
        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('bcc')
        if bcc and isinstance(bcc, str):
            self.rule['bcc'] = [self.rule['bcc']]
        add_suffix = self.rule.get('email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # Add Jira ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJira ticket: %s' % (url)

        to_addr = self.rule['email']
        if 'email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['email_from_field'])
            if isinstance(recipient, str):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'email_add_domain' in self.rule:
                    to_addr = [name + self.rule['email_add_domain'] for name in to_addr]
        if self.rule.get('email_format') == 'html':
            # email_msg = MIMEText(body, 'html', _charset='UTF-8') # old way
            email_msg = MIMEMultipart()
            msgText = MIMEText(body, 'html', _charset='UTF-8')
            email_msg.attach(msgText)   # Added, and edited the previous line

            for image_key in self.images_dictionary:
                fp = open(os.path.join(self.assets_dir, self.images_dictionary[image_key]), 'rb')
                img = MIMEImage(fp.read())
                fp.close()
                img.add_header('Content-ID', '<{}>'.format(image_key))
                email_msg.attach(img)
        else:
            email_msg = MIMEText(body, _charset='UTF-8')
        email_msg['Subject'] = self.create_title(matches)
        email_msg['To'] = ', '.join(to_addr)
        email_msg['From'] = self.from_addr
        email_msg['Reply-To'] = self.rule.get('email_reply_to', email_msg['To'])
        email_msg['Date'] = formatdate()
        if self.rule.get('cc'):
            email_msg['CC'] = ','.join(self.rule['cc'])
            to_addr = to_addr + self.rule['cc']
        if self.rule.get('bcc'):
            to_addr = to_addr + self.rule['bcc']

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
                else:
                    # default port : 465
                    self.smtp = SMTP_SSL(self.smtp_host, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    # default port : 25
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls(keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.quit()

        elastalert_logger.info("Sent email to %s" % (to_addr))

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'email',
                'recipients': self.rule['email']}
