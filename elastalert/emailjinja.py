# -*- coding: utf-8 -*-
import datetime
import elastalert
import json
import logging
import types
import util

from jinja2 import Environment, FileSystemLoader

from email.utils import COMMASPACE
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException
from socket import error

from alerts import BasicMatchString, Alerter
from util import EAException
from util import elastalert_logger, pretty_ts, ts_to_dt

from elasticsearch.client import Elasticsearch
from elasticsearch.exceptions import ElasticsearchException



#--- Helpers ----------------------------------------------
def _convert_to_strings(list_of_strs):
    if isinstance(list_of_strs, (list, tuple)):
        result = COMMASPACE.join(list_of_strs)
    else:
        result = list_of_strs
    return _encode_str(result)

def _encode_str(s):
    if type(s) == types.UnicodeType:
        return s.encode('utf8')
    return s

# Supports:
#   email*
#   email_reply_to
#   num_events
#   smtp_host
#   smtp_port
#   smtp_ssl
#   smtp_auth_file
#   from_addr
#   template_text_content
#   template_text_file
#   template_html_content
#   template_html_file
#
# (* required)

class EmailJinjaAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailJinjaAlerter, self).__init__(*args)

        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], str):
            self.rule['email'] = [self.rule['email']]

    def alert(self, matches):

        if False:
            print "*********** STACK ***********"
            import traceback
            traceback.print_stack()
            print "*********** MATCHES ***********"
            print matches
            print "*********** RULES ************"
            print self.rule

        if 'template_text_content' in self.rule:
            text = self.rule['template_text_content']
        elif 'template_text_file' in self.rule:
            with open(self.rule['template_text_file'], 'r') as f:
                text = f.read()
        else:
            text = '{{ matches|length }} items found'

        if 'template_html_content' in self.rule:
            html = self.rule['template_html_content']
        elif 'template_html_file' in self.rule:
            with open(self.rule['template_html_file'], 'r') as f:
                html = f.read()
        else:
            html = '{{ matches|length }} items found'

        es_conn_conf = elastalert.ElastAlerter.build_es_conn_config(self.rule)

        env = {
            'rule': self.rule,
            'matches': matches,
            'pipeline': self.pipeline,
            'jira_server': self.pipeline['jira_server'] if (self.pipeline and 'jira_server' in self.pipeline) else None,
            'jira_ticket': self.pipeline['jira_ticket'] if (self.pipeline and 'jira_ticket' in self.pipeline) else None,
            'es': elastalert.ElastAlerter.new_elasticsearch(es_conn_conf),
            'json': json,
            'util': util,
            'datetime': datetime,
        }

        text = Environment().from_string(text).render(**env)
        html = Environment().from_string(html).render(**env)

        messageRoot = MIMEMultipart('related')
        messageRoot['Subject'] = _encode_str(self.create_title(matches))
        messageRoot['From']    = _encode_str(self.from_addr)
        messageRoot['To']      = _convert_to_strings(self.rule['email'])

        if self.rule.get('email_reply_to'):
            messageRoot['Reply-To'] = _convert_to_strings(self.rule.get('email_reply_to'))

        messageRoot.preamble = 'This is a multi-part message in MIME format.'

        # Encapsulate the plain and HTML versions of the message body in an
        # 'alternative' part, so message agents can decide which they want to display.
        msgAlternative = MIMEMultipart('alternative')
        msgAlternative.attach(MIMEText(_encode_str(text), 'plain'))
        msgAlternative.attach(MIMEText(_encode_str(html), 'html'))
        messageRoot.attach(msgAlternative)

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP_SSL(self.smtp_host)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls()
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))

        self.smtp.sendmail(messageRoot['From'], self.rule['email'], messageRoot.as_string())
        self.smtp.close()

        elastalert_logger.info("Sent email to %s for rule: %s" % (self.rule['email'], self.rule['name']))

    def create_default_title(self, matches):
        subject = '%s: %d matches found - %s' % \
                      (self.rule['name'], len(matches),
                      pretty_ts(ts_to_dt(self.pipeline['alert_time'])))

        return subject

    def create_custom_title(self, matches):
        # Assume rule['alert_subject'] to be a jinja templated string. See Alerter.create_title()
        subject = self.rule['alert_subject'] 

        es_conn_conf = elastalert.ElastAlerter.build_es_conn_config(self.rule)
        env = {
            'rule': self.rule,
            'matches': matches,
            'pipeline': self.pipeline,
            'jira_server': self.pipeline['jira_server'] if (self.pipeline and 'jira_server' in self.pipeline) else None,
            'jira_ticket': self.pipeline['jira_ticket'] if (self.pipeline and 'jira_ticket' in self.pipeline) else None,
            'es': elastalert.ElastAlerter.new_elasticsearch(es_conn_conf),
            'util': util,
            'datetime': datetime,
        }

        return Environment().from_string(subject).render(**env)

    def get_info(self):
        return {'type': 'email-jinja',
                'recipients': self.rule['email']}

