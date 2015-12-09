# -*- coding: utf-8 -*-
import json
import types
import logging

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
from util import elastalert_logger

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

# from elastalert
def new_elasticsearch(es_conn_conf):
    """ returns an Elasticsearch instance configured using an es_conn_config """
    return Elasticsearch(host=es_conn_conf['es_host'],
                         port=es_conn_conf['es_port'],
                         url_prefix=es_conn_conf['es_url_prefix'],
                         use_ssl=es_conn_conf['use_ssl'],
                         http_auth=es_conn_conf['http_auth'],
                         timeout=es_conn_conf['es_conn_timeout'])

# from elastalert
def build_es_conn_config(conf):
    """ Given a conf dictionary w/ raw config properties 'use_ssl', 'es_host', 'es_port'
    'es_username' and 'es_password', this will return a new dictionary
    with properly initialized values for 'es_host', 'es_port', 'use_ssl' and 'http_auth' which
    will be a basicauth username:password formatted string """
    parsed_conf = {}
    parsed_conf['use_ssl'] = False
    parsed_conf['http_auth'] = None
    parsed_conf['es_username'] = None
    parsed_conf['es_password'] = None
    parsed_conf['es_host'] = conf['es_host']
    parsed_conf['es_port'] = conf['es_port']
    parsed_conf['es_url_prefix'] = ''
    parsed_conf['es_conn_timeout'] = 10

    if 'es_username' in conf:
        parsed_conf['es_username'] = conf['es_username']
        parsed_conf['es_password'] = conf['es_password']

    if parsed_conf['es_username'] and parsed_conf['es_password']:
        parsed_conf['http_auth'] = parsed_conf['es_username'] + ':' + parsed_conf['es_password']

    if 'use_ssl' in conf:
        parsed_conf['use_ssl'] = conf['use_ssl']

    if 'es_conn_timeout' in conf:
        parsed_conf['es_conn_timeout'] = conf['es_conn_timeout']

    if 'es_url_prefix' in conf:
        parsed_conf['es_url_prefix'] = conf['es_url_prefix']

    return parsed_conf


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

        ## # # # # # # # # # # # # # # # # # # # # # # # ##
        # Marc: I am not sure why I need this
        # in ruletypes.py we seem to test check_for_match
        # and it seems to me like it should not reach this
        # function if there are no matches
        if len(matches) < self.rule["num_events"]:
            print "Not enough matches: %d" % (len(matches))
            return
        ## # # # # # # # # # # # # # # # # # # # # # # # ##

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

        es_conn_conf = build_es_conn_config(self.rule)

        env = {
            'rule': self.rule,
            'matches': matches,
            'pipeline': self.pipeline,
            'jira_server': self.pipeline['jira_server'] if (self.pipeline and 'jira_server' in self.pipeline) else None,
            'jira_ticket': self.pipeline['jira_ticket'] if (self.pipeline and 'jira_ticket' in self.pipeline) else None,
            'es': new_elasticsearch(es_conn_conf),
            'json': json,
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

        self.smtp.sendmail(messageRoot['From'], messageRoot['To'], messageRoot.as_string())
        self.smtp.close()

        elastalert_logger.info("Sent email to %s for rule: %s" % (self.rule['email'], self.rule['name']))

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'email-jinja',
                'recipients': self.rule['email']}


