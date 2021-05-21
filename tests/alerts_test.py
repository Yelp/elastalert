# -*- coding: utf-8 -*-
import base64
import datetime
import json
import subprocess
import re
import uuid

import mock
import pytest
from jira.exceptions import JIRAError
from requests.auth import HTTPProxyAuth
from requests.exceptions import RequestException

from elastalert.alerts import AlertaAlerter
from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.alerts import ChatworkAlerter
from elastalert.alerts import CommandAlerter
from elastalert.alerts import DatadogAlerter
from elastalert.alerts import DingTalkAlerter
from elastalert.alerts import DiscordAlerter
from elastalert.alerts import GitterAlerter
from elastalert.alerts import GoogleChatAlerter
from elastalert.alerts import HiveAlerter
from elastalert.alerts import HTTPPostAlerter
from elastalert.alerts import LineNotifyAlerter
from elastalert.alerts import PagerTreeAlerter
from elastalert.alerts import ServiceNowAlerter
from elastalert.alerts import TelegramAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.alerters.jira import JiraAlerter
from elastalert.alerters.jira import JiraFormattedMatchString
from elastalert.alerters.email import EmailAlerter
from elastalert.alerters.mattermost import MattermostAlerter
from elastalert.alerters.opsgenie import OpsGenieAlerter
from elastalert.alerters.pagerduty import PagerDutyAlerter
from elastalert.alerters.slack import SlackAlerter
from elastalert.alerters.teams import MsTeamsAlerter
from elastalert.alerters.zabbix import ZabbixAlerter
from elastalert.alerts import VictorOpsAlerter
from elastalert.util import ts_add
from elastalert.util import ts_now
from elastalert.util import EAException


class mock_rule:
    def get_match_str(self, event):
        return str(event)


def test_basic_match_string(ea):
    ea.rules[0]['top_count_keys'] = ['username']
    match = {'@timestamp': '1918-01-17', 'field': 'value', 'top_events_username': {'bob': 10, 'mallory': 5}}
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'anytest' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'bob: 10' in alert_text
    assert 'field: value' in alert_text

    # Non serializable objects don't cause errors
    match['non-serializable'] = {open: 10}
    alert_text = str(BasicMatchString(ea.rules[0], match))

    # unicode objects dont cause errors
    match['snowman'] = '☃'
    alert_text = str(BasicMatchString(ea.rules[0], match))

    # Pretty printed objects
    match.pop('non-serializable')
    match['object'] = {'this': {'that': [1, 2, "3"]}}
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert '"this": {\n        "that": [\n            1,\n            2,\n            "3"\n        ]\n    }' in alert_text

    ea.rules[0]['alert_text'] = 'custom text'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'anytest' not in alert_text

    ea.rules[0]['alert_text_type'] = 'alert_text_only'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' not in alert_text
    assert 'username' not in alert_text
    assert 'field: value' not in alert_text

    ea.rules[0]['alert_text_type'] = 'exclude_fields'
    alert_text = str(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'field: value' not in alert_text


def test_jira_formatted_match_string(ea):
    match = {'foo': {'bar': ['one', 2, 'three']}, 'top_events_poof': 'phew'}
    alert_text = str(JiraFormattedMatchString(ea.rules[0], match))
    tab = 4 * ' '
    expected_alert_text_snippet = '{code}{\n' \
        + tab + '"foo": {\n' \
        + 2 * tab + '"bar": [\n' \
        + 3 * tab + '"one",\n' \
        + 3 * tab + '2,\n' \
        + 3 * tab + '"three"\n' \
        + 2 * tab + ']\n' \
        + tab + '}\n' \
        + '}{code}'
    assert expected_alert_text_snippet in alert_text


def test_email():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': '☃'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_from_field():
    rule = {'name': 'test alert', 'email': ['testing@test.test'], 'email_add_domain': 'example.com',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_from_field': 'data.user', 'owner': 'owner_value'}
    # Found, without @
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, with @
    rule['email_add_domain'] = '@example.com'
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, list
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': ['qlo', 'foo']}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com', 'foo@example.com']

    # Not found
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'foo': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']

    # Found, wrong type
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 17}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']


def test_email_with_unicode_strings():
    rule = {'name': 'test alert', 'email': 'testing@test.test', 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': '☃'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_with_auth():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt',
            'rule_file': '/tmp/foo.yaml'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cert_key():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt',
            'smtp_cert_file': 'dummy/cert.crt', 'smtp_key_file': 'dummy/client.key', 'rule_file': '/tmp/foo.yaml'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile='dummy/cert.crt', keyfile='dummy/client.key'),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'cc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_bcc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'bcc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' not in body
        assert 'From: testfrom@test.test' in body


def test_email_with_cc_and_bcc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'cc': ['test1@test.com', 'test2@test.com'], 'bcc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test',
                            'test1@test.com',
                            'test2@test.com',
                            'tester@testing.testing'
                        ],
                        mock.ANY
        ),
            mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: test1@test.com,test2@test.com' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_args():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'alert_subject': 'Test alert for {0} {1}',
        'alert_subject_args': ['test_term', 'test.term'],
        'alert_text': 'Test alert for {0} and {1} {2}',
        'alert_text_args': ['test_arg1', 'test_arg2', 'test.arg3'],
        'alert_missing_value': '<CUSTOM MISSING VALUE>'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'test_arg1': 'testing', 'test': {'term': ':)', 'arg3': '☃'}}])
        expected = [mock.call('localhost', 25),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]
        # Extract the MIME encoded message body
        body_text = base64.b64decode(body.split('\n\n')[-1][:-1]).decode('utf-8')

        assert 'testing' in body_text
        assert '<CUSTOM MISSING VALUE>' in body_text
        assert '☃' in body_text

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value :)' in body


def test_email_query_key_in_subject():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'],
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'query_key': 'username'}
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'username': 'werbenjagermanjensen'}])

        body = mock_smtp.mock_calls[4][1][2]
        lines = body.split('\n')
        found_subject = False
        for line in lines:
            if line.startswith('Subject'):
                assert 'werbenjagermanjensen' in line
                found_subject = True
        assert found_subject


def test_opsgenie_basic():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['lytics'], 'type': mock_rule()}
    with mock.patch('requests.post') as mock_post:

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])
        print(("mock_post: {0}".format(mock_post._mock_call_args_list)))
        mcal = mock_post._mock_call_args_list
        print(('mcal: {0}'.format(mcal[0])))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'username': 'lytics', 'type': 'user'}]
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


def test_opsgenie_frequency():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['lytics'], 'type': mock_rule(),
            'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
            'alert': 'opsgenie'}
    with mock.patch('requests.post') as mock_post:

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])

        assert alert.get_info()['recipients'] == rule['opsgenie_recipients']

        print(("mock_post: {0}".format(mock_post._mock_call_args_list)))
        mcal = mock_post._mock_call_args_list
        print(('mcal: {0}'.format(mcal[0])))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'username': 'lytics', 'type': 'user'}]
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


def test_opsgenie_alert_routing():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['{RECEIPIENT_PREFIX}'], 'opsgenie_recipients_args': {'RECEIPIENT_PREFIX': 'recipient'},
            'type': mock_rule(),
            'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
            'alert': 'opsgenie',
            'opsgenie_teams': ['{TEAM_PREFIX}-Team'], 'opsgenie_teams_args': {'TEAM_PREFIX': 'team'}}
    with mock.patch('requests.post'):

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00', 'team': "Test", 'recipient': "lytics"}])

        assert alert.get_info()['teams'] == ['Test-Team']
        assert alert.get_info()['recipients'] == ['lytics']


def test_opsgenie_default_alert_routing():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['{RECEIPIENT_PREFIX}'], 'opsgenie_recipients_args': {'RECEIPIENT_PREFIX': 'recipient'},
            'type': mock_rule(),
            'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
            'alert': 'opsgenie',
            'opsgenie_teams': ['{TEAM_PREFIX}-Team'],
            'opsgenie_default_receipients': ["devops@test.com"], 'opsgenie_default_teams': ["Test"]
            }
    with mock.patch('requests.post'):

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00', 'team': "Test"}])

        assert alert.get_info()['teams'] == ['{TEAM_PREFIX}-Team']
        assert alert.get_info()['recipients'] == ['devops@test.com']


def test_opsgenie_details_with_constant_value():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {'Foo': 'Bar'}
    }
    match = {
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Foo': 'Bar'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_details_with_field():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {'Foo': {'field': 'message'}}
    }
    match = {
        'message': 'Bar',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Foo': 'Bar'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_details_with_nested_field():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {'Foo': {'field': 'nested.field'}}
    }
    match = {
        'nested': {
            'field': 'Bar'
        },
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Foo': 'Bar'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_details_with_non_string_field():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Age': {'field': 'age'},
            'Message': {'field': 'message'}
        }
    }
    match = {
        'age': 10,
        'message': {
            'format': 'The cow goes %s!',
            'arg0': 'moo'
        }
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {
            'Age': '10',
            'Message': "{'format': 'The cow goes %s!', 'arg0': 'moo'}"
        },
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_details_with_missing_field():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        }
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_details_with_environment_variable_replacement(environ):
    environ.update({
        'TEST_VAR': 'Bar'
    })
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {'Foo': '$TEST_VAR'}
    }
    match = {
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Foo': 'Bar'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_tags():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_tags': ['test1', 'test2']
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['test1', 'test2', 'ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_message():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_message': 'test1'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'test1',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_alias():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_alias': 'test1'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies',
        'alias': 'test1'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_subject():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_subject': 'test1'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'test1',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_subject_args():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_subject': 'test',
        'opsgenie_subject_args': ['Testing', 'message']
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'test',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_p1():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'P1'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': 'P1',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_p2():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'P2'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': 'P2',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_p3():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'P3'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': 'P3',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_p4():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'P4'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': 'P4',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_p5():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'P5'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': 'P5',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_priority_none():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': 'abc'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies=None
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_proxy():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_proxy': 'https://proxy.url'
    }
    match = {
        'message': 'Testing',
        '@timestamp': '2014-10-31T00:00:00'
    }
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        'https://api.opsgenie.com/v2/alerts',
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'GenieKey ogkey'
        },
        json=mock.ANY,
        proxies={'https': 'https://proxy.url'}
    )

    expected_json = {
        'description': BasicMatchString(rule, match).__str__(),
        'details': {'Message': 'Testing'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_jira():
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'jira_project': 'testproject',
        'jira_priority': 0,
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_label': 'testlabel',
        'jira_component': 'testcomponent',
        'jira_description': description_txt,
        'jira_watchers': ['testwatcher1', 'testwatcher2'],
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }

    mock_priority = mock.Mock(id='5')

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []
        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected = [
        mock.call('jiraserver', basic_auth=('jirauser', 'jirapassword')),
        mock.call().priorities(),
        mock.call().fields(),
        mock.call().create_issue(
            issuetype={'name': 'testtype'},
            priority={'id': '5'},
            project={'key': 'testproject'},
            labels=['testlabel'],
            components=[{'name': 'testcomponent'}],
            description=mock.ANY,
            summary='Issue test_value occurred at 2014-10-31T00:00:00',
        ),
        mock.call().add_watcher(mock.ANY, 'testwatcher1'),
        mock.call().add_watcher(mock.ANY, 'testwatcher2'),
    ]

    # We don't care about additional calls to mock_jira, such as __str__
    assert mock_jira.mock_calls[:6] == expected
    assert mock_jira.mock_calls[3][2]['description'].startswith(description_txt)

    # Search called if jira_bump_tickets
    rule['jira_bump_tickets'] = True
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = []
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected.insert(3, mock.call().search_issues(mock.ANY))
    assert mock_jira.mock_calls == expected

    # Remove a field if jira_ignore_in_title set
    rule['jira_ignore_in_title'] = 'test_term'
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = []
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    assert 'test_value' not in mock_jira.mock_calls[3][1][0]

    # Issue is still created if search_issues throws an exception
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.side_effect = JIRAError
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    assert mock_jira.mock_calls == expected

    # Only bump after 3d of inactivity
    rule['jira_bump_after_inactivity'] = 3
    mock_issue = mock.Mock()

    # Check ticket is bumped if it is updated 4 days ago
    mock_issue.fields.updated = str(ts_now() - datetime.timedelta(days=4))
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = [mock_issue]
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        # Check add_comment is called
        assert len(mock_jira.mock_calls) == 5
        assert '().add_comment' == mock_jira.mock_calls[4][0]

    # Check ticket is bumped is not bumped if ticket is updated right now
    mock_issue.fields.updated = str(ts_now())
    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = [mock_issue]
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        # Only 4 calls for mock_jira since add_comment is not called
        assert len(mock_jira.mock_calls) == 4

        # Test match resolved values
        rule = {
            'name': 'test alert',
            'jira_account_file': 'jirafile',
            'type': mock_rule(),
            'owner': 'the_owner',
            'jira_project': 'testproject',
            'jira_issuetype': 'testtype',
            'jira_server': 'jiraserver',
            'jira_label': 'testlabel',
            'jira_component': 'testcomponent',
            'jira_description': "DESC",
            'jira_watchers': ['testwatcher1', 'testwatcher2'],
            'timestamp_field': '@timestamp',
            'jira_affected_user': "#gmail.the_user",
            'rule_file': '/tmp/foo.yaml'
        }
        mock_issue = mock.Mock()
        mock_issue.fields.updated = str(ts_now() - datetime.timedelta(days=4))
        mock_fields = [
            {'name': 'affected user', 'id': 'affected_user_id', 'schema': {'type': 'string'}}
        ]
        with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
                mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
            mock_jira.return_value = mock.Mock()
            mock_jira.return_value.search_issues.return_value = [mock_issue]
            mock_jira.return_value.fields.return_value = mock_fields
            mock_jira.return_value.priorities.return_value = [mock_priority]
            alert = JiraAlerter(rule)
            alert.alert([{'gmail.the_user': 'jdoe', '@timestamp': '2014-10-31T00:00:00'}])
            assert mock_jira.mock_calls[4][2]['affected_user_id'] == "jdoe"


def test_jira_arbitrary_field_support():
    description_txt = "Description stuff goes here like a runbook link."
    rule = {
        'name': 'test alert',
        'jira_account_file': 'jirafile',
        'type': mock_rule(),
        'owner': 'the_owner',
        'jira_project': 'testproject',
        'jira_issuetype': 'testtype',
        'jira_server': 'jiraserver',
        'jira_label': 'testlabel',
        'jira_component': 'testcomponent',
        'jira_description': description_txt,
        'jira_watchers': ['testwatcher1', 'testwatcher2'],
        'jira_arbitrary_reference_string_field': '$owner$',
        'jira_arbitrary_string_field': 'arbitrary_string_value',
        'jira_arbitrary_string_array_field': ['arbitrary_string_value1', 'arbitrary_string_value2'],
        'jira_arbitrary_string_array_field_provided_as_single_value': 'arbitrary_string_value_in_array_field',
        'jira_arbitrary_number_field': 1,
        'jira_arbitrary_number_array_field': [2, 3],
        'jira_arbitrary_number_array_field_provided_as_single_value': 1,
        'jira_arbitrary_complex_field': 'arbitrary_complex_value',
        'jira_arbitrary_complex_array_field': ['arbitrary_complex_value1', 'arbitrary_complex_value2'],
        'jira_arbitrary_complex_array_field_provided_as_single_value': 'arbitrary_complex_value_in_array_field',
        'timestamp_field': '@timestamp',
        'alert_subject': 'Issue {0} occurred at {1}',
        'alert_subject_args': ['test_term', '@timestamp'],
        'rule_file': '/tmp/foo.yaml'
    }

    mock_priority = mock.MagicMock(id='5')

    mock_fields = [
        {'name': 'arbitrary reference string field', 'id': 'arbitrary_reference_string_field', 'schema': {'type': 'string'}},
        {'name': 'arbitrary string field', 'id': 'arbitrary_string_field', 'schema': {'type': 'string'}},
        {'name': 'arbitrary string array field', 'id': 'arbitrary_string_array_field', 'schema': {'type': 'array', 'items': 'string'}},
        {
            'name': 'arbitrary string array field provided as single value',
            'id': 'arbitrary_string_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'string'}
        },
        {'name': 'arbitrary number field', 'id': 'arbitrary_number_field', 'schema': {'type': 'number'}},
        {'name': 'arbitrary number array field', 'id': 'arbitrary_number_array_field', 'schema': {'type': 'array', 'items': 'number'}},
        {
            'name': 'arbitrary number array field provided as single value',
            'id': 'arbitrary_number_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'number'}
        },
        {'name': 'arbitrary complex field', 'id': 'arbitrary_complex_field', 'schema': {'type': 'ArbitraryType'}},
        {
            'name': 'arbitrary complex array field',
            'id': 'arbitrary_complex_array_field',
            'schema': {'type': 'array', 'items': 'ArbitraryType'}
        },
        {
            'name': 'arbitrary complex array field provided as single value',
            'id': 'arbitrary_complex_array_field_provided_as_single_value',
            'schema': {'type': 'array', 'items': 'ArbitraryType'}
        },
    ]

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields
        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    expected = [
        mock.call('jiraserver', basic_auth=('jirauser', 'jirapassword')),
        mock.call().priorities(),
        mock.call().fields(),
        mock.call().create_issue(
            issuetype={'name': 'testtype'},
            project={'key': 'testproject'},
            labels=['testlabel'],
            components=[{'name': 'testcomponent'}],
            description=mock.ANY,
            summary='Issue test_value occurred at 2014-10-31T00:00:00',
            arbitrary_reference_string_field='the_owner',
            arbitrary_string_field='arbitrary_string_value',
            arbitrary_string_array_field=['arbitrary_string_value1', 'arbitrary_string_value2'],
            arbitrary_string_array_field_provided_as_single_value=['arbitrary_string_value_in_array_field'],
            arbitrary_number_field=1,
            arbitrary_number_array_field=[2, 3],
            arbitrary_number_array_field_provided_as_single_value=[1],
            arbitrary_complex_field={'name': 'arbitrary_complex_value'},
            arbitrary_complex_array_field=[{'name': 'arbitrary_complex_value1'}, {'name': 'arbitrary_complex_value2'}],
            arbitrary_complex_array_field_provided_as_single_value=[{'name': 'arbitrary_complex_value_in_array_field'}],
        ),
        mock.call().add_watcher(mock.ANY, 'testwatcher1'),
        mock.call().add_watcher(mock.ANY, 'testwatcher2'),
    ]

    # We don't care about additional calls to mock_jira, such as __str__
    assert mock_jira.mock_calls[:6] == expected
    assert mock_jira.mock_calls[3][2]['description'].startswith(description_txt)

    # Reference an arbitrary string field that is not defined on the JIRA server
    rule['jira_nonexistent_field'] = 'nonexistent field value'

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields

        with pytest.raises(Exception) as exception:
            alert = JiraAlerter(rule)
            alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        assert "Could not find a definition for the jira field 'nonexistent field'" in str(exception)

    del rule['jira_nonexistent_field']

    # Reference a watcher that does not exist
    rule['jira_watchers'] = 'invalid_watcher'

    with mock.patch('elastalert.alerters.jira.JIRA') as mock_jira, \
            mock.patch('elastalert.alerts.read_yaml') as mock_open:
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = mock_fields

        # Cause add_watcher to raise, which most likely means that the user did not exist
        mock_jira.return_value.add_watcher.side_effect = Exception()

        with pytest.raises(Exception) as exception:
            alert = JiraAlerter(rule)
            alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
        assert "Exception encountered when trying to add 'invalid_watcher' as a watcher. Does the user exist?" in str(exception)


def test_kibana(ea):
    rule = {'filter': [{'query': {'query_string': {'query': 'xy:z'}}}],
            'name': 'Test rule!',
            'es_host': 'test.testing',
            'es_port': 12345,
            'timeframe': datetime.timedelta(hours=1),
            'index': 'logstash-test',
            'include': ['@timestamp'],
            'timestamp_field': '@timestamp'}
    match = {'@timestamp': '2014-10-10T00:00:00'}
    with mock.patch("elastalert.elastalert.elasticsearch_client") as mock_es:
        mock_create = mock.Mock(return_value={'_id': 'ABCDEFGH'})
        mock_es_inst = mock.Mock()
        mock_es_inst.index = mock_create
        mock_es_inst.host = 'test.testing'
        mock_es_inst.port = 12345
        mock_es.return_value = mock_es_inst
        link = ea.generate_kibana_db(rule, match)

    assert 'http://test.testing:12345/_plugin/kibana/#/dashboard/temp/ABCDEFGH' == link

    # Name and index
    dashboard = json.loads(mock_create.call_args_list[0][1]['body']['dashboard'])
    assert dashboard['index']['default'] == 'logstash-test'
    assert 'Test rule!' in dashboard['title']

    # Filters and time range
    filters = dashboard['services']['filter']['list']
    assert 'xy:z' in filters['1']['query']
    assert filters['1']['type'] == 'querystring'
    time_range = filters['0']
    assert time_range['from'] == ts_add(match['@timestamp'], -rule['timeframe'])
    assert time_range['to'] == ts_add(match['@timestamp'], datetime.timedelta(minutes=10))

    # Included fields active in table
    assert dashboard['rows'][1]['panels'][0]['fields'] == ['@timestamp']


def test_command():
    # Test command as list with a formatted arg
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s']}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz',
             'nested': {'field': 1}}
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)

    # Test command as string with formatted arg (old-style string format)
    rule = {'command': '/bin/test/ --arg %(somefield)s'}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg foobarbaz', stdin=subprocess.PIPE, shell=False)

    # Test command as string without formatted arg (old-style string format)
    rule = {'command': '/bin/test/foo.sh'}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test/foo.sh', stdin=subprocess.PIPE, shell=True)

    # Test command with pipe_match_json
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'pipe_match_json': True}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        mock_subprocess = mock.Mock()
        mock_popen.return_value = mock_subprocess
        mock_subprocess.communicate.return_value = (None, None)
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert mock_subprocess.communicate.called_with(input=json.dumps(match))

    # Test command with pipe_alert_text
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'pipe_alert_text': True, 'type': mock_rule(), 'name': 'Test'}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    alert_text = str(BasicMatchString(rule, match))
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        mock_subprocess = mock.Mock()
        mock_popen.return_value = mock_subprocess
        mock_subprocess.communicate.return_value = (None, None)
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert mock_subprocess.communicate.called_with(input=alert_text.encode())

    # Test command with fail_on_non_zero_exit
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'fail_on_non_zero_exit': True}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    with pytest.raises(Exception) as exception:
        with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
            mock_subprocess = mock.Mock()
            mock_popen.return_value = mock_subprocess
            mock_subprocess.wait.return_value = 1
            alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert "Non-zero exit code while running command" in str(exception)

    # Test OSError
    try:
        rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
                'pipe_alert_text': True, 'type': mock_rule(), 'name': 'Test'}
        alert = CommandAlerter(rule)
        match = {'@timestamp': '2014-01-01T00:00:00',
                 'somefield': 'foobarbaz'}
        alert_text = str(BasicMatchString(rule, match))
        mock_run = mock.MagicMock(side_effect=OSError)
        with mock.patch("elastalert.alerts.subprocess.Popen", mock_run), pytest.raises(OSError) as mock_popen:
            mock_subprocess = mock.Mock()
            mock_popen.return_value = mock_subprocess
            mock_subprocess.communicate.return_value = (None, None)
            alert.alert([match])
    except EAException:
        assert True


def test_ms_teams():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'text': BasicMatchString(rule, match).__str__()
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_ms_teams_uses_color_and_fixed_width_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'ms_teams_alert_fixed_width': True,
        'ms_teams_theme_color': '#124578',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    body = BasicMatchString(rule, match).__str__()
    body = body.replace('`', "'")
    body = "```{0}```".format('```\n\n```'.join(x for x in body.split('\n'))).replace('\n``````', '')
    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'themeColor': '#124578',
        'text': body
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_ms_teams_proxy():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'ms_teams_proxy': 'https://test.proxy.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'text': BasicMatchString(rule, match).__str__()
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': rule['ms_teams_proxy']}
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_ms_teams_ea_exception():
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'ms_teams_webhook_url': 'http://test.webhook.url',
            'ms_teams_alert_summary': 'Alert from ElastAlert',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MsTeamsAlerter(rule)
        match = {
            '@timestamp': '2016-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_slack_uses_custom_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_uses_custom_timeout():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert_subject': 'Cool subject',
        'alert': [],
        'slack_timeout': 20
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=20
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_uses_rule_name_when_custom_title_is_not_provided():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': ['http://please.dontgohere.slack'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none',
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_uses_custom_slack_channel():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': ['http://please.dontgohere.slack'],
        'slack_channel_override': '#test-alert',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '#test-alert',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none',
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_uses_list_of_custom_slack_channel():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': ['http://please.dontgohere.slack'],
        'slack_channel_override': ['#test-alert', '#test-alert2'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data1 = {
        'username': 'elastalert',
        'channel': '#test-alert',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    expected_data2 = {
        'username': 'elastalert',
        'channel': '#test-alert2',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_with(
        rule['slack_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data1 == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data2 == json.loads(mock_post_request.call_args_list[1][1]['data'])


def test_slack_attach_kibana_discover_url_when_generated():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_attach_kibana_discover_url': True,
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'kibana_discover_url': 'http://kibana#discover'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'parse': 'none',
        'text': '',
        'attachments': [
            {
                'color': 'danger',
                'title': 'Test Rule',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            },
            {
                'color': '#ec4b98',
                'title': 'Discover in Kibana',
                'title_link': 'http://kibana#discover'
            }
        ],
        'icon_emoji': ':ghost:',
        'channel': ''
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_slack_attach_kibana_discover_url_when_not_generated():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_attach_kibana_discover_url': True,
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'parse': 'none',
        'text': '',
        'attachments': [
            {
                'color': 'danger',
                'title': 'Test Rule',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'icon_emoji': ':ghost:',
        'channel': ''
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_slack_kibana_discover_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_attach_kibana_discover_url': True,
        'slack_kibana_discover_title': 'Click to discover in Kibana',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'kibana_discover_url': 'http://kibana#discover'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'parse': 'none',
        'text': '',
        'attachments': [
            {
                'color': 'danger',
                'title': 'Test Rule',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            },
            {
                'color': '#ec4b98',
                'title': 'Click to discover in Kibana',
                'title_link': 'http://kibana#discover'
            }
        ],
        'icon_emoji': ':ghost:',
        'channel': ''
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_slack_kibana_discover_color():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_attach_kibana_discover_url': True,
        'slack_kibana_discover_color': 'blue',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'kibana_discover_url': 'http://kibana#discover'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'parse': 'none',
        'text': '',
        'attachments': [
            {
                'color': 'danger',
                'title': 'Test Rule',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            },
            {
                'color': 'blue',
                'title': 'Discover in Kibana',
                'title_link': 'http://kibana#discover'
            }
        ],
        'icon_emoji': ':ghost:',
        'channel': ''
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_slack_ignore_ssl_errors():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_ignore_ssl_errors': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=False,
        timeout=10
    )

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': 'Test Rule',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_proxy():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_proxy': 'http://proxy.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': rule['slack_proxy']},
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_username_override():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'test elastalert',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'test elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_title_link():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_title_link': 'http://slack.title.link',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'title_link': 'http://slack.title.link'
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_title': 'slack title',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': 'slack title',
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_icon_url_override():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_icon_url_override': 'http://slack.icon.url.override',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_url': 'http://slack.icon.url.override',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_msg_color():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_msg_color': 'good',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'good',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_parse_override():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_parse_override': 'full',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': '',
        'parse': 'full'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_text_string():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_text_string': 'text str',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': []
            }
        ],
        'text': 'text str',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_alert_fields():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_alert_fields': [
            {
                'title': 'Host',
                'value': 'somefield',
                'short': 'true'
            },
            {
                'title': 'Sensors',
                'value': '@timestamp',
                'short': 'true'
            }
        ],
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields':
                [
                    {
                        'short': 'true',
                        'title': 'Host',
                        'value': 'foobarbaz'
                    },
                    {
                        'short': 'true',
                        'title': 'Sensors',
                        'value': '2016-01-01T00:00:00'
                    }
                ],
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_ca_certs():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_ca_certs': True,
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_footer():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_footer': 'Elastic Alerts',
        'slack_footer_icon': 'http://footer.icon.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'footer': 'Elastic Alerts',
                'footer_icon': 'http://footer.icon.url'
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_image_url():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_image_url': 'http://image.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'image_url': 'http://image.url',
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_thumb_url():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_thumb_url': 'http://thumb.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'thumb_url': 'http://thumb.url',
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_author_name():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_author_name': 'author name',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'author_name': 'author name',
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_author_link():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_author_link': 'http://author.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'author_link': 'http://author.url',
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_author_icon():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_author_icon': 'http://author.icon',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'author_icon': 'http://author.icon',
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_msg_pretext():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'slack_username_override': 'elastalert',
        'slack_msg_pretext': 'pretext value',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SlackAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert',
        'channel': '',
        'icon_emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'mrkdwn_in': ['text', 'pretext'],
                'fields': [],
                'pretext': 'pretext value'
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(
        rule['slack_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        verify=True,
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_ea_exception():
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'slack_webhook_url': 'http://please.dontgohere.slack',
            'slack_username_override': 'elastalert',
            'slack_msg_pretext': 'pretext value',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = SlackAlerter(rule)
        match = {
            '@timestamp': '2016-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_http_alerter_with_payload():
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_payload': {'posted_name': 'somefield'},
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_with_payload_all_values():
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_payload': {'posted_name': 'somefield'},
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_all_values': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'foobarbaz',
        'name': 'somestaticname',
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_without_payload():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_proxy():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies={'https': 'http://proxy.url'},
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_timeout():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_timeout': 20,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=20,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_headers():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_headers': {'authorization': 'Basic 123dr3234'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'authorization': 'Basic 123dr3234'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_post_ca_certs_true():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_ca_certs': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_post_ca_certs_false():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_ca_certs': False,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_post_ea_exception():
    try:
        rule = {
            'name': 'Test HTTP Post Alerter Without Payload',
            'type': 'any',
            'http_post_url': 'http://test.webhook.url',
            'http_post_static_payload': {'name': 'somestaticname'},
            'http_post_ca_certs': False,
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPostAlerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_pagerduty_alerter():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': '',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/generic/2010-04-15/create_event.json',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_class_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'somefield',
        'pagerduty_v2_payload_class_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'somefield',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_component_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'somefield',
        'pagerduty_v2_payload_component_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'somefield',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_group_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'somefield',
        'pagerduty_v2_payload_group_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'somefield',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_source_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'somefield',
        'pagerduty_v2_payload_source_args': ['@timestamp', 'somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'somefield',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_custom_details():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'pagerduty_v2_payload_custom_details': {'a': 'somefield', 'c': 'f'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'a': 'foobarbaz',
                'c': None,
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_include_all_info():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'pagerduty_v2_payload_include_all_info': False,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {},
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_incident_key():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom key',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom key',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_incident_key_with_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': 'Hungry kittens',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Hungry kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject_with_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinky',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinky kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinky\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject_with_args_specifying_trigger():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_event_type': 'trigger',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinkiest',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinkiest kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinkiest\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_proxy():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_event_type': 'trigger',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'pagerduty_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinkiest',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinkiest kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinkiest\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'},
                                              proxies={'https': 'http://proxy.url'})
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_ea_exception():
    try:
        rule = {
            'name': 'Test PD Rule',
            'type': 'any',
            'alert_subject': '{0} kittens',
            'alert_subject_args': ['somefield'],
            'pagerduty_service_key': 'magicalbadgers',
            'pagerduty_event_type': 'trigger',
            'pagerduty_client_name': 'ponies inc.',
            'pagerduty_incident_key': 'custom {0}',
            'pagerduty_incident_key_args': ['someotherfield'],
            'pagerduty_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerDutyAlerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'somefield': 'Stinkiest',
            'someotherfield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_alert_text_kw(ea):
    rule = ea.rules[0].copy()
    rule['alert_text'] = '{field} at {time}'
    rule['alert_text_kw'] = {
        '@timestamp': 'time',
        'field': 'field',
    }
    match = {'@timestamp': '1918-01-17', 'field': 'value'}
    alert_text = str(BasicMatchString(rule, match))
    body = '{field} at {@timestamp}'.format(**match)
    assert body in alert_text


def test_alert_text_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['owner'] = 'the owner from rule'
    rule['priority'] = 'priority from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Priority: {0}; Owner: {1}; Abc: {2}'
    rule['alert_text_args'] = ['priority', 'owner', 'abc']

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = str(BasicMatchString(rule, match))
    assert 'Priority: priority from rule' in alert_text
    assert 'Owner: the owner from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_alert_text_kw_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['foo_rule'] = 'foo from rule'
    rule['owner'] = 'the owner from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Owner: {owner}; Foo: {foo}; Abc: {abc}'
    rule['alert_text_kw'] = {
        'owner': 'owner',
        'foo_rule': 'foo',
        'abc': 'abc',
    }

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = str(BasicMatchString(rule, match))
    assert 'Owner: the owner from rule' in alert_text
    assert 'Foo: foo from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_resolving_rule_references():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'list_of_things': [
            '1',
            '$owner$',
            [
                '11',
                '$owner$',
            ],
        ],
        'nested_dict': {
            'nested_one': '1',
            'nested_owner': '$owner$',
        },
        'resolved_string_reference': '$owner$',
        'resolved_int_reference': '$priority$',
        'unresolved_reference': '$foo$',
    }
    alert = Alerter(rule)
    assert 'the_owner' == alert.rule['resolved_string_reference']
    assert 2 == alert.rule['resolved_int_reference']
    assert '$foo$' == alert.rule['unresolved_reference']
    assert 'the_owner' == alert.rule['list_of_things'][1]
    assert 'the_owner' == alert.rule['list_of_things'][2][1]
    assert 'the_owner' == alert.rule['nested_dict']['nested_owner']


def test_alerta_no_auth():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_api_skip_ssl': True,
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["%(key)s", "%(logdate)s", "%(sender_ip)s"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe %(hostname)s is UP at %(logdate)s GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        # 'key': ---- missing field on purpose, to verify that simply the text is left empty
        # 'logdate': ---- missing field on purpose, to verify that simply the text is left empty
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "<MISSING VALUE>", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json'},
        verify=False
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_auth():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'alerta_api_key': '123456789ABCDEF',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_severity': "debug",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Key {}'.format(rule['alerta_api_key'])})


def test_alerta_new_style():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        # 'key': ---- missing field on purpose, to verify that simply the text is left empty
        # 'logdate': ---- missing field on purpose, to verify that simply the text is left empty
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_use_qk_as_resource():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_use_qk_as_resource': True,
        'query_key': 'hostname',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "aProbe",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_timeout():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_timeout': 86450,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86450,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_type():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_type': 'elastalert2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert2",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_resource():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_resource': 'elastalert2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert2",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_service():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_service': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert2"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_environment():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_environment': 'Production2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production2",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_tags():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_tags': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": ['elastalert2'],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_ea_exception():
    try:
        rule = {
            'name': 'Test Alerta rule!',
            'alerta_api_url': 'http://elastalerthost:8080/api/alert',
            'timeframe': datetime.timedelta(hours=1),
            'timestamp_field': '@timestamp',
            'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
            'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
            'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
            'alerta_event': "ProbeUP",
            'alerta_group': "Health",
            'alerta_origin': "ElastAlert 2",
            'alerta_severity': "debug",
            'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
            'alerta_value': "UP",
            'type': 'any',
            'alerta_use_match_timestamp': True,
            'alerta_tags': ['elastalert2'],
            'alert': 'alerta'
        }

        match = {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = AlertaAlerter(rule)
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_alert_subject_size_limit_no_args():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    alert = Alerter(rule)
    alertSubject = alert.create_custom_title([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
    assert 5 == len(alertSubject)


def test_alert_error():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'name': 'datadog-test-name'
    }
    alert = Alerter(rule)
    try:
        alert.alert([match])
    except NotImplementedError:
        assert True


def test_alert_get_aggregation_summary_text__maximum_width():
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'A very long subject',
        'alert_subject_max_len': 5
    }
    alert = Alerter(rule)
    assert 80 == alert.get_aggregation_summary_text__maximum_width()


def test_alert_subject_size_limit_with_args(ea):
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'alert_subject': 'Test alert for {0} {1}',
        'alert_subject_args': ['test_term', 'test.term'],
        'alert_subject_max_len': 6
    }
    alert = Alerter(rule)
    alertSubject = alert.create_custom_title([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])
    assert 6 == len(alertSubject)


def test_datadog_alerter():
    rule = {
        'name': 'Test Datadog Event Alerter',
        'type': 'any',
        'datadog_api_key': 'test-api-key',
        'datadog_app_key': 'test-app-key',
        'alert': [],
        'alert_subject': 'Test Datadog Event Alert'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DatadogAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'name': 'datadog-test-name'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'title': rule['alert_subject'],
        'text': "Test Datadog Event Alerter\n\n@timestamp: 2021-01-01T00:00:00\nname: datadog-test-name\n"
    }
    mock_post_request.assert_called_once_with(
        "https://api.datadoghq.com/api/v1/events",
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'DD-API-KEY': rule['datadog_api_key'],
            'DD-APPLICATION-KEY': rule['datadog_app_key']
        }
    )
    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_datadog_alerterea_exception():
    try:
        rule = {
            'name': 'Test Datadog Event Alerter',
            'type': 'any',
            'datadog_api_key': 'test-api-key',
            'datadog_app_key': 'test-app-key',
            'alert': [],
            'alert_subject': 'Test Datadog Event Alert'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DatadogAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'name': 'datadog-test-name'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_pagertree():
    rule = {
        'name': 'Test PagerTree Rule',
        'type': 'any',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerTreeAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'event_type': 'create',
        'Id': str(uuid.uuid4()),
        'Title': 'Test PagerTree Rule',
        'Description': 'Test PagerTree Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['pagertree_integration_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    uuid4hex = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    match = uuid4hex.match(actual_data['Id'])
    assert bool(match) is True
    assert expected_data["event_type"] == actual_data['event_type']
    assert expected_data["Title"] == actual_data['Title']
    assert expected_data["Description"] == actual_data['Description']


def test_pagertree_proxy():
    rule = {
        'name': 'Test PagerTree Rule',
        'type': 'any',
        'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
        'pagertree_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerTreeAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'event_type': 'create',
        'Id': str(uuid.uuid4()),
        'Title': 'Test PagerTree Rule',
        'Description': 'Test PagerTree Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['pagertree_integration_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    uuid4hex = re.compile(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
    match = uuid4hex.match(actual_data['Id'])
    assert bool(match) is True
    assert expected_data["event_type"] == actual_data['event_type']
    assert expected_data["Title"] == actual_data['Title']
    assert expected_data["Description"] == actual_data['Description']


def test_pagertree_ea_exception():
    try:
        rule = {
            'name': 'Test PagerTree Rule',
            'type': 'any',
            'pagertree_integration_url': 'https://api.pagertree.com/integration/xxxxx',
            'pagertree_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerTreeAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_line_notify():
    rule = {
        'name': 'Test LineNotify Rule',
        'type': 'any',
        'linenotify_access_token': 'xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = LineNotifyAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message': 'Test LineNotify Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        'https://notify-api.line.me/api/notify',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer {}'.format('xxxxx')
        }
    )

    actual_data = mock_post_request.call_args_list[0][1]['data']
    assert expected_data == actual_data


def test_line_notify_ea_exception():
    try:
        rule = {
            'name': 'Test LineNotify Rule',
            'type': 'any',
            'linenotify_access_token': 'xxxxx',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = LineNotifyAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_gitter_msg_level_default():
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GitterAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message': 'Test Gitter Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'level': 'error'
    }

    mock_post_request.assert_called_once_with(
        rule['gitter_webhook_url'],
        mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][0][1])
    assert expected_data == actual_data
    assert 'error' in actual_data['level']


def test_gitter_msg_level_info():
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'gitter_msg_level': 'info',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GitterAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message': 'Test Gitter Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'level': 'info'
    }

    mock_post_request.assert_called_once_with(
        rule['gitter_webhook_url'],
        mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][0][1])
    assert expected_data == actual_data
    assert 'info' in actual_data['level']


def test_gitter_msg_level_error():
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'gitter_msg_level': 'error',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GitterAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'message': 'Test Gitter Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'level': 'error'
    }

    mock_post_request.assert_called_once_with(
        rule['gitter_webhook_url'],
        mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][0][1])
    assert expected_data == actual_data
    assert 'error' in actual_data['level']


def test_gitter_proxy():
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'gitter_msg_level': 'error',
        'gitter_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GitterAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'message': 'Test Gitter Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'level': 'error'
    }

    mock_post_request.assert_called_once_with(
        rule['gitter_webhook_url'],
        mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][0][1])
    assert expected_data == actual_data
    assert 'error' in actual_data['level']


def test_gitter_ea_exception():
    try:
        rule = {
            'name': 'Test Gitter Rule',
            'type': 'any',
            'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
            'gitter_msg_level': 'error',
            'gitter_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = GitterAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_chatwork():
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'body': 'Test Chatwork Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies=None,
        auth=None
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data


def test_chatwork_proxy():
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'chatwork_proxy': 'http://proxy.url',
        'chatwork_proxy_login': 'admin',
        'chatwork_proxy_pass': 'password',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'body': 'Test Chatwork Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data


def test_chatwork_ea_exception():
    try:
        rule = {
            'name': 'Test Chatwork Rule',
            'type': 'any',
            'chatwork_apikey': 'xxxx1',
            'chatwork_room_id': 'xxxx2',
            'chatwork_proxy': 'http://proxy.url',
            'chatwork_proxy_login': 'admin',
            'chatwork_proxy_pass': 'password',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ChatworkAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_telegram():
    rule = {
        'name': 'Test Telegram Rule',
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule* ⚠ ```\nTest Telegram Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_proxy():
    rule = {
        'name': 'Test Telegram Rule',
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'telegram_proxy': 'http://proxy.url',
        'telegram_proxy_login': 'admin',
        'telegram_proxy_pass': 'password',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule* ⚠ ```\nTest Telegram Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_text_maxlength():
    rule = {
        'name': 'Test Telegram Rule' + ('a' * 3985),
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule' + ('a' * 3979) +
                '\n⚠ *message was cropped according to telegram limits!* ⚠ ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_ea_exception():
    try:
        rule = {
            'name': 'Test Telegram Rule' + ('a' * 3985),
            'type': 'any',
            'telegram_bot_token': 'xxxxx1',
            'telegram_room_id': 'xxxxx2',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = TelegramAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_service_now():
    rule = {
        'name': 'Test ServiceNow Rule',
        'type': 'any',
        'username': 'ServiceNow username',
        'password': 'ServiceNow password',
        'servicenow_rest_url': 'https://xxxxxxxxxx',
        'short_description': 'ServiceNow short_description',
        'comments': 'ServiceNow comments',
        'assignment_group': 'ServiceNow assignment_group',
        'category': 'ServiceNow category',
        'subcategory': 'ServiceNow subcategory',
        'cmdb_ci': 'ServiceNow cmdb_ci',
        'caller_id': 'ServiceNow caller_id',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ServiceNowAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'description': 'Test ServiceNow Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'short_description': rule['short_description'],
        'comments': rule['comments'],
        'assignment_group': rule['assignment_group'],
        'category': rule['category'],
        'subcategory': rule['subcategory'],
        'cmdb_ci': rule['cmdb_ci'],
        'caller_id': rule['caller_id']
    }

    mock_post_request.assert_called_once_with(
        rule['servicenow_rest_url'],
        auth=(rule['username'], rule['password']),
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        data=mock.ANY,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_service_now_proxy():
    rule = {
        'name': 'Test ServiceNow Rule',
        'type': 'any',
        'username': 'ServiceNow username',
        'password': 'ServiceNow password',
        'servicenow_rest_url': 'https://xxxxxxxxxx',
        'short_description': 'ServiceNow short_description',
        'comments': 'ServiceNow comments',
        'assignment_group': 'ServiceNow assignment_group',
        'category': 'ServiceNow category',
        'subcategory': 'ServiceNow subcategory',
        'cmdb_ci': 'ServiceNow cmdb_ci',
        'caller_id': 'ServiceNow caller_id',
        'servicenow_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ServiceNowAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'description': 'Test ServiceNow Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'short_description': rule['short_description'],
        'comments': rule['comments'],
        'assignment_group': rule['assignment_group'],
        'category': rule['category'],
        'subcategory': rule['subcategory'],
        'cmdb_ci': rule['cmdb_ci'],
        'caller_id': rule['caller_id']
    }

    mock_post_request.assert_called_once_with(
        rule['servicenow_rest_url'],
        auth=(rule['username'], rule['password']),
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        data=mock.ANY,
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_service_now_ea_exception():
    try:
        rule = {
            'name': 'Test ServiceNow Rule',
            'type': 'any',
            'username': 'ServiceNow username',
            'password': 'ServiceNow password',
            'servicenow_rest_url': 'https://xxxxxxxxxx',
            'short_description': 'ServiceNow short_description',
            'comments': 'ServiceNow comments',
            'assignment_group': 'ServiceNow assignment_group',
            'category': 'ServiceNow category',
            'subcategory': 'ServiceNow subcategory',
            'cmdb_ci': 'ServiceNow cmdb_ci',
            'caller_id': 'ServiceNow caller_id',
            'servicenow_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ServiceNowAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_victor_ops():
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': 'INFO',
        'victorops_entity_display_name': 'no entity display name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = VictorOpsAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message_type': rule['victorops_message_type'],
        'entity_display_name': rule['victorops_entity_display_name'],
        'monitoring_tool': 'ElastAlert',
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_victor_ops_proxy():
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': 'INFO',
        'victorops_entity_display_name': 'no entity display name',
        'victorops_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = VictorOpsAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message_type': rule['victorops_message_type'],
        'entity_display_name': rule['victorops_entity_display_name'],
        'monitoring_tool': 'ElastAlert',
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_victor_ops_ea_exception():
    try:
        rule = {
            'name': 'Test VictorOps Rule',
            'type': 'any',
            'victorops_api_key': 'xxxx1',
            'victorops_routing_key': 'xxxx2',
            'victorops_message_type': 'INFO',
            'victorops_entity_display_name': 'no entity display name',
            'victorops_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = VictorOpsAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_google_chat_basic():
    rule = {
        'name': 'Test GoogleChat Rule',
        'type': 'any',
        'googlechat_webhook_url': 'http://xxxxxxx',
        'googlechat_format': 'basic',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GoogleChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'text': 'Test GoogleChat Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        rule['googlechat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_google_chat_card():
    rule = {
        'name': 'Test GoogleChat Rule',
        'type': 'any',
        'googlechat_webhook_url': 'http://xxxxxxx',
        'googlechat_format': 'card',
        'googlechat_header_title': 'xxxx1',
        'googlechat_header_subtitle': 'xxxx2',
        'googlechat_header_image': 'http://xxxx/image.png',
        'googlechat_footer_kibanalink': 'http://xxxxx/kibana',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GoogleChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'cards': [{
            'header': {
                'title': rule['googlechat_header_title'],
                'subtitle': rule['googlechat_header_subtitle'],
                'imageUrl': rule['googlechat_header_image']
            },
            'sections': [
                {
                    'widgets': [{
                        "textParagraph": {
                            'text': 'Test GoogleChat Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
                        }
                    }]
                },
                {
                    'widgets': [{
                        'buttons': [{
                            'textButton': {
                                'text': 'VISIT KIBANA',
                                'onClick': {
                                    'openLink': {
                                        'url': rule['googlechat_footer_kibanalink']
                                    }
                                }
                            }
                        }]
                    }]
                }
            ]}
        ]
    }

    mock_post_request.assert_called_once_with(
        rule['googlechat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_google_chat_ea_exception():
    try:
        rule = {
            'name': 'Test GoogleChat Rule',
            'type': 'any',
            'googlechat_webhook_url': 'http://xxxxxxx',
            'googlechat_format': 'card',
            'googlechat_header_title': 'xxxx1',
            'googlechat_header_subtitle': 'xxxx2',
            'googlechat_header_image': 'http://xxxx/image.png',
            'googlechat_footer_kibanalink': 'http://xxxxx/kibana',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = GoogleChatAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_discord():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'discord_embed_footer': 'footer',
        'discord_embed_icon_url': 'http://xxxx/image.png',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n```',
                'color': 0xffffff,
                'footer': {
                    'text': 'footer',
                    'icon_url': 'http://xxxx/image.png'
                }
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_not_footer():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n```',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_proxy():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'discord_proxy': 'http://proxy.url',
        'discord_proxy_login': 'admin',
        'discord_proxy_password': 'password',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n```',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_description_maxlength():
    rule = {
        'name': 'Test Discord Rule' + ('a' * 2069),
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule' + ('a' * 1933) +
                               '\n *message was cropped according to discord embed description limits!* ```',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_ea_exception():
    try:
        rule = {
            'name': 'Test Discord Rule' + ('a' * 2069),
            'type': 'any',
            'discord_webhook_url': 'http://xxxxxxx',
            'discord_emoji_title': ':warning:',
            'discord_embed_color': 0xffffff,
            'alert': [],
            'alert_subject': 'Test Discord'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DiscordAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_dingtalk_text():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'text',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'text',
        'text': {'content': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'}
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_markdown():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'markdown',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'markdown',
        'markdown': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_single_action_card():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'single_action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'singleTitle': rule['dingtalk_single_title'],
            'singleURL': rule['dingtalk_single_url']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_action_card():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'dingtalk_btn_orientation': '1',
        'dingtalk_btns': [
            {
                'title': 'test1',
                'actionURL': 'https://xxxxx0/'
            },
            {
                'title': 'test2',
                'actionURL': 'https://xxxxx1/'
            }
        ],
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'btnOrientation': rule['dingtalk_btn_orientation'],
            'btns': rule['dingtalk_btns']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_proxy():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'dingtalk_btn_orientation': '1',
        'dingtalk_btns': [
            {
                'title': 'test1',
                'actionURL': 'https://xxxxx0/'
            },
            {
                'title': 'test2',
                'actionURL': 'https://xxxxx1/'
            }
        ],
        'dingtalk_proxy': 'http://proxy.url',
        'dingtalk_proxy_login': 'admin',
        'dingtalk_proxy_pass': 'password',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'btnOrientation': rule['dingtalk_btn_orientation'],
            'btns': rule['dingtalk_btns']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_ea_exception():
    try:
        rule = {
            'name': 'Test DingTalk Rule',
            'type': 'any',
            'dingtalk_access_token': 'xxxxxxx',
            'dingtalk_msgtype': 'action_card',
            'dingtalk_single_title': 'elastalert',
            'dingtalk_single_url': 'http://xxxxx2',
            'dingtalk_btn_orientation': '1',
            'dingtalk_btns': [
                {
                    'title': 'test1',
                    'actionURL': 'https://xxxxx0/'
                },
                {
                    'title': 'test2',
                    'actionURL': 'https://xxxxx1/'
                }
            ],
            'dingtalk_proxy': 'http://proxy.url',
            'dingtalk_proxy_login': 'admin',
            'dingtalk_proxy_pass': 'password',
            'alert': [],
            'alert_subject': 'Test DingTalk'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DingTalkAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_mattermost_proxy():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_proxy': 'https://proxy.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies={'https': 'https://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_alert_text_only():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_not_alert_text_only():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'exclude_fields',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': []
            }
        ],
        'text': 'Test Mattermost Rule\n\n',
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_msg_fields():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_msg_fields': [
            {
                'title': 'Stack',
                'value': "{0} {1}",
                'short': False,
                'args': ["type", "msg.status_code"]
            },
            {
                'title': 'Name',
                'value': 'static field',
                'short': False
            }
        ],
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [
                    {'title': 'Stack', 'value': '<MISSING VALUE> <MISSING VALUE>', 'short': False},
                    {'title': 'Name', 'value': 'static field', 'short': False}
                ],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_icon_url_override():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_icon_url_override': 'http://xxxx/icon.png',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert',
        'icon_url': 'http://xxxx/icon.png'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_channel_override():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_channel_override': 'test channel',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert',
        'channel': 'test channel'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_ignore_ssl_errors():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_ignore_ssl_errors': True,
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=False,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_title_link():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_title_link': 'http://title.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'title_link': 'http://title.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_footer():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_footer': 'Mattermost footer',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'footer': 'Mattermost footer'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_footer_icon():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_footer_icon': 'http://icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'footer_icon': 'http://icon.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_image_url():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_image_url': 'http://image.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'image_url': 'http://image.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_thumb_url():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_thumb_url': 'http://thumb.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'thumb_url': 'http://thumb.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_name():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_name': 'author name',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_name': 'author name'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_link():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_link': 'http://author.link.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_link': 'http://author.link.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_icon():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_icon': 'http://author.icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_icon': 'http://author.icon.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_ea_exception():
    try:
        rule = {
            'name': 'Test Mattermost Rule',
            'type': 'any',
            'alert_text_type': 'alert_text_only',
            'mattermost_webhook_url': 'http://xxxxx',
            'mattermost_msg_pretext': 'aaaaa',
            'mattermost_msg_color': 'danger',
            'mattermost_author_icon': 'http://author.icon.url',
            'alert': [],
            'alert_subject': 'Test Mattermost'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MattermostAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_thehive_alerter():
    rule = {'alert': [],
            'alert_text': '',
            'alert_text_type': 'alert_text_only',
            'description': 'test',
            'hive_alert_config': {'customFields': [{'name': 'test',
                                                    'type': 'string',
                                                    'value': 'test.ip'}],
                                  'follow': True,
                                  'severity': 2,
                                  'source': 'elastalert',
                                  'status': 'New',
                                  'tags': ['test.ip'],
                                  'tlp': 3,
                                  'type': 'external'},
            'hive_connection': {'hive_apikey': '',
                                'hive_host': 'https://localhost',
                                'hive_port': 9000},
            'hive_observable_data_mapping': [{'ip': 'test.ip'}],
            'name': 'test-thehive',
            'tags': ['a', 'b'],
            'type': 'any'}
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HiveAlerter(rule)
    match = {
        "test": {
          "ip": "127.0.0.1"
        },
        "@timestamp": "2021-05-09T14:43:30",
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "artifacts": [
            {
                "data": "127.0.0.1",
                "dataType": "ip",
                "message": None,
                "tags": [],
                "tlp": 2
            }
        ],
        "customFields": {
            "test": {
                "order": 0,
                "string": "127.0.0.1"
            }
        },
        "description": "\n\n",
        "follow": True,
        "severity": 2,
        "source": "elastalert",
        "status": "New",
        "tags": [
            "127.0.0.1"
        ],
        "title": "test-thehive",
        "tlp": 3,
        "type": "external"
    }

    conn_config = rule['hive_connection']
    alert_url = f"{conn_config['hive_host']}:{conn_config['hive_port']}/api/alert"
    mock_post_request.assert_called_once_with(
        alert_url,
        data=mock.ANY,
        headers={'Content-Type': 'application/json',
                 'Authorization': 'Bearer '},
        verify=False,
        proxies={'http': '', 'https': ''}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    # The date and sourceRef are autogenerated, so we can't expect them to be a particular value
    del actual_data['date']
    del actual_data['sourceRef']

    assert expected_data == actual_data


def test_zabbix_basic():
    rule = {
        'name': 'Basic Zabbix test',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'alert': [],
        'alert_subject': 'Test Zabbix',
        'zbx_host': 'example.com',
        'zbx_key': 'example-key'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ZabbixAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00Z',
        'somefield': 'foobarbaz'
    }
    with mock.patch('pyzabbix.ZabbixSender.send') as mock_zbx_send:
        alert.alert([match])

        zabbix_metrics = {
            "host": "example.com",
            "key": "example-key",
            "value": "1",
            "clock": 1609459200
        }
        alerter_args = mock_zbx_send.call_args.args
        assert vars(alerter_args[0][0]) == zabbix_metrics
