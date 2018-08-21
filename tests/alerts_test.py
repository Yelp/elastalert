# -*- coding: utf-8 -*-
import datetime
import json
import subprocess
from contextlib import nested

import mock
import pytest
from jira.exceptions import JIRAError

from elastalert.alerts import AlertaAlerter
from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.alerts import CommandAlerter
from elastalert.alerts import EmailAlerter
from elastalert.alerts import HipChatAlerter
from elastalert.alerts import HTTPPostAlerter
from elastalert.alerts import JiraAlerter
from elastalert.alerts import JiraFormattedMatchString
from elastalert.alerts import MsTeamsAlerter
from elastalert.alerts import PagerDutyAlerter
from elastalert.alerts import SlackAlerter
from elastalert.alerts import StrideAlerter
from elastalert.config import load_modules
from elastalert.opsgenie import OpsGenieAlerter
from elastalert.util import ts_add
from elastalert.util import ts_now


class mock_rule:
    def get_match_str(self, event):
        return str(event)


def test_basic_match_string(ea):
    ea.rules[0]['top_count_keys'] = ['username']
    match = {'@timestamp': '1918-01-17', 'field': 'value', 'top_events_username': {'bob': 10, 'mallory': 5}}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'anytest' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'bob: 10' in alert_text
    assert 'field: value' in alert_text

    # Non serializable objects don't cause errors
    match['non-serializable'] = {open: 10}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))

    # unicode objects dont cause errors
    match['snowman'] = u'☃'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))

    # Pretty printed objects
    match.pop('non-serializable')
    match['object'] = {'this': {'that': [1, 2, "3"]}}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert '"this": {\n        "that": [\n            1, \n            2, \n            "3"\n        ]\n    }' in alert_text

    ea.rules[0]['alert_text'] = 'custom text'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'anytest' not in alert_text

    ea.rules[0]['alert_text_type'] = 'alert_text_only'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' not in alert_text
    assert 'username' not in alert_text
    assert 'field: value' not in alert_text

    ea.rules[0]['alert_text_type'] = 'exclude_fields'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
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
        + 3 * tab + '"one", \n' \
        + 3 * tab + '2, \n' \
        + 3 * tab + '"three"\n' \
        + 2 * tab + ']\n' \
        + tab + '}\n' \
        + '}{code}'
    assert expected_alert_text_snippet in alert_text


def test_email():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': u'☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, with @
    rule['email_add_domain'] = '@example.com'
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, list
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': ['qlo', 'foo']}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com', 'foo@example.com']

    # Not found
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'foo': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']

    # Found, wrong type
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 17}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']


def test_email_with_unicode_strings():
    rule = {'name': 'test alert', 'email': u'testing@test.test', 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': u'☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, [u'testing@test.test'], mock.ANY),
                    mock.call().close()]
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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cert_key():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt',
            'smtp_cert_file': 'dummy/cert.crt', 'smtp_key_file': 'dummy/client.key', 'rule_file': '/tmp/foo.yaml'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile='dummy/cert.crt', keyfile='dummy/client.key'),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'cc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().close()]
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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().close()]
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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
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
            mock.call().close()]
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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'test_arg1': 'testing', 'test': {'term': ':)', 'arg3': u'☃'}}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]
        # Extract the MIME encoded message body
        body_text = body.split('\n\n')[-1][:-1].decode('base64')

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
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
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
        print("mock_post: {0}".format(mock_post._mock_call_args_list))
        mcal = mock_post._mock_call_args_list
        print('mcal: {0}'.format(mcal[0]))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'id': 'lytics', 'type': 'user'}]
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

        print("mock_post: {0}".format(mock_post._mock_call_args_list))
        mcal = mock_post._mock_call_args_list
        print('mcal: {0}'.format(mcal[0]))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'id': 'lytics', 'type': 'user'}]
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


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

    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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
    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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
    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
        mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
        mock_jira.return_value = mock.Mock()
        mock_jira.return_value.search_issues.return_value = []
        mock_jira.return_value.priorities.return_value = [mock_priority]
        mock_jira.return_value.fields.return_value = []

        alert = JiraAlerter(rule)
        alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

    assert 'test_value' not in mock_jira.mock_calls[3][1][0]

    # Issue is still created if search_issues throws an exception
    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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
    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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
    with nested(
        mock.patch('elastalert.alerts.JIRA'),
        mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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
        with nested(
            mock.patch('elastalert.alerts.JIRA'),
            mock.patch('elastalert.alerts.yaml_loader')
        ) as (mock_jira, mock_open):
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

    with nested(
            mock.patch('elastalert.alerts.JIRA'),
            mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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

    with nested(
            mock.patch('elastalert.alerts.JIRA'),
            mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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

    with nested(
            mock.patch('elastalert.alerts.JIRA'),
            mock.patch('elastalert.alerts.yaml_loader')
    ) as (mock_jira, mock_open):
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

    # Test command as string with formatted arg (new-style string format)
    rule = {'command': '/bin/test/ --arg {match[somefield]}', 'new_style_string_format': True}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg foobarbaz', stdin=subprocess.PIPE, shell=False)

    rule = {'command': '/bin/test/ --arg {match[nested][field]}', 'new_style_string_format': True}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg 1', stdin=subprocess.PIPE, shell=False)

    # Test command as string without formatted arg (new-style string format)
    rule = {'command': '/bin/test/foo.sh', 'new_style_string_format': True}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test/foo.sh', stdin=subprocess.PIPE, shell=True)

    rule = {'command': '/bin/test/foo.sh {{bar}}', 'new_style_string_format': True}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test/foo.sh {bar}', stdin=subprocess.PIPE, shell=True)

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


def test_ms_teams():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    load_modules(rule)
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
    load_modules(rule)
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


def test_slack_uses_custom_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': 'http://please.dontgohere.slack',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    load_modules(rule)
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
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_slack_uses_rule_name_when_custom_title_is_not_provided():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'slack_webhook_url': ['http://please.dontgohere.slack'],
        'alert': []
    }
    load_modules(rule)
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
        verify=True
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
    load_modules(rule)
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
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_with_payload():
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_payload': {'posted_name': 'somefield'},
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    load_modules(rule)
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
        timeout=10
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
    load_modules(rule)
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
        timeout=10
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
    load_modules(rule)
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
        timeout=10
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'alert': []
    }
    load_modules(rule)
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
    load_modules(rule)
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
    load_modules(rule)
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
    load_modules(rule)
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
    load_modules(rule)
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
    load_modules(rule)
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
    load_modules(rule)
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


def test_alert_text_kw(ea):
    rule = ea.rules[0].copy()
    rule['alert_text'] = '{field} at {time}'
    rule['alert_text_kw'] = {
        '@timestamp': 'time',
        'field': 'field',
    }
    match = {'@timestamp': '1918-01-17', 'field': 'value'}
    alert_text = unicode(BasicMatchString(rule, match))
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

    alert_text = unicode(BasicMatchString(rule, match))
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

    alert_text = unicode(BasicMatchString(rule, match))
    assert 'Owner: the owner from rule' in alert_text
    assert 'Foo: foo from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_resolving_rule_references(ea):
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


def test_stride_plain_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    body = "{0}\n\n@timestamp: {1}\nsomefield: {2}".format(
        rule['name'], match['@timestamp'], match['somefield']
    )
    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': body}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_stride_underline_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert_text': '<u>Underline Text</u>',
        'alert_text_type': 'alert_text_only',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    body = "Underline Text"
    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': body, 'marks': [
                    {'type': 'underline'}
                ]}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_stride_bold_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert_text': '<b>Bold Text</b>',
        'alert_text_type': 'alert_text_only',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    body = "Bold Text"
    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': body, 'marks': [
                    {'type': 'strong'}
                ]}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_stride_strong_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert_text': '<strong>Bold Text</strong>',
        'alert_text_type': 'alert_text_only',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    body = "Bold Text"
    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': body, 'marks': [
                    {'type': 'strong'}
                ]}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_stride_hyperlink():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert_text': '<a href="http://stride.com">Link</a>',
        'alert_text_type': 'alert_text_only',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    body = "Link"
    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': body, 'marks': [
                    {'type': 'link', 'attrs': {'href': 'http://stride.com'}}
                ]}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_stride_html():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'stride_access_token': 'token',
        'stride_cloud_id': 'cloud_id',
        'stride_conversation_id': 'conversation_id',
        'alert_subject': 'Cool subject',
        'alert_text': '<b>Alert</b>: we found something. <a href="http://stride.com">Link</a>',
        'alert_text_type': 'alert_text_only',
        'alert': []
    }
    load_modules(rule)
    alert = StrideAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {'body': {'version': 1, 'type': "doc", 'content': [
        {'type': "panel", 'attrs': {'panelType': "warning"}, 'content': [
            {'type': 'paragraph', 'content': [
                {'type': 'text', 'text': 'Alert', 'marks': [
                    {'type': 'strong'}
                ]},
                {'type': 'text', 'text': ': we found something. '},
                {'type': 'text', 'text': 'Link', 'marks': [
                    {'type': 'link', 'attrs': {'href': 'http://stride.com'}}
                ]}
            ]}
        ]}
    ]}}

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(rule['stride_access_token'])},
        verify=True,
        proxies=None
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_hipchat_body_size_limit_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'hipchat_auth_token': 'token',
        'hipchat_room_id': 'room_id',
        'hipchat_message_format': 'text',
        'alert_subject': 'Cool subject',
        'alert_text': 'Alert: we found something.\n\n{message}',
        'alert_text_type': 'alert_text_only',
        'alert': [],
        'alert_text_kw': {
            '@timestamp': 'time',
            'message': 'message',
        },
    }
    load_modules(rule)
    alert = HipChatAlerter(rule)
    match = {
        '@timestamp': '2018-01-01T00:00:00',
        'message': 'foo bar\n' * 5000,
    }
    body = alert.create_alert_body([match])

    assert len(body) <= 10000


def test_hipchat_body_size_limit_html():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'hipchat_auth_token': 'token',
        'hipchat_room_id': 'room_id',
        'hipchat_message_format': 'html',
        'alert_subject': 'Cool subject',
        'alert_text': 'Alert: we found something.\n\n{message}',
        'alert_text_type': 'alert_text_only',
        'alert': [],
        'alert_text_kw': {
            '@timestamp': 'time',
            'message': 'message',
        },
    }
    load_modules(rule)
    alert = HipChatAlerter(rule)
    match = {
        '@timestamp': '2018-01-01T00:00:00',
        'message': 'foo bar\n' * 5000,
    }

    body = alert.create_alert_body([match])

    assert len(body) <= 10000


def test_alerta_no_auth(ea):
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': u'@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["%(key)s", "%(logdate)s", "%(sender_ip)s"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "Elastalert",
        'alerta_severity': "debug",
        'alerta_text': "Probe %(hostname)s is UP at %(logdate)s GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        u'@timestamp': '2014-10-10T00:00:00',
        # 'key': ---- missing field on purpose, to verify that simply the text is left empty
        # 'logdate': ---- missing field on purpose, to verify that simply the text is left empty
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "Elastalert",
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
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_auth(ea):
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

    load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Key {}'.format(rule['alerta_api_key'])})


def test_alerta_new_style(ea):
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
        'alerta_origin': "Elastalert",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'alerta_new_style_string_format': True,
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

    load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "Elastalert",
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
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])
