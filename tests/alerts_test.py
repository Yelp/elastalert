# -*- coding: utf-8 -*-
import datetime
import json
import subprocess
from contextlib import ExitStack

import base64
import mock
import pytest
from jira.exceptions import JIRAError

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.alerts import CommandAlerter
from elastalert.alerts import EmailAlerter
from elastalert.alerts import JiraAlerter
from elastalert.alerts import JiraFormattedMatchString
from elastalert.alerts import SlackAlerter
from elastalert.config import load_modules
from elastalert.opsgenie import OpsGenieAlerter
from elastalert.util import ts_add


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



def test_email():
    rule = {'name': 'test alert', 'email': ['bdh931101@gmail.com'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': '☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(),
                    mock.call().sendmail(mock.ANY, ['bdh931101@gmail.com'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: bdh931101@gmail.com' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body

def test_email_with_unicode_strings():
    rule = {'name': 'test alert', 'email': 'testing@test.test', 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': '☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(),
                    mock.call().sendmail(mock.ANY, ['testing@test.test'], mock.ANY),
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
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(),
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
                    mock.call().starttls(),
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
                    mock.call().starttls(),
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
                    mock.call().starttls(),
                    mock.call().sendmail(mock.ANY,
                                         ['testing@test.test', 'test@test.test', 'test1@test.com', 'test2@test.com', 'tester@testing.testing'],
                                         mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: test1@test.com,test2@test.com' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_args():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0} {1}', 'alert_subject_args': ['test_term', 'test.term'], 'alert_text': 'Test alert for {0} and {1} {2}',
            'alert_text_args': ['test_arg1', 'test_arg2', 'test.arg3']}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'test_arg1': 'testing', 'test': {'term': ':)', 'arg3': '☃'}}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]
        # Extract the MIME encoded message body
        body_text = body.split('\n\n')[-1][:-1]
        body_text = base64.b64decode(body_text).decode('utf-8')
        assert 'testing' in body_text
        assert '<MISSING VALUE>' in body_text
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
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v1/json/alert',
            'opsgenie_recipients': ['lytics'], 'type': mock_rule()}
    with mock.patch('requests.post') as mock_post:

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])
        print(("mock_post: {0}".format(mock_post._mock_call_args_list)))
        mcal = mock_post._mock_call_args_list
        print(('mcal: {0}'.format(mcal[0])))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v1/json/alert')

        assert mock_post.called

        assert mcal[0][1]['json']['apiKey'] == 'ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['recipients'] == ['lytics']
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


def test_opsgenie_frequency():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v1/json/alert',
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
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v1/json/alert')

        assert mock_post.called

        assert mcal[0][1]['json']['apiKey'] == 'ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['recipients'] == ['lytics']
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


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
        mock_create = mock.Mock()
        mock_create.return_value = {'_id': 'ABCDEFGH'}
        mock_es_inst = mock.Mock()
        mock_es_inst.index = mock_create
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
             'somefield': 'foobarbaz'}
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)

    # Test command as string with formatted arg
    rule = {'command': '/bin/test/ --arg %(somefield)s'}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg foobarbaz', stdin=subprocess.PIPE, shell=False)

    # Test command as string without formatted arg
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
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(rule['slack_webhook_url'], data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
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
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(rule['slack_webhook_url'][0], data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
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
                'fields': []
            }
        ],
        'text': '',
        'parse': 'none'
    }
    mock_post_request.assert_called_once_with(rule['slack_webhook_url'][0], data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


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
