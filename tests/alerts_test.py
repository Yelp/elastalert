# -*- coding: utf-8 -*-
import datetime
import json
import subprocess

import mock

from elastalert.alerts import basic_match_string
from elastalert.alerts import CommandAlerter
from elastalert.alerts import EmailAlerter
from elastalert.alerts import JiraAlerter
from elastalert.util import ts_add


class mock_rule:
    def get_match_str(self, event):
        return str(event)


def test_alert_text(ea):
    ea.rules[0]['top_count_keys'] = ['username']
    match = {'@timestamp': '1918-01-17', 'field': 'value', 'top_events_username': {'bob': 10, 'mallory': 5}}
    alert_text = basic_match_string(ea.rules[0], match)
    assert 'anytest' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'bob: 10' in alert_text
    assert 'field: value' in alert_text

    ea.rules[0]['alert_text'] = 'custom text'
    alert_text = basic_match_string(ea.rules[0], match)
    assert 'custom text' in alert_text

    ea.rules[0]['alert_text_type'] = 'alert_text_only'
    alert_text = basic_match_string(ea.rules[0], match)
    assert 'custom text' in alert_text
    assert 'some stuff happened' not in alert_text
    assert 'username' not in alert_text
    assert 'field: value' not in alert_text

    ea.rules[0]['alert_text_type'] = 'exclude_fields'
    alert_text = basic_match_string(ea.rules[0], match)
    assert 'custom text' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'field: value' not in alert_text


def test_email():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'],
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term']}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[1][1][2]
        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'Subject: Test alert for test_value' in body


def test_email_query_key_in_subject():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'],
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'query_key': 'username'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'username': 'werbenjagermanjensen'}])

        body = mock_smtp.mock_calls[1][1][2]
        lines = body.split('\n')
        found_subject = False
        for line in lines:
            if line.startswith('Subject'):
                assert 'werbenjagermanjensen' in line
                found_subject = True
        assert found_subject


def test_jira():
    rule = {'name': 'test alert', 'jira_account_file': 'jirafile', 'type': mock_rule(),
            'jira_project': 'testproject', 'jira_issuetype': 'testtype', 'jira_server': 'jiraserver',
            'jira_label': 'testlabel', 'jira_component': 'testcomponent',
            'timestamp_field': '@timestamp', 'alert_subject': 'Issue {0} occured at {1}',
            'alert_subject_args': ['test_term', '@timestamp']}
    with mock.patch('elastalert.alerts.JIRA') as mock_jira:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'jirauser', 'password': 'jirapassword'}
            mock_jira.return_value = mock.Mock()

            alert = JiraAlerter(rule)
            alert.alert([{'test_term': 'test_value', '@timestamp': '2014-10-31T00:00:00'}])

            expected = [mock.call('jiraserver', basic_auth=('jirauser', 'jirapassword')),
                        mock.call().create_issue(issuetype={'name': 'testtype'},
                                                 project={'key': 'testproject'},
                                                 labels=['testlabel'],
                                                 components=[{'name': 'testcomponent'}],
                                                 description=mock.ANY,
                                                 summary='Issue test_value occured at 2014-10-31T00:00:00')]
            assert mock_jira.mock_calls == expected


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
    with mock.patch("elastalert.elastalert.Elasticsearch") as mock_es:
        mock_create = mock.Mock(return_value={'_id': 'ABCDEFGH'})
        mock_es_inst = mock.Mock()
        mock_es_inst.create = mock_create
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
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE)

    # Test command as string with formatted arg
    rule = {'command': '/bin/test/ --arg %(somefield)s'}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerts.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg foobarbaz', stdin=subprocess.PIPE)

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
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE)
    assert mock_subprocess.communicate.called_with(input=json.dumps(match))
