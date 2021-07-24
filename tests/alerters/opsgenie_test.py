import logging
import pytest
import requests

from unittest import mock

from requests import RequestException

from elastalert.alerters.opsgenie import OpsGenieAlerter
from elastalert.alerts import BasicMatchString
from elastalert.util import EAException
from tests.alerts_test import mock_rule


def test_opsgenie_basic(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'type': mock_rule()
    }
    with mock.patch('requests.post') as mock_post:
        rep = requests
        rep.status_code = 202
        mock_post.return_value = rep

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])
        print(("mock_post: {0}".format(mock_post._mock_call_args_list)))
        mcal = mock_post._mock_call_args_list

        print(('mcal: {0}'.format(mcal[0])))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        # Should be default source 'ElastAlert', because 'opsgenie_source' param isn't set in rule
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        user, level, message = caplog.record_tuples[0]
        assert "Error response from https://api.opsgenie.com/v2/alerts \n API Response: <MagicMock name='post()' id=" not in message
        assert ('elastalert', logging.INFO, 'Alert sent to OpsGenie') == caplog.record_tuples[0]


def test_opsgenie_basic_not_status_code_202(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_account': 'genies',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_recipients': ['lytics'],
        'type': mock_rule()
    }
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
        user, level, message = caplog.record_tuples[0]
        assert "Error response from https://api.opsgenie.com/v2/alerts \n API Response: <MagicMock name='post()' id=" in message
        assert ('elastalert', logging.INFO, 'Alert sent to OpsGenie') == caplog.record_tuples[1]


def test_opsgenie_frequency():
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_account': 'genies',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_recipients': ['lytics'],
        'type': mock_rule(),
        'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
        'alert': 'opsgenie'
    }
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


def test_opsgenie_alert_routing():
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_account': 'genies',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_recipients': ['{RECEIPIENT_PREFIX}'],
        'opsgenie_recipients_args': {'RECEIPIENT_PREFIX': 'recipient'},
        'type': mock_rule(),
        'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
        'alert': 'opsgenie',
        'opsgenie_teams': ['{TEAM_PREFIX}-Team'],
        'opsgenie_teams_args': {'TEAM_PREFIX': 'team'}
    }
    with mock.patch('requests.post'):

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00', 'team': "Test", 'recipient': "lytics"}])

        assert alert.get_info()['teams'] == ['Test-Team']
        assert alert.get_info()['recipients'] == ['lytics']


def test_opsgenie_default_alert_routing():
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_account': 'genies',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_recipients': ['{RECEIPIENT_PREFIX}'],
        'opsgenie_recipients_args': {'RECEIPIENT_PREFIX': 'recipient'},
        'type': mock_rule(),
        'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
        'alert': 'opsgenie',
        'opsgenie_teams': ['{TEAM_PREFIX}-Team'],
        'opsgenie_default_receipients': ["devops@test.com"],
        'opsgenie_default_teams': ["Test"]
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


@pytest.mark.parametrize('opsgenie_priority', [
    ('P1'),
    ('P2'),
    ('P3'),
    ('P4'),
    ('P5')
])
def test_opsgenie_priority(opsgenie_priority):
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_priority': opsgenie_priority
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
        'priority': opsgenie_priority,
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


def test_opsgenie_ea_exception():
    with pytest.raises(EAException) as ea:
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
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error sending alert: ' in str(ea)


@pytest.mark.parametrize('opsgenie_account, opsgenie_recipients, opsgenie_teams, expected_data', [
    ('',       '',         '',                     {'type': 'opsgenie'}),
    ('genies', '',         '',                     {'type': 'opsgenie', 'account': 'genies'}),
    ('',       ['lytics'], '',                     {'type': 'opsgenie', 'recipients': ['lytics']}),
    ('',       '',         ['{TEAM_PREFIX}-Team'], {'type': 'opsgenie', 'teams': ['{TEAM_PREFIX}-Team']}),
])
def test_opsgenie_getinfo(opsgenie_account, opsgenie_recipients, opsgenie_teams, expected_data):
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule()
    }
    if opsgenie_account:
        rule['opsgenie_account'] = opsgenie_account
    if opsgenie_recipients:
        rule['opsgenie_recipients'] = opsgenie_recipients
    if opsgenie_teams:
        rule['opsgenie_teams'] = opsgenie_teams

    alert = OpsGenieAlerter(rule)

    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('query_key, expected_data', [
    ('hostname',  'ElastAlert: Opsgenie Details - aProbe'),
    ('test',      'ElastAlert: Opsgenie Details'),
    ('',          'ElastAlert: Opsgenie Details'),
])
def test_opsgenie_create_default_title(query_key, expected_data):
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
    if query_key:
        rule['query_key'] = query_key

    match = [
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        },
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname2': 'aProbe'
        }
    ]

    alert = OpsGenieAlerter(rule)

    result = alert.create_default_title(match)
    assert expected_data == result


@pytest.mark.parametrize('opsgenie_key, expected_data', [
    ('',  'Missing required option(s): opsgenie_key'),
    ('a',
        {
            "type": "opsgenie"
        }),
])
def test_opsgenie_required_error(opsgenie_key, expected_data):
    try:
        rule = {
            'name': 'Opsgenie Details',
            'type': mock_rule(),
        }

        if opsgenie_key:
            rule['opsgenie_key'] = opsgenie_key

        alert = OpsGenieAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


@pytest.mark.parametrize('opsgenie_entity, expected_entity, opsgenie_priority, expected_priority', [
    ('const host', 'const host', 'P1', 'P1'),
    ('host {hostname}', 'host server_a', 'P{level}', 'P2'),
    ('Elastalert {source}', 'Elastalert EMEA', '{priority}', 'P3'),
])
def test_opsgenie_substitution(opsgenie_entity, expected_entity, opsgenie_priority, expected_priority):
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_entity': opsgenie_entity,
        'opsgenie_priority': opsgenie_priority,
    }
    matches = [{
        'message': 'Testing',
        'hostname': 'server_a',
        'source': 'EMEA',
        'level': '2',
        'priority': 'P3',
        '@timestamp': '2014-10-31T00:00:00'
    }]
    alert = OpsGenieAlerter(rule)

    with mock.patch('requests.post') as mock_post:
        alert = OpsGenieAlerter(rule)
        alert.alert(matches)

        mcal = mock_post._mock_call_args_list
        assert mock_post.called

        assert mcal[0][1]['json']['entity'] == expected_entity
        assert mcal[0][1]['json']['priority'] == expected_priority


def test_opsgenie_details_with_constant_value_matchs():
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
        alert.alert([match, match])

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
        'description': 'Opsgenie Details\n'
                       '\n'
                       "{'@timestamp': '2014-10-31T00:00:00'}\n"
                       '\n'
                       '@timestamp: 2014-10-31T00:00:00\n'
                       '\n'
                       '----------------------------------------\n'
                       'Opsgenie Details\n'
                       '\n'
                       "{'@timestamp': '2014-10-31T00:00:00'}\n"
                       '\n'
                       '@timestamp: 2014-10-31T00:00:00\n'
                       '\n'
                       '----------------------------------------\n',
        'details': {'Foo': 'Bar'},
        'message': 'ElastAlert: Opsgenie Details',
        'priority': None,
        'source': 'ElastAlert',
        'tags': ['ElastAlert', 'Opsgenie Details'],
        'user': 'genies'
    }
    actual_json = mock_post_request.call_args_list[0][1]['json']
    assert expected_json == actual_json


def test_opsgenie_source_blank(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_source': '',
        'type': mock_rule()
    }
    with mock.patch('requests.post') as mock_post:
        rep = requests
        rep.status_code = 202
        mock_post.return_value = rep

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])
        print(("mock_post: {0}".format(mock_post._mock_call_args_list)))
        mcal = mock_post._mock_call_args_list

        print(('mcal: {0}'.format(mcal[0])))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        user, level, message = caplog.record_tuples[0]
        assert "Error response from https://api.opsgenie.com/v2/alerts \n API Response: <MagicMock name='post()' id=" not in message
        assert ('elastalert', logging.INFO, 'Alert sent to OpsGenie') == caplog.record_tuples[0]


def test_opsgenie_parse_responders(caplog):
    caplog.set_level(logging.WARNING)
    rule = {
        'name': 'testOGalert',
        'opsgenie_key': 'ogkey',
        'opsgenie_account': 'genies',
        'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
        'opsgenie_recipients': ['{RECEIPIENT_PREFIX}'],
        'opsgenie_recipients_args': {'RECEIPIENT_PREFIX': 'recipient'},
        'type': mock_rule(),
        'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
        'alert': 'opsgenie',
        'opsgenie_teams': ['{TEAM_PREFIX}-Team'],
        'opsgenie_teams_args': {'TEAM_PREFIX': 'team'},
        'opsgenie_default_teams': ["Test"]
    }
    match = [
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        },
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname2': 'aProbe'
        }
    ]
    with mock.patch('requests.post'):
        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00', 'team': "Test"}])
        actual = alert._parse_responders(
            rule['opsgenie_teams'],
            rule['opsgenie_teams_args'],
            match,
            rule['opsgenie_default_teams']
        )
    excepted = ['Test']
    assert excepted == actual
    user, level, message = caplog.record_tuples[0]
    assert logging.WARNING == level
    assert "Cannot create responder for OpsGenie Alert. Key not foud: 'RECEIPIENT_PREFIX'." in message
    user, level, message = caplog.record_tuples[1]
    assert logging.WARNING == level
    assert 'no responders can be formed. Trying the default responder' in message
    user, level, message = caplog.record_tuples[2]
    assert logging.WARNING == level
    assert 'default responder not set. Falling back' in message
    user, level, message = caplog.record_tuples[3]
    assert logging.WARNING == level
    assert "Cannot create responder for OpsGenie Alert. Key not foud: 'TEAM_PREFIX'." in message
    user, level, message = caplog.record_tuples[4]
    assert logging.WARNING == level
    assert 'no responders can be formed. Trying the default responder' in message


def test_opsgenie_create_custom_title():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'Testing': 'abc',
        'opsgenie_subject': '{} {} {}',
        'opsgenie_subject_args': ['Testing', 'message', '@timestamp']
    }
    match = [
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        },
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        }
    ]
    alert = OpsGenieAlerter(rule)
    actual = alert.create_custom_title(match)
    excepted = 'abc Testing 2014-10-31T00:00:00'
    assert excepted == actual


def test_opsgenie_get_details():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'},
            'cde': {'field2': 'ok'},
            'abc': 'test',
            'f': 1
        },
        'Testing': 'abc',
        'opsgenie_subject': '{} {} {}',
        'opsgenie_subject_args': ['Testing', 'message', '@timestamp']
    }
    match = [
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        },
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        }
    ]
    alert = OpsGenieAlerter(rule)
    actual = alert.get_details(match)
    excepted = {'Message': 'Testing', 'abc': 'test'}
    assert excepted == actual


def test_opsgenie_get_details2():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'Testing': 'abc',
        'opsgenie_subject': '{} {} {}',
        'opsgenie_subject_args': ['Testing', 'message', '@timestamp']
    }
    match = [
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        },
        {
            'message': 'Testing',
            '@timestamp': '2014-10-31T00:00:00'
        }
    ]
    alert = OpsGenieAlerter(rule)
    actual = alert.get_details(match)
    excepted = {}
    assert excepted == actual
