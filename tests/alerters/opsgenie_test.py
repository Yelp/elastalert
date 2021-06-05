from unittest import mock
import pytest
from requests import RequestException

from elastalert.util import EAException
from elastalert.alerters.opsgenie import OpsGenieAlerter
from elastalert.alerts import BasicMatchString
from tests.alerts_test import mock_rule


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
    try:
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
    except EAException:
        assert True


def test_opsgenie_getinfo():
    rule = {
        'name': 'Opsgenie Details',
        'type': mock_rule(),
        'opsgenie_account': 'genies',
        'opsgenie_key': 'ogkey',
        'opsgenie_details': {
            'Message': {'field': 'message'},
            'Missing': {'field': 'missing'}
        },
        'opsgenie_proxy': 'https://proxy.url',
        'opsgenie_teams': ['{TEAM_PREFIX}-Team'],
        'opsgenie_recipients': ['lytics']
    }
    alert = OpsGenieAlerter(rule)

    expected_data = {
        'type': 'opsgenie',
        'recipients': ['lytics'],
        'account': 'genies',
        'teams': ['{TEAM_PREFIX}-Team']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data
