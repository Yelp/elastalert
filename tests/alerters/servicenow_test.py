import json

from unittest import mock
import pytest
from requests import RequestException

from elastalert.alerters.servicenow import ServiceNowAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


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


def test_servicenow_getinfo():
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

    expected_data = {
        'type': 'ServiceNow',
        'self.servicenow_rest_url': 'https://xxxxxxxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data
