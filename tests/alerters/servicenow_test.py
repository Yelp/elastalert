import json
import logging
import pytest

from requests import RequestException
from unittest import mock

from elastalert.alerters.servicenow import ServiceNowAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_service_now(caplog):
    caplog.set_level(logging.INFO)
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
        'short_description': 'ServiceNow short_description',
        'comments': 'ServiceNow comments',
        'assignment_group': 'ServiceNow assignment_group',
        'category': 'ServiceNow category',
        'subcategory': 'ServiceNow subcategory',
        'cmdb_ci': 'ServiceNow cmdb_ci',
        'caller_id': 'ServiceNow caller_id'
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
    assert ('elastalert', logging.INFO, 'Alert sent to ServiceNow') == caplog.record_tuples[0]


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
        'short_description': 'ServiceNow short_description',
        'comments': 'ServiceNow comments',
        'assignment_group': 'ServiceNow assignment_group',
        'category': 'ServiceNow category',
        'subcategory': 'ServiceNow subcategory',
        'cmdb_ci': 'ServiceNow cmdb_ci',
        'caller_id': 'ServiceNow caller_id'
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


def test_service_now_impact_and_urgency():
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
        'servicenow_impact': 3,
        'servicenow_urgency': 1,
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

    data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert data['impact'] == rule['servicenow_impact']
    assert data['urgency'] == rule['servicenow_urgency']


def test_service_now_ea_exception():
    with pytest.raises(EAException) as ea:
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
    assert 'Error posting to ServiceNow: ' in str(ea)


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


servicenow_required_error_param = 'username, password, servicenow_rest_url, short_description, comments, '
servicenow_required_error_param += 'assignment_group, category, subcategory, cmdb_ci, caller_id, expected_data'
servicenow_required_error_excepted = 'username, password, servicenow_rest_url, short_description, comments, '
servicenow_required_error_excepted += 'assignment_group, category, subcategory, cmdb_ci, caller_id'


@pytest.mark.parametrize(servicenow_required_error_param, [
    ('',  '',  '',  '',  '',  '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', '',  '',  '',  '',  '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', '',  '',  '',  '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', '',  '',  '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', '',  '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', '',  ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', 'f', ''  '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', 'f', 'g' '',  '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', 'f', 'g' 'h', '',  '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', 'f', 'g' 'h', 'i', '',  '', 'Missing required option(s): ' + servicenow_required_error_excepted),
    ('a', 'b', 'c', 'd', 'e', 'f', 'g' 'h', 'i', 'j', 'k',
        {
            "type": "ServiceNow",
            "self.servicenow_rest_url": 'c'
        }),
])
def test_servicenow_required_error(username, password, servicenow_rest_url, short_description, comments,
                                   assignment_group, category, subcategory, cmdb_ci, caller_id, expected_data):
    try:
        rule = {
            'name': 'Test servicenow Rule',
            'type': 'any',
            'alert': []
        }

        if username:
            rule['username'] = username
        if password:
            rule['password'] = password
        if servicenow_rest_url:
            rule['servicenow_rest_url'] = servicenow_rest_url
        if short_description:
            rule['short_description'] = short_description
        if comments:
            rule['comments'] = comments
        if assignment_group:
            rule['assignment_group'] = assignment_group
        if category:
            rule['category'] = category
        if subcategory:
            rule['subcategory'] = subcategory
        if cmdb_ci:
            rule['cmdb_ci'] = cmdb_ci
        if caller_id:
            rule['caller_id'] = caller_id

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ServiceNowAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
