import json

import mock
import pytest
from requests import RequestException

from elastalert.alerters.victorops import VictorOpsAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


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
