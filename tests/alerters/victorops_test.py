import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.victorops import VictorOpsAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_victorops(caplog):
    caplog.set_level(logging.INFO)
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
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Trigger sent to VictorOps') == caplog.record_tuples[0]


def test_victorops_no_title(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': 'INFO',
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
        'entity_display_name': rule['name'],
        'monitoring_tool': 'ElastAlert',
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Trigger sent to VictorOps') == caplog.record_tuples[0]


def test_victorops_proxy():
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
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_victorops_ea_exception():
    with pytest.raises(EAException) as ea:
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
    assert 'Error posting to VictorOps:' in str(ea)


def test_victorops_entity_id():
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': 'INFO',
        'victorops_entity_display_name': 'no entity display name',
        'victorops_entity_id': '12345',
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
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        'entity_id': '12345',
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


@pytest.mark.parametrize('message_type, except_message_type', [
    ('INFO', 'INFO'),
    ('WARNING', 'WARNING'),
    ('ACKNOWLEDGEMENT', 'ACKNOWLEDGEMENT'),
    ('CRITICAL', 'CRITICAL'),
    ('RECOVERY', 'RECOVERY')
])
def test_victorops_message_type(message_type, except_message_type):
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': message_type,
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
        'message_type': except_message_type,
        'entity_display_name': rule['victorops_entity_display_name'],
        'monitoring_tool': 'ElastAlert',
        'state_message': 'Test VictorOps Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }

    mock_post_request.assert_called_once_with(
        'https://alert.victorops.com/integrations/generic/20131114/alert/xxxx1/xxxx2',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_victorops_getinfo():
    rule = {
        'name': 'Test VictorOps Rule',
        'type': 'any',
        'victorops_api_key': 'xxxx1',
        'victorops_routing_key': 'xxxx2',
        'victorops_message_type': 'INFO',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = VictorOpsAlerter(rule)

    expected_data = {
        'type': 'victorops',
        'victorops_routing_key': 'xxxx2'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('victorops_api_key, victorops_routing_key, victorops_message_type, expected_data', [
    ('',      '',      '',     'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('xxxx1', '',      '',     'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('',      'xxxx2', '',     'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('',      '',      'INFO', 'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('xxxx1', 'xxxx2', '',     'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('xxxx1', '',      'INFO', 'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('',      'xxxx2', 'INFO', 'Missing required option(s): victorops_api_key, victorops_routing_key, victorops_message_type'),
    ('xxxx1', 'xxxx2', 'INFO',
        {
            'type': 'victorops',
            'victorops_routing_key': 'xxxx2'
        }),
])
def test_victoropst_required_error(victorops_api_key, victorops_routing_key, victorops_message_type, expected_data):
    try:
        rule = {
            'name': 'Test VictorOps Rule',
            'type': 'any',
            'alert': []
        }

        if victorops_api_key:
            rule['victorops_api_key'] = victorops_api_key

        if victorops_routing_key:
            rule['victorops_routing_key'] = victorops_routing_key

        if victorops_message_type:
            rule['victorops_message_type'] = victorops_message_type

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = VictorOpsAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
