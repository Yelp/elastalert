import json

import mock
import pytest
from requests import RequestException

from elastalert.alerters.gitter import GitterAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


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
