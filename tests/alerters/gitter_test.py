import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.gitter import GitterAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


@pytest.mark.parametrize('msg_level, except_msg_level', [
    ('',      'error'),
    ('error', 'error'),
    ('info',  'info')
])
def test_gitter_msg_level(msg_level, except_msg_level, caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'alert': []
    }

    if msg_level:
        rule['gitter_msg_level'] = msg_level

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
        'level': except_msg_level
    }

    mock_post_request.assert_called_once_with(
        rule['gitter_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Alert sent to Gitter') == caplog.record_tuples[0]


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
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_gitter_ea_exception():
    with pytest.raises(EAException) as ea:
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
    assert 'Error posting to Gitter: ' in str(ea)


def test_gitter_getinfo():
    rule = {
        'name': 'Test Gitter Rule',
        'type': 'any',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GitterAlerter(rule)

    expected_data = {
        'type': 'gitter',
        'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('gitter_webhook_url, expected_data', [
    ('', 'Missing required option(s): gitter_webhook_url'),
    ('https://webhooks.gitter.im/e/xxxxx',
        {
           'type': 'gitter',
           'gitter_webhook_url': 'https://webhooks.gitter.im/e/xxxxx'
        })
])
def test_gitter_required_error(gitter_webhook_url, expected_data):
    try:
        rule = {
            'name': 'Test Gitter Rule',
            'type': 'any',
            'alert': []
        }

        if gitter_webhook_url:
            rule['gitter_webhook_url'] = gitter_webhook_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = GitterAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
