import json

import mock
import pytest
from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerters.telegram import TelegramAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_telegram():
    rule = {
        'name': 'Test Telegram Rule',
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule* ⚠ ```\nTest Telegram Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_proxy():
    rule = {
        'name': 'Test Telegram Rule',
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'telegram_proxy': 'http://proxy.url',
        'telegram_proxy_login': 'admin',
        'telegram_proxy_pass': 'password',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule* ⚠ ```\nTest Telegram Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_text_maxlength():
    rule = {
        'name': 'Test Telegram Rule' + ('a' * 3985),
        'type': 'any',
        'telegram_bot_token': 'xxxxx1',
        'telegram_room_id': 'xxxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TelegramAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'chat_id': rule['telegram_room_id'],
        'text': '⚠ *Test Telegram Rule' + ('a' * 3979) +
                '\n⚠ *message was cropped according to telegram limits!* ⚠ ```',
        'parse_mode': 'markdown',
        'disable_web_page_preview': True
    }

    mock_post_request.assert_called_once_with(
        'https://api.telegram.org/botxxxxx1/sendMessage',
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_telegram_ea_exception():
    try:
        rule = {
            'name': 'Test Telegram Rule' + ('a' * 3985),
            'type': 'any',
            'telegram_bot_token': 'xxxxx1',
            'telegram_room_id': 'xxxxx2',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = TelegramAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True
