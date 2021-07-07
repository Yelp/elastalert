import json
import logging
import pytest

from unittest import mock

from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerters.discord import DiscordAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_discord(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'discord_embed_footer': 'footer',
        'discord_embed_icon_url': 'http://xxxx/image.png',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
                'color': 0xffffff,
                'footer': {
                    'text': 'footer',
                    'icon_url': 'http://xxxx/image.png'
                }
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Alert sent to the webhook http://xxxxxxx') == caplog.record_tuples[0]


def test_discord_not_footer():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_proxy():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'discord_proxy': 'http://proxy.url',
        'discord_proxy_login': 'admin',
        'discord_proxy_password': 'password',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_description_maxlength():
    rule = {
        'name': 'Test Discord Rule' + ('a' * 2069),
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule' + ('a' * 1933) +
                               '\n *message was cropped according to discord embed description limits!*',
                'color': 0xffffff
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_discord_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Discord Rule' + ('a' * 2069),
            'type': 'any',
            'discord_webhook_url': 'http://xxxxxxx',
            'discord_emoji_title': ':warning:',
            'discord_embed_color': 0xffffff,
            'alert': [],
            'alert_subject': 'Test Discord'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DiscordAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to Discord: . Details: ' in str(ea)


def test_discord_getinfo():
    rule = {
        'name': 'Test Discord Rule' + ('a' * 2069),
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)

    expected_data = {
        'type': 'discord',
        'discord_webhook_url': 'http://xxxxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('discord_webhook_url, expected_data', [
    ('', 'Missing required option(s): discord_webhook_url'),
    ('http://xxxxxxx',
        {
            'type': 'discord',
            'discord_webhook_url': 'http://xxxxxxx'
        }),
])
def test_discord_required_error(discord_webhook_url, expected_data):
    try:
        rule = {
            'name': 'Test Discord Rule' + ('a' * 2069),
            'type': 'any',
            'alert': [],
            'alert_subject': 'Test Discord'
        }

        if discord_webhook_url:
            rule['discord_webhook_url'] = discord_webhook_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DiscordAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_discord_matches():
    rule = {
        'name': 'Test Discord Rule',
        'type': 'any',
        'discord_webhook_url': 'http://xxxxxxx',
        'discord_emoji_title': ':warning:',
        'discord_embed_color': 0xffffff,
        'discord_embed_footer': 'footer',
        'discord_embed_icon_url': 'http://xxxx/image.png',
        'alert': [],
        'alert_subject': 'Test Discord'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DiscordAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match, match])

    expected_data = {
        'content': ':warning: Test Discord :warning:',
        'embeds':
            [{
                'description': 'Test Discord Rule\n' +
                               '\n' +
                               '@timestamp: 2021-01-01T00:00:00\n' +
                               'somefield: foobarbaz\n' +
                               '\n' +
                               '----------------------------------------\n' +
                               'Test Discord Rule\n' +
                               '\n' +
                               '@timestamp: 2021-01-01T00:00:00\n' +
                               'somefield: foobarbaz\n' +
                               '\n' +
                               '----------------------------------------\n',
                'color': 0xffffff,
                'footer': {
                    'text': 'footer',
                    'icon_url': 'http://xxxx/image.png'
                }
            }]
    }

    mock_post_request.assert_called_once_with(
        rule['discord_webhook_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json'},
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
