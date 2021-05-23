import json

import mock
import pytest
from requests import RequestException

from elastalert.alerters.rocketchat import RocketChatAlerter
from elastalert.alerts import BasicMatchString
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_rocketchat_uses_custom_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_uses_rule_name_when_custom_title_is_not_provided():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': ['http://please.dontgohere.rocketchat'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_username_override():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_username_override': 'test elastalert',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'test elastalert',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_chat_channel():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': ['http://please.dontgohere.rocketchat'],
        'rocket_chat_channel_override': '#test-alert',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '#test-alert',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_uses_list_of_custom_rocket_chat_channel():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': ['http://please.dontgohere.rocketchat'],
        'rocket_chat_channel_override': ['#test-alert', '#test-alert2'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data1 = {
        'username': 'elastalert2',
        'channel': '#test-alert',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    expected_data2 = {
        'username': 'elastalert2',
        'channel': '#test-alert2',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_with(
        rule['rocket_chat_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data1 == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data2 == json.loads(mock_post_request.call_args_list[1][1]['data'])


def test_rocketchat_emoji_override():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': ['http://please.dontgohere.rocketchat'],
        'rocket_chat_emoji_override': ':shushing_face:',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':shushing_face:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['name'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'][0],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_msg_color_good():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_username_override': 'elastalert2',
        'rocket_chat_msg_color': 'good',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'good',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_msg_color_warning():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_username_override': 'elastalert2',
        'rocket_chat_msg_color': 'warning',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'warning',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_text_string():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_username_override': 'elastalert2',
        'rocket_chat_text_string': 'text str',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': 'text str'
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_proxy():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_proxy': 'http://proxy.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields': []
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': rule['rocket_chat_proxy']}
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_alert_fields():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
        'rocket_chat_username_override': 'elastalert2',
        'rocket_chat_alert_fields': [
            {
                'title': 'Host',
                'value': 'somefield',
                'short': 'true'
            },
            {
                'title': 'Sensors',
                'value': '@timestamp',
                'short': 'true'
            }
        ],
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = RocketChatAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'username': 'elastalert2',
        'channel': '',
        'emoji': ':ghost:',
        'attachments': [
            {
                'color': 'danger',
                'title': rule['alert_subject'],
                'text': BasicMatchString(rule, match).__str__(),
                'fields':
                [
                    {
                        'short': 'true',
                        'title': 'Host',
                        'value': 'foobarbaz'
                    },
                    {
                        'short': 'true',
                        'title': 'Sensors',
                        'value': '2021-01-01T00:00:00'
                    }
                ],
            }
        ],
        'text': ''
    }
    mock_post_request.assert_called_once_with(
        rule['rocket_chat_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_rocketchat_required_options_key_error():
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = RocketChatAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])
    except KeyError:
        assert True


def test_rocketchat_msg_color_key_error():
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
            'rocket_chat_msg_color': 'abc',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = RocketChatAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])
    except KeyError:
        assert True


def test_rocketchat_ea_exception():
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'rocket_chat_webhook_url': 'http://please.dontgohere.rocketchat',
            'rocket_chat_username_override': 'elastalert2',
            'rocket_chat_msg_pretext': 'pretext value',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = RocketChatAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True
