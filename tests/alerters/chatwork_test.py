import logging
import pytest

from unittest import mock

from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerters.chatwork import ChatworkAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_chatwork(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'body': 'Test Chatwork Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies=None,
        auth=None
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Alert sent to Chatwork room xxxx2') == caplog.record_tuples[0]


def test_chatwork_proxy():
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'chatwork_proxy': 'http://proxy.url',
        'chatwork_proxy_login': 'admin',
        'chatwork_proxy_pass': 'password',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'body': 'Test Chatwork Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data


def test_chatwork_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Chatwork Rule',
            'type': 'any',
            'chatwork_apikey': 'xxxx1',
            'chatwork_room_id': 'xxxx2',
            'chatwork_proxy': 'http://proxy.url',
            'chatwork_proxy_login': 'admin',
            'chatwork_proxy_pass': 'password',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ChatworkAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to Chattwork: . Details: ' in str(ea)


def test_chatwork_getinfo():
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)

    expected_data = {
        "type": "chatwork",
        "chatwork_room_id": "xxxx2"
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('chatwork_apikey, chatwork_room_id, expected_data', [
    ('',      '',      'Missing required option(s): chatwork_apikey, chatwork_room_id'),
    ('xxxx1', '',      'Missing required option(s): chatwork_apikey, chatwork_room_id'),
    ('',      'xxxx2', '1Missing required option(s): chatwork_apikey, chatwork_room_id'),
    ('xxxx1', 'xxxx2',
        {
            "type": "chatwork",
            "chatwork_room_id": "xxxx2"
        }),
])
def test_chatwork_required_error(chatwork_apikey, chatwork_room_id, expected_data):
    try:
        rule = {
            'name': 'Test Chatwork Rule',
            'type': 'any',
            'alert': []
        }

        if chatwork_apikey:
            rule['chatwork_apikey'] = chatwork_apikey

        if chatwork_room_id:
            rule['chatwork_room_id'] = chatwork_room_id

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ChatworkAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_chatwork_maxlength():
    rule = {
        'name': 'Test Chatwork Rule' + ('a' * 2069),
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'body': 'Test Chatwork Rule' + ('a' * 1932) +
        '\n *message was cropped according to chatwork embed description limits!*'
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies=None,
        auth=None
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data


def test_chatwork_matchs():
    rule = {
        'name': 'Test Chatwork Rule',
        'type': 'any',
        'chatwork_apikey': 'xxxx1',
        'chatwork_room_id': 'xxxx2',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ChatworkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match, match])
    expected_data = {
        'body': 'Test Chatwork Rule\n' +
                '\n' +
                '@timestamp: 2021-01-01T00:00:00\n' +
                'somefield: foobarbaz\n' +
                '\n' +
                '----------------------------------------\n' +
                'Test Chatwork Rule\n' +
                '\n' +
                '@timestamp: 2021-01-01T00:00:00\n' +
                'somefield: foobarbaz\n' +
                '\n' +
                '----------------------------------------\n',
    }

    mock_post_request.assert_called_once_with(
        'https://api.chatwork.com/v2/rooms/xxxx2/messages',
        params=mock.ANY,
        headers={'X-ChatWorkToken': 'xxxx1'},
        proxies=None,
        auth=None
    )

    actual_data = mock_post_request.call_args_list[0][1]['params']
    assert expected_data == actual_data
