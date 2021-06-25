import json
import logging
import pytest

from unittest import mock

from requests import RequestException
from requests.auth import HTTPProxyAuth

from elastalert.alerters.dingtalk import DingTalkAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_dingtalk_text(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'text',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'text',
        'text': {'content': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'}
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Trigger sent to dingtalk') == caplog.record_tuples[0]


def test_dingtalk_markdown():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'markdown',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'markdown',
        'markdown': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_single_action_card():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'single_action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'singleTitle': rule['dingtalk_single_title'],
            'singleURL': rule['dingtalk_single_url']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_action_card():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'dingtalk_btn_orientation': '1',
        'dingtalk_btns': [
            {
                'title': 'test1',
                'actionURL': 'https://xxxxx0/'
            },
            {
                'title': 'test2',
                'actionURL': 'https://xxxxx1/'
            }
        ],
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'btnOrientation': rule['dingtalk_btn_orientation'],
            'btns': rule['dingtalk_btns']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_action_card2():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies=None,
        auth=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_proxy():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'dingtalk_msgtype': 'action_card',
        'dingtalk_single_title': 'elastalert',
        'dingtalk_single_url': 'http://xxxxx2',
        'dingtalk_btn_orientation': '1',
        'dingtalk_btns': [
            {
                'title': 'test1',
                'actionURL': 'https://xxxxx0/'
            },
            {
                'title': 'test2',
                'actionURL': 'https://xxxxx1/'
            }
        ],
        'dingtalk_proxy': 'http://proxy.url',
        'dingtalk_proxy_login': 'admin',
        'dingtalk_proxy_pass': 'password',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'msgtype': 'actionCard',
        'actionCard': {
            'title': 'Test DingTalk',
            'text': 'Test DingTalk Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n',
            'btnOrientation': rule['dingtalk_btn_orientation'],
            'btns': rule['dingtalk_btns']
        }
    }

    mock_post_request.assert_called_once_with(
        'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json;charset=utf-8'
        },
        proxies={'https': 'http://proxy.url'},
        auth=HTTPProxyAuth('admin', 'password')
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_dingtalk_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test DingTalk Rule',
            'type': 'any',
            'dingtalk_access_token': 'xxxxxxx',
            'dingtalk_msgtype': 'action_card',
            'dingtalk_single_title': 'elastalert',
            'dingtalk_single_url': 'http://xxxxx2',
            'dingtalk_btn_orientation': '1',
            'dingtalk_btns': [
                {
                    'title': 'test1',
                    'actionURL': 'https://xxxxx0/'
                },
                {
                    'title': 'test2',
                    'actionURL': 'https://xxxxx1/'
                }
            ],
            'dingtalk_proxy': 'http://proxy.url',
            'dingtalk_proxy_login': 'admin',
            'dingtalk_proxy_pass': 'password',
            'alert': [],
            'alert_subject': 'Test DingTalk'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DingTalkAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to dingtalk: ' in str(ea)


def test_dingtalk_getinfo():
    rule = {
        'name': 'Test DingTalk Rule',
        'type': 'any',
        'dingtalk_access_token': 'xxxxxxx',
        'alert': [],
        'alert_subject': 'Test DingTalk'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DingTalkAlerter(rule)

    expected_data = {
        'type': 'dingtalk',
        "dingtalk_webhook_url": 'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('dingtalk_access_token, expected_data', [
    ('',        'Missing required option(s): dingtalk_access_token'),
    ('xxxxxxx',
        {
            'type': 'dingtalk',
            "dingtalk_webhook_url": 'https://oapi.dingtalk.com/robot/send?access_token=xxxxxxx'
        }),
])
def test_dingtalk_required_error(dingtalk_access_token, expected_data):
    try:
        rule = {
            'name': 'Test DingTalk Rule',
            'type': 'any',
            'alert': [],
            'alert_subject': 'Test DingTalk'
        }

        if dingtalk_access_token:
            rule['dingtalk_access_token'] = dingtalk_access_token

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = DingTalkAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
