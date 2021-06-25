import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.mattermost import MattermostAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_mattermost_proxy(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_proxy': 'https://proxy.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies={'https': 'https://proxy.url'}
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
    assert ('elastalert', logging.INFO, 'Alert sent to Mattermost') == caplog.record_tuples[0]


def test_mattermost_alert_text_only():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_not_alert_text_only():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'exclude_fields',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': []
            }
        ],
        'text': 'Test Mattermost Rule\n\n',
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_msg_fields():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_msg_fields': [
            {
                'title': 'Stack',
                'value': "{0} {1}",
                'short': False,
                'args': ["type", "msg.status_code"]
            },
            {
                'title': 'Name',
                'value': 'static field',
                'short': False
            }
        ],
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [
                    {'title': 'Stack', 'value': '<MISSING VALUE> <MISSING VALUE>', 'short': False},
                    {'title': 'Name', 'value': 'static field', 'short': False}
                ],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_icon_url_override():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_icon_url_override': 'http://xxxx/icon.png',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert',
        'icon_url': 'http://xxxx/icon.png'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_channel_override():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_channel_override': 'test channel',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert',
        'channel': 'test channel'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_ignore_ssl_errors():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_ignore_ssl_errors': True,
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=False,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_title_link():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_title': 'mattermost.title',
        'mattermost_title_link': 'http://title.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'title': 'mattermost.title',
                'title_link': 'http://title.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_footer():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_footer': 'Mattermost footer',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'footer': 'Mattermost footer'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_footer_icon():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_footer_icon': 'http://icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'footer_icon': 'http://icon.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_image_url():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_image_url': 'http://image.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'image_url': 'http://image.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_thumb_url():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_thumb_url': 'http://thumb.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'thumb_url': 'http://thumb.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_name():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_name': 'author name',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_name': 'author name'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_link():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_link': 'http://author.link.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_link': 'http://author.link.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_author_icon():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_icon': 'http://author.icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_icon': 'http://author.icon.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Mattermost Rule',
            'type': 'any',
            'alert_text_type': 'alert_text_only',
            'mattermost_webhook_url': 'http://xxxxx',
            'mattermost_msg_pretext': 'aaaaa',
            'mattermost_msg_color': 'danger',
            'mattermost_author_icon': 'http://author.icon.url',
            'alert': [],
            'alert_subject': 'Test Mattermost'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MattermostAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to Mattermost: ' in str(ea)


def test_mattermost_get_aggregation_summary_text__maximum_width():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_author_icon': 'http://author.icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    assert 75 == alert.get_aggregation_summary_text__maximum_width()


@pytest.mark.parametrize('msg_color, except_msg_color', [
    ('',        'danger'),
    ('danger',  'danger'),
    ('good',    'good'),
    ('warning', 'warning')
])
def test_mattermost_msg_color(msg_color, except_msg_color):
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_author_icon': 'http://author.icon.url',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }

    if msg_color:
        rule['mattermost_msg_color'] = msg_color

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': except_msg_color,
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n',
                'author_icon': 'http://author.icon.url'
            }
        ],
        'username': 'elastalert'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_getinfo():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)

    expected_data = {
        'type': 'mattermost',
        'mattermost_username_override': 'elastalert',
        'mattermost_webhook_url': ['http://xxxxx']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('mattermost_webhook_url, expected_data', [
    ('',  'Missing required option(s): mattermost_webhook_url'),
    ('http://xxxxx',
        {
            'type': 'mattermost',
            'mattermost_username_override': 'elastalert',
            'mattermost_webhook_url': ['http://xxxxx']
        }),
])
def test_mattermost_required_error(mattermost_webhook_url, expected_data):
    try:
        rule = {
            'name': 'Test Mattermost Rule',
            'type': 'any',
            'alert_text_type': 'alert_text_only',
            'alert': [],
            'alert_subject': 'Test Mattermost'
        }

        if mattermost_webhook_url:
            rule['mattermost_webhook_url'] = mattermost_webhook_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MattermostAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_mattermost_attach_kibana_discover_url_when_generated():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_attach_kibana_discover_url': True,
        'mattermost_webhook_url': 'http://please.dontgohere.mattermost',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'kibana_discover_url': 'http://localhost:5601/app/discover#/'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Rule: ',
                'color': 'danger',
                'title': 'Test Rule',
                'pretext': '',
                'fields': [],
                'text': 'Test Rule\n\n'
            },
            {
                'color': '#ec4b98',
                'title': 'Discover in Kibana',
                'title_link': 'http://localhost:5601/app/discover#/'
            }
        ], 'username': 'elastalert'
    }
    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_attach_kibana_discover_url_when_not_generated():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_attach_kibana_discover_url': True,
        'mattermost_webhook_url': 'http://please.dontgohere.mattermost',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Rule: ',
                'color': 'danger',
                'title': 'Test Rule',
                'pretext': '',
                'fields': [],
                'text': 'Test Rule\n\n'
            }
        ], 'username': 'elastalert'
    }
    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_kibana_discover_title():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_attach_kibana_discover_url': True,
        'mattermost_kibana_discover_title': 'Click to discover in Kibana',
        'mattermost_webhook_url': 'http://please.dontgohere.mattermost',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'kibana_discover_url': 'http://localhost:5601/app/discover#/'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Rule: ',
                'color': 'danger',
                'title': 'Test Rule',
                'pretext': '',
                'fields': [],
                'text': 'Test Rule\n\n'
            },
            {
                'color': '#ec4b98',
                'title': 'Click to discover in Kibana',
                'title_link': 'http://localhost:5601/app/discover#/'
            }
        ], 'username': 'elastalert'
    }
    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_kibana_discover_color():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_attach_kibana_discover_url': True,
        'mattermost_kibana_discover_color': 'blue',
        'mattermost_webhook_url': 'http://please.dontgohere.mattermost',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'kibana_discover_url': 'http://localhost:5601/app/discover#/'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Rule: ',
                'color': 'danger',
                'title': 'Test Rule',
                'pretext': '',
                'fields': [],
                'text': 'Test Rule\n\n'
            },
            {
                'color': 'blue',
                'title': 'Discover in Kibana',
                'title_link': 'http://localhost:5601/app/discover#/'
            }
        ], 'username': 'elastalert'
    }
    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data


def test_mattermost_username_override():
    rule = {
        'name': 'Test Mattermost Rule',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'mattermost_webhook_url': 'http://xxxxx',
        'mattermost_msg_pretext': 'aaaaa',
        'mattermost_msg_color': 'danger',
        'mattermost_username_override': 'test user',
        'alert': [],
        'alert_subject': 'Test Mattermost'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MattermostAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'attachments': [
            {
                'fallback': 'Test Mattermost: aaaaa',
                'color': 'danger',
                'title': 'Test Mattermost',
                'pretext': 'aaaaa',
                'fields': [],
                'text': 'Test Mattermost Rule\n\n'
            }
        ], 'username': 'test user'
    }

    mock_post_request.assert_called_once_with(
        rule['mattermost_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        verify=True,
        proxies=None
    )

    actual_data = json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert expected_data == actual_data
