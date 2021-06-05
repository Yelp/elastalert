from unittest import mock
import pytest
from requests import RequestException

from elastalert.alerters.line import LineNotifyAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_line_notify():
    rule = {
        'name': 'Test LineNotify Rule',
        'type': 'any',
        'linenotify_access_token': 'xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = LineNotifyAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'message': 'Test LineNotify Rule\n\n@timestamp: 2021-01-01T00:00:00\nsomefield: foobarbaz\n'
    }

    mock_post_request.assert_called_once_with(
        'https://notify-api.line.me/api/notify',
        data=mock.ANY,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer {}'.format('xxxxx')
        }
    )

    actual_data = mock_post_request.call_args_list[0][1]['data']
    assert expected_data == actual_data


def test_line_notify_ea_exception():
    try:
        rule = {
            'name': 'Test LineNotify Rule',
            'type': 'any',
            'linenotify_access_token': 'xxxxx',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = LineNotifyAlerter(rule)
        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    except EAException:
        assert True


def test_line_getinfo():
    rule = {
        'name': 'Test LineNotify Rule',
        'type': 'any',
        'linenotify_access_token': 'xxxxx',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = LineNotifyAlerter(rule)

    expected_data = {
        "type": "linenotify",
        "linenotify_access_token": 'xxxxx'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('linenotify_access_token, expected_data', [
    ('',  'Missing required option(s): linenotify_access_token'),
    ('xxxxx',
        {
            "type": "linenotify",
            "linenotify_access_token": 'xxxxx'
        }),
])
def test_line_required_error(linenotify_access_token, expected_data):
    try:
        rule = {
            'name': 'Test LineNotify Rule',
            'type': 'any',
            'alert': []
        }

        if linenotify_access_token != '':
            rule['linenotify_access_token'] = linenotify_access_token

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = LineNotifyAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
