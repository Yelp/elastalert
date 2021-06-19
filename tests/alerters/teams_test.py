import json
import logging

from unittest import mock
import pytest
from requests import RequestException

from elastalert.alerters.teams import MsTeamsAlerter
from elastalert.alerts import BasicMatchString
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_ms_teams(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'text': BasicMatchString(rule, match).__str__()
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'Alert sent to MS Teams') == caplog.record_tuples[0]


def test_ms_teams_uses_color_and_fixed_width_text():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'ms_teams_alert_fixed_width': True,
        'ms_teams_theme_color': '#124578',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    body = BasicMatchString(rule, match).__str__()
    body = body.replace('`', "'")
    body = "```{0}```".format('```\n\n```'.join(x for x in body.split('\n'))).replace('\n``````', '')
    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'themeColor': '#124578',
        'text': body
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies=None
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_ms_teams_proxy():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'ms_teams_alert_summary': 'Alert from ElastAlert',
        'ms_teams_proxy': 'https://test.proxy.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)
    match = {
        '@timestamp': '2016-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'summary': rule['ms_teams_alert_summary'],
        'title': rule['alert_subject'],
        'text': BasicMatchString(rule, match).__str__()
    }
    mock_post_request.assert_called_once_with(
        rule['ms_teams_webhook_url'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
        proxies={'https': rule['ms_teams_proxy']}
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_ms_teams_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'ms_teams_webhook_url': 'http://test.webhook.url',
            'ms_teams_alert_summary': 'Alert from ElastAlert',
            'alert_subject': 'Cool subject',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MsTeamsAlerter(rule)
        match = {
            '@timestamp': '2016-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to ms teams: ' in str(ea)


def test_ms_teams_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'ms_teams_webhook_url': 'http://test.webhook.url',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = MsTeamsAlerter(rule)

    expected_data = {
        'type': 'ms_teams',
        'ms_teams_webhook_url': ['http://test.webhook.url']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('ms_teams_webhook_url, expected_data', [
    ('', 'Missing required option(s): ms_teams_webhook_url'),
    ('http://test.webhook.url',
        {
            'type': 'ms_teams',
            'ms_teams_webhook_url': ['http://test.webhook.url']
        })
])
def test_ms_teams_required_error(ms_teams_webhook_url, expected_data):
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'alert': []
        }

        if ms_teams_webhook_url != '':
            rule['ms_teams_webhook_url'] = ms_teams_webhook_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = MsTeamsAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
