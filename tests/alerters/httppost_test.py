import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.httppost import HTTPPostAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_http_alerter_with_payload(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_payload': {'posted_name': 'somefield'},
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_all_values():
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_payload': {'posted_name': 'somefield'},
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_all_values': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'foobarbaz',
        'name': 'somestaticname',
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_without_payload():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_proxy():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies={'https': 'http://proxy.url'},
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_timeout():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_timeout': 20,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=20,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_headers():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'http_post_headers': {'authorization': 'Basic 123dr3234'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'authorization': 'Basic 123dr3234'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


@pytest.mark.parametrize('ca_certs, ignore_ssl_errors, excpet_verify', [
    ('',    '',    True),
    ('',    True,  False),
    ('',    False, True),
    (True,  '',    True),
    (True,  True,  True),
    (True,  False, True),
    (False, '',    True),
    (False, True,  False),
    (False, False, True)
])
def test_http_alerter_post_ca_certs(ca_certs, ignore_ssl_errors, excpet_verify):
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'http_post_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    if ca_certs:
        rule['http_post_ca_certs'] = ca_certs

    if ignore_ssl_errors:
        rule['http_post_ignore_ssl_errors'] = ignore_ssl_errors

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
        'name': 'somestaticname'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=excpet_verify
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_post_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test HTTP Post Alerter Without Payload',
            'type': 'any',
            'http_post_url': 'http://test.webhook.url',
            'http_post_static_payload': {'name': 'somestaticname'},
            'http_post_ca_certs': False,
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPostAlerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting HTTP Post alert: ' in str(ea)


def test_http_getinfo():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post_url': 'http://test.webhook.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPostAlerter(rule)

    expected_data = {
        'type': 'http_post',
        'http_post_webhook_url': ['http://test.webhook.url']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('http_post_url, expected_data', [
    ('',  'Missing required option(s): http_post_url'),
    ('http://test.webhook.url',
        {
            'type': 'http_post',
            'http_post_webhook_url': ['http://test.webhook.url']
        }),
])
def test_http_required_error(http_post_url, expected_data):
    try:
        rule = {
            'name': 'Test HTTP Post Alerter Without Payload',
            'type': 'any',
            'alert': []
        }

        if http_post_url:
            rule['http_post_url'] = http_post_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPostAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
