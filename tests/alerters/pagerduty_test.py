import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.pagerduty import PagerDutyAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_pagerduty_alerter():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': '',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/generic/2010-04-15/create_event.json',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_class_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'somefield',
        'pagerduty_v2_payload_class_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'somefield',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_component_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'somefield',
        'pagerduty_v2_payload_component_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'somefield',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_group_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'somefield',
        'pagerduty_v2_payload_group_args': ['@timestamp', 'somefield'],
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'somefield',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_source_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'somefield',
        'pagerduty_v2_payload_source_args': ['@timestamp', 'somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'somefield',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_custom_details():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'pagerduty_v2_payload_custom_details': {'a': 'somefield', 'c': 'f'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'a': 'foobarbaz',
                'c': None,
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_payload_include_all_info():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'pagerduty_v2_payload_include_all_info': False,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {},
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_incident_key():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom key',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom key',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_incident_key_with_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': 'Hungry kittens',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['somefield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Hungry kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject_with_args():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinky',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinky kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinky\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_custom_alert_subject_with_args_specifying_trigger():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_event_type': 'trigger',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinkiest',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinkiest kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinkiest\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_proxy():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_event_type': 'trigger',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'pagerduty_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'Stinkiest',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinkiest kittens',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: Stinkiest\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'},
                                              proxies={'https': 'http://proxy.url'})
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test PD Rule',
            'type': 'any',
            'alert_subject': '{0} kittens',
            'alert_subject_args': ['somefield'],
            'pagerduty_service_key': 'magicalbadgers',
            'pagerduty_event_type': 'trigger',
            'pagerduty_client_name': 'ponies inc.',
            'pagerduty_incident_key': 'custom {0}',
            'pagerduty_incident_key_args': ['someotherfield'],
            'pagerduty_proxy': 'http://proxy.url',
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerDutyAlerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'somefield': 'Stinkiest',
            'someotherfield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to pagerduty: ' in str(ea)


@pytest.mark.parametrize('severity, except_severity', [
    ('', 'critical'),
    ('critical', 'critical'),
    ('error', 'error'),
    ('warning', 'warning'),
    ('info', 'info')
])
def test_pagerduty_alerter_v2_payload_severity(severity, except_severity):
    rule = {}
    if severity == '':
        rule = {
            'name': 'Test PD Rule',
            'type': 'any',
            'pagerduty_service_key': 'magicalbadgers',
            'pagerduty_client_name': 'ponies inc.',
            'pagerduty_api_version': 'v2',
            'pagerduty_v2_payload_class': 'ping failure',
            'pagerduty_v2_payload_component': 'mysql',
            'pagerduty_v2_payload_group': 'app-stack',
            'pagerduty_v2_payload_source': 'mysql.host.name',
            'alert': []
        }
    else:
        rule = {
            'name': 'Test PD Rule',
            'type': 'any',
            'pagerduty_service_key': 'magicalbadgers',
            'pagerduty_client_name': 'ponies inc.',
            'pagerduty_api_version': 'v2',
            'pagerduty_v2_payload_class': 'ping failure',
            'pagerduty_v2_payload_component': 'mysql',
            'pagerduty_v2_payload_group': 'app-stack',
            'pagerduty_v2_payload_severity': severity,
            'pagerduty_v2_payload_source': 'mysql.host.name',
            'alert': []
        }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': except_severity,
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
            },
            'timestamp': '2017-01-01T00:00:00'
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_getinfo():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)

    expected_data = {
        'type': 'pagerduty',
        'pagerduty_client_name': 'ponies inc.'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('pagerduty_service_key, pagerduty_client_name, expected_data', [
    ('',       '',       'Missing required option(s): pagerduty_service_key, pagerduty_client_name'),
    ('xxxxx1', '',       'Missing required option(s): pagerduty_service_key, pagerduty_client_name'),
    ('',       'xxxxx2', 'Missing required option(s): pagerduty_service_key, pagerduty_client_name'),
    ('xxxxx1', 'xxxxx2',
        {
            'type': 'pagerduty',
            'pagerduty_client_name': 'xxxxx2'
        }),
])
def test_pagerduty_required_error(pagerduty_service_key, pagerduty_client_name, expected_data):
    try:
        rule = {
            'name': 'Test PD Rule',
            'type': 'any',
            'alert': []
        }

        if pagerduty_service_key:
            rule['pagerduty_service_key'] = pagerduty_service_key

        if pagerduty_client_name:
            rule['pagerduty_client_name'] = pagerduty_client_name

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = PagerDutyAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


@pytest.mark.parametrize('pagerduty_event_type, excepted_pagerduty_event_type, excepted_log_message', [
    ('',            'trigger',     'Trigger sent to PagerDuty'),
    ('trigger',     'trigger',     'Trigger sent to PagerDuty'),
    ('resolve',     'resolve',     'Resolve sent to PagerDuty'),
    ('acknowledge', 'acknowledge', 'acknowledge sent to PagerDuty')
])
def test_pagerduty_alerter_event_type(pagerduty_event_type, excepted_pagerduty_event_type, excepted_log_message, caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'alert': []
    }

    if pagerduty_event_type:
        rule['pagerduty_event_type'] = pagerduty_event_type

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Test PD Rule',
        'details': {
            'information': 'Test PD Rule\n\n@timestamp: 2017-01-01T00:00:00\nsomefield: foobarbaz\n'
        },
        'event_type': excepted_pagerduty_event_type,
        'incident_key': '',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/generic/2010-04-15/create_event.json',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, excepted_log_message) == caplog.record_tuples[0]


def test_pagerduty_alerter_match_timestamp_none():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'alert_subject': '{0} kittens',
        'alert_subject_args': ['somefield'],
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_event_type': 'trigger',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_incident_key': 'custom {0}',
        'pagerduty_incident_key_args': ['someotherfield'],
        'pagerduty_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        'somefield': 'Stinkiest',
        'someotherfield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'description': 'Stinkiest kittens',
        'details': {
            'information': 'Test PD Rule\n\nsomefield: Stinkiest\nsomeotherfield: foobarbaz\n'
        },
        'event_type': 'trigger',
        'incident_key': 'custom foobarbaz',
        'service_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with(alert.url, data=mock.ANY, headers={'content-type': 'application/json'},
                                              proxies={'https': 'http://proxy.url'})
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_pagerduty_alerter_v2_match_timestamp_none():
    rule = {
        'name': 'Test PD Rule',
        'type': 'any',
        'pagerduty_service_key': 'magicalbadgers',
        'pagerduty_client_name': 'ponies inc.',
        'pagerduty_api_version': 'v2',
        'pagerduty_v2_payload_class': 'ping failure',
        'pagerduty_v2_payload_component': 'mysql',
        'pagerduty_v2_payload_group': 'app-stack',
        'pagerduty_v2_payload_severity': 'error',
        'pagerduty_v2_payload_source': 'mysql.host.name',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = PagerDutyAlerter(rule)
    match = {
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'client': 'ponies inc.',
        'payload': {
            'class': 'ping failure',
            'component': 'mysql',
            'group': 'app-stack',
            'severity': 'error',
            'source': 'mysql.host.name',
            'summary': 'Test PD Rule',
            'custom_details': {
                'information': 'Test PD Rule\n\nsomefield: foobarbaz\n'
            }
        },
        'event_action': 'trigger',
        'dedup_key': '',
        'routing_key': 'magicalbadgers',
    }
    mock_post_request.assert_called_once_with('https://events.pagerduty.com/v2/enqueue',
                                              data=mock.ANY, headers={'content-type': 'application/json'}, proxies=None)
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
