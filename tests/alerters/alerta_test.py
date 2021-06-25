import datetime
import json
import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.alerta import AlertaAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_alerta_no_auth(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_api_skip_ssl': True,
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["%(key)s", "%(logdate)s", "%(sender_ip)s"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe %(hostname)s is UP at %(logdate)s GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        # 'key': ---- missing field on purpose, to verify that simply the text is left empty
        # 'logdate': ---- missing field on purpose, to verify that simply the text is left empty
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "<MISSING VALUE>", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        headers={
            'content-type': 'application/json'},
        verify=False
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'Alert sent to Alerta') == caplog.record_tuples[0]


def test_alerta_auth():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'alerta_api_key': '123456789ABCDEF',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_severity': "debug",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json',
            'Authorization': 'Key {}'.format(rule['alerta_api_key'])})


def test_alerta_new_style():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        # 'key': ---- missing field on purpose, to verify that simply the text is left empty
        # 'logdate': ---- missing field on purpose, to verify that simply the text is left empty
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_use_qk_as_resource():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_use_qk_as_resource': True,
        'query_key': 'hostname',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "aProbe",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_timeout():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_timeout': 86450,
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86450,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_type():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_type': 'elastalert2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert2",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_resource():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_resource': 'elastalert2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert2",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_service():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_service': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert2"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_environment():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_environment': 'Production2',
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": [],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production2",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_tags():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_tags': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": ['elastalert2'],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "createTime": "2014-10-10T00:00:00.000000Z",
        "environment": "Production",
        "rawData": "Test Alerta rule!\n\n@timestamp: 2014-10-10T00:00:00\nhostname: aProbe\nsender_ip: 1.1.1.1\n",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )
    assert expected_data == json.loads(
        mock_post_request.call_args_list[0][1]['data'])


def test_alerta_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Alerta rule!',
            'alerta_api_url': 'http://elastalerthost:8080/api/alert',
            'timeframe': datetime.timedelta(hours=1),
            'timestamp_field': '@timestamp',
            'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
            'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
            'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
            'alerta_event': "ProbeUP",
            'alerta_group': "Health",
            'alerta_origin': "ElastAlert 2",
            'alerta_severity': "debug",
            'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
            'alerta_value': "UP",
            'type': 'any',
            'alerta_use_match_timestamp': True,
            'alerta_tags': ['elastalert2'],
            'alert': 'alerta'
        }

        match = {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = AlertaAlerter(rule)
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting to Alerta: ' in str(ea)


def test_alerta_getinfo():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'type': 'any',
        'alert': 'alerta'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)

    expected_data = {
        'type': 'alerta',
        'alerta_url': 'http://elastalerthost:8080/api/alert'
    }
    actual_data = alert.get_info()

    assert expected_data == actual_data


@pytest.mark.parametrize('alerta_api_url, expected_data', [
    ('',  'Missing required option(s): alerta_api_url'),
    ('http://elastalerthost:8080/api/alert',
        {
            'type': 'alerta',
            'alerta_url': 'http://elastalerthost:8080/api/alert'
        }),
])
def test_alerta_required_error(alerta_api_url, expected_data):
    try:
        rule = {
            'name': 'Test Alerta rule!',
            'timeframe': datetime.timedelta(hours=1),
            'timestamp_field': '@timestamp',
            'type': 'any',
            'alert': 'alerta'
        }

        if alerta_api_url:
            rule['alerta_api_url'] = alerta_api_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = AlertaAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


@pytest.mark.parametrize('query_key, expected_data', [
    ('hostname', 'Test Alerta rule!.aProbe'),
    ('test',     'Test Alerta rule!'),
    ('',         'Test Alerta rule!'),
])
def test_alerta_create_default_title(query_key, expected_data):
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'type': 'any',
        'alert': 'alerta'
    }
    if query_key:
        rule['query_key'] = query_key

    match = [
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        },
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname2': 'aProbe'
        }
    ]
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)

    result = alert.create_default_title(match)
    assert expected_data == result


def test_alerta_match_timestamp_none():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': True,
        'alerta_tags': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": ['elastalert2'],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "environment": "Production",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )

    actual_data = json.loads(
        mock_post_request.call_args_list[0][1]['data'])
    del actual_data['createTime']
    del actual_data['rawData']
    assert expected_data == actual_data


def test_alerta_use_match_timestamp():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'alerta_attributes_keys': ["hostname", "TimestampEvent", "senderIP"],
        'alerta_attributes_values': ["{hostname}", "{logdate}", "{sender_ip}"],
        'alerta_correlate': ["ProbeUP", "ProbeDOWN"],
        'alerta_event': "ProbeUP",
        'alerta_group': "Health",
        'alerta_origin': "ElastAlert 2",
        'alerta_severity': "debug",
        'alerta_text': "Probe {hostname} is UP at {logdate} GMT",
        'alerta_value': "UP",
        'type': 'any',
        'alerta_use_match_timestamp': False,
        'alerta_tags': ['elastalert2'],
        'alert': 'alerta'
    }

    match = {
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        "origin": "ElastAlert 2",
        "resource": "elastalert",
        "severity": "debug",
        "service": ["elastalert"],
        "tags": ['elastalert2'],
        "text": "Probe aProbe is UP at <MISSING VALUE> GMT",
        "value": "UP",
        "environment": "Production",
        "timeout": 86400,
        "correlate": ["ProbeUP", "ProbeDOWN"],
        "group": "Health",
        "attributes": {"senderIP": "1.1.1.1", "hostname": "aProbe", "TimestampEvent": "<MISSING VALUE>"},
        "type": "elastalert",
        "event": "ProbeUP"
    }

    mock_post_request.assert_called_once_with(
        alert.url,
        data=mock.ANY,
        verify=True,
        headers={
            'content-type': 'application/json'}
    )

    actual_data = json.loads(
        mock_post_request.call_args_list[0][1]['data'])
    del actual_data['createTime']
    del actual_data['rawData']
    assert expected_data == actual_data


def test_get_json_payload_error():
    rule = {
        'name': 'Test Alerta rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'type': 'any',
        'alert': 'alerta',
        'query_key': 'hostname'
    }
    match = {
        '@timestamp': '2014-10-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = AlertaAlerter(rule)

    mock_run = mock.MagicMock(side_effect=Exception)
    with mock.patch('json.dumps', mock_run):

        with pytest.raises(Exception) as e:
            alert.get_json_payload(match)

        assert 'Error building Alerta request: ' in str(e)
