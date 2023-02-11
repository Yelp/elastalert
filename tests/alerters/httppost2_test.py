import json
import logging
from unittest import mock

import pytest
import yaml
from requests import RequestException

from elastalert.alerters.httppost2 import HTTPPost2Alerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_http_alerter_with_payload(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload as JSON string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "posted_name": "toto"
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_raw_fields(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload and raw fields',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto'},
        'http_post2_raw_fields': {'posted_raw_field': 'somefield'},
        'http_post2_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'posted_raw_field': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_raw_fields_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload and raw fields as JSON string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_raw_fields:
          posted_raw_field: somefield
        http_post2_static_payload:
          name: somestaticname
        http_post2_payload: |
          {
            "posted_name": "toto"
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'posted_raw_field': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_raw_fields_overwrite(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter raw fields overwrite payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto', 'overwrite_field': 'tata'},
        'http_post2_raw_fields': {'overwrite_field': 'somefield'},
        'http_post2_static_payload': {'name': 'somestaticname'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'overwrite_field': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_raw_fields_overwrite_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter raw fields overwrite payload as a JSON string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "posted_name": "toto",
            "overwrite_field": "tata"
          }
        http_post2_raw_fields:
          overwrite_field: somefield
        http_post2_static_payload:
          name: somestaticname
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'overwrite_field': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_no_clash(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload has no clash with the match fields',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'toto': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_no_clash_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) has no clash with the match fields
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"posted_name": "toto"}
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'toto': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_keys(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the key',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'args_{{some_field}}': 'tata'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'to\tto'  # include some specially handled control char
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'args_to\tto': 'tata',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_keys_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the key
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"args_{{some_field}}": "tata"}
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'to\tto'  # include some specially handled control char
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'args_to\tto': 'tata',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_template_error(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With unexpected template syntax error',
            'type': 'any',
            'jinja_root_name': '_data',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': 'toto'},
            'http_post2_payload': {'posted_name': '{{ _data["titi"] }}'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: The value of 'http_post2_payload' has an invalid Jinja2 syntax." in str(error)


def test_http_alerter_with_payload_unexpected_error(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With unexpected error',
            'type': 'any',
            'jinja_root_name': '_data',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': 'toto'},
            'http_post2_payload': {'posted_name': '{% for k,v in titi %}{% endfor %}'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': {'foobarbaz': 'tata'}
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: An unexpected error occurred with the 'http_post2_payload' value." in str(error)


def test_http_alerter_with_payload_json_decode_error(caplog):
    with pytest.raises(ValueError) as error:
        rule = yaml.safe_load(
            '''
            name: Test HTTP Post Alerter With json decode error
            type: any
            http_post2_url: http://test.webhook.url
            http_post2_payload: |
              this is invalid json
            alert: []
            '''
        )
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: The rendered value for 'http_post2_payload' contains invalid JSON." in str(error)


def test_http_alerter_with_payload_args_keys_jinja_root(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload args for the key using custom jinja root
        type: any
        jinja_root_name: _data
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "args_{{_data['key1']}}": "tata",
            "args_{{_data["key2"]}}": "toto"
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'key1': 'ta\tta',  # include some specially handled control char
        'key2': 'to\tto',
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'args_to\tto': 'toto',
        'args_ta\tta': 'tata',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_nested_keys(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the key',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'key': {'nested_key': 'some_value_{{some_field}}'}},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'key': {'nested_key': 'some_value_toto'},
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_nested_keys_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the key
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "key": {"nested_key": "some_value_{{some_field}}"}
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'key': {'nested_key': 'some_value_toto'},
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_none_value(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the key',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'key': None},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'key': None,
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_none_value_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the key
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"key": null}
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'key': None,
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_key_not_found(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the key if not found',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'args_{{some_field1}}': 'tata'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'args_': 'tata',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_key_not_found_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the key if not found
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"args_{{some_field1}}": "tata"}
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'toto'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'args_': 'tata',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the value',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto', 'args_name': '{{some_field}}'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foo\tbar\nbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name': 'foo\tbar\nbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        """
        name: Test HTTP Post Alerter With Payload as json string and args for the value
        type: any
        http_post2_url: 'http://test.webhook.url'
        http_post2_payload: |
          {
            "posted_name": "toto",
            "args_name": "{{some_field}}"
          }
        alert: []
        """
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foo\tbar\nbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name': 'foo\tbar\nbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value_jinja_root(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the value using custom jinja root',
        'jinja_root_name': '_data',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto', 'args_name': "{{_data['some_field']}}"},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foo\tbar\nbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name': 'foo\tbar\nbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value_jinja_root_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the value using custom jinja root
        jinja_root_name: _data
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "posted_name": "toto",
            "args_name1": "{{_data['some_field']}}",
            "args_name2": "{{_data["some_field"]}}"
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foo\tbar\nbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name1': 'foo\tbar\nbaz',
        'args_name2': 'foo\tbar\nbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value_not_found(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload args for the value if not found',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto', 'args_name': '{{some_field1}}'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name': '',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_args_value_not_found_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string) args for the value if not found
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {
            "posted_name": "toto",
            "args_name": "{{some_field1}}"
          }
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'some_field': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        'args_name': '',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_no_clash(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers has no clash with the match fields',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_name': 'titi'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'titi'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_no_clash_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers has no clash with the match fields
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_name": "titi"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'titi'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_value(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args value',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_name': '{{titi}}'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foo\tbarbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'foo\tbarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_value_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers args value
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_name": "{{titi}}"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foo\tbarbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'foo\tbarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_template_error(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With Headers args template error',
            'jinja_root_name': '_data',
            'type': 'any',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': '{{ _data["titi"] }}'},
            'http_post2_payload': {'posted_name': 'toto'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: The value of 'http_post2_headers' has an invalid Jinja2 syntax." in str(error)


def test_http_alerter_with_header_json_decode_error(caplog):
    with pytest.raises(ValueError) as error:
        rule = yaml.safe_load(
            '''
            name: Test HTTP Post Alerter With Headers args json decode error
            type: any
            http_post2_url: http://test.webhook.url
            http_post2_headers: |
              this is invalid json
            http_post2_payload:
              posted_name: toto
            alert: []
            '''
        )
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: The rendered value for 'http_post2_headers' contains invalid JSON." in str(error)


def test_http_alerter_with_header_args_value_jinja_root(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args value using custom jinja root',
        'jinja_root_name': '_data',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_name': "{{_data['titi']}}"},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foo\tbarbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'foo\tbarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_value_jinja_root_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers args value using custom jinja root
        type: any
        jinja_root_name: _data
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_name": "{{_data['titi']}}"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foo\tbarbaz'  # include some specially handled control chars
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': 'foo\tbarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_value_list(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With Headers args value',
            'type': 'any',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': ["test1", "test2"]},
            'http_post2_payload': {'posted_name': 'toto'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: ['test1', 'test2']" in str(error)


def test_http_alerter_with_header_args_value_list_as_json_string(caplog):
    with pytest.raises(ValueError) as error:
        rule = yaml.safe_load(
            '''
            name: Test HTTP Post Alerter With Headers args value as json string
            type: any
            http_post2_url: http://test.webhook.url
            http_post2_headers: |
              {"header_name": ["test1", "test2"]}
            http_post2_payload:
              posted_name: toto
            alert: []
            '''
        )
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: ['test1', 'test2']" in str(error)


def test_http_alerter_with_header_args_value_dict(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With Headers args value',
            'type': 'any',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': {'test': 'val'}},
            'http_post2_payload': {'posted_name': 'toto'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: {'test': 'val'}" in str(error)


def test_http_alerter_with_header_args_value_dict_as_json_string(caplog):
    with pytest.raises(ValueError) as error:
        rule = yaml.safe_load(
            '''
            name: Test HTTP Post Alerter With Headers args value as json string
            type: any
            http_post2_url: http://test.webhook.url
            http_post2_headers: |
              {"header_name": {"test": "val"}}
            http_post2_payload:
              posted_name: toto
            alert: []
            '''
        )
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: {'test': 'val'}" in str(error)


def test_http_alerter_with_header_args_value_none(caplog):
    with pytest.raises(ValueError) as error:
        rule = {
            'name': 'Test HTTP Post Alerter With Headers args value',
            'type': 'any',
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_headers': {'header_name': None},
            'http_post2_payload': {'posted_name': 'toto'},
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: None" in str(error)


def test_http_alerter_with_header_args_value_none_as_json_string(caplog):
    with pytest.raises(ValueError) as error:
        rule = yaml.safe_load(
            '''
            name: Test HTTP Post Alerter With Headers args value as json string
            type: any
            http_post2_url: http://test.webhook.url
            http_post2_headers: |
              {"header_name": null}
            http_post2_payload:
              posted_name: toto
            alert: []
            '''
        )
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'titi': 'foobarbaz'
        }
        with mock.patch('requests.post'):
            alert.alert([match])

    assert "HTTP Post 2: Can't send a header value which is not a string! " \
           "Forbidden header header_name: None" in str(error)


def test_http_alerter_with_header_args_value_not_found(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args value if not found',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_name': '{{titi1}}'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': ''
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_value_not_found_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers args value if not found as json string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_name": "{{titi1}}"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_name': ''
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_key(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args key',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_{{titi}}': 'tata'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_foobarbaz': 'tata'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_key_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers args key as json string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_{{titi}}": "tata"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_foobarbaz': 'tata'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_key_jinja_root(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args key using custom jinja root',
        'jinja_root_name': '_data',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {"header_{{_data['titi']}}": 'tata'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2023-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_foobarbaz': 'tata'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_key_not_found(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Headers args key if not found',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'header_{{titi1}}': 'tata'},
        'http_post2_payload': {'posted_name': 'toto'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_': 'tata'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_header_args_key_not_found_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Headers args key if not found as json string
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_headers: |
          {"header_{{titi1}}": "tata"}
        http_post2_payload:
          posted_name: toto
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'titi': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json;charset=utf-8',
        'header_': 'tata'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers=expected_headers,
        proxies=None,
        timeout=10,
        verify=True
    )
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_nested(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': '{{ toto.tata }}'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'toto': {'tata': 'titi'}
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'titi',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_nested_as_json_string(caplog):
    caplog.set_level(logging.INFO)
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"posted_name": "{{ toto.tata }}"}
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'toto': {'tata': 'titi'}
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'titi',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
    assert ('elastalert', logging.INFO, 'HTTP Post 2 alert sent.') == caplog.record_tuples[0]


def test_http_alerter_with_payload_all_values():
    rule = {
        'name': 'Test HTTP Post Alerter With Payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_payload': {'posted_name': 'toto'},
        'http_post2_all_values': True,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


def test_http_alerter_with_payload_all_values_as_json_string():
    rule = yaml.safe_load(
        '''
        name: Test HTTP Post Alerter With Payload (as JSON string)
        type: any
        http_post2_url: http://test.webhook.url
        http_post2_payload: |
          {"posted_name": "toto"}
        http_post2_all_values: true
        alert: []
        '''
    )
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        'posted_name': 'toto',
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
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
        'http_post2_url': 'http://test.webhook.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
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
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_proxy': 'http://proxy.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
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
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_timeout': 20,
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
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
        'http_post2_url': 'http://test.webhook.url',
        'http_post2_headers': {'authorization': 'Basic 123dr3234'},
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
        data=mock.ANY,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8',
                 'authorization': 'Basic 123dr3234'},
        proxies=None,
        timeout=10,
        verify=True
    )
    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])


@pytest.mark.parametrize('ca_certs, ignore_ssl_errors, excpet_verify', [
    ('', '', True),
    ('', True, False),
    ('', False, True),
    (True, '', True),
    (True, True, True),
    (True, False, True),
    (False, '', True),
    (False, True, False),
    (False, False, True)
])
def test_http_alerter_post_ca_certs(ca_certs, ignore_ssl_errors, excpet_verify):
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'alert': []
    }
    if ca_certs:
        rule['http_post2_ca_certs'] = ca_certs

    if ignore_ssl_errors:
        rule['http_post2_ignore_ssl_errors'] = ignore_ssl_errors

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)
    match = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])
    expected_data = {
        '@timestamp': '2017-01-01T00:00:00',
        'somefield': 'foobarbaz',
    }
    mock_post_request.assert_called_once_with(
        rule['http_post2_url'],
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
            'http_post2_url': 'http://test.webhook.url',
            'http_post2_ca_certs': False,
            'alert': []
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)
        match = {
            '@timestamp': '2017-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('requests.post', mock_run), pytest.raises(RequestException):
            alert.alert([match])
    assert 'Error posting HTTP Post 2 alert: ' in str(ea)


def test_http_getinfo():
    rule = {
        'name': 'Test HTTP Post Alerter Without Payload',
        'type': 'any',
        'http_post2_url': 'http://test.webhook.url',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = HTTPPost2Alerter(rule)

    expected_data = {
        'type': 'http_post2',
        'http_post2_webhook_url': ['http://test.webhook.url']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('http_post2_url, expected_data', [
    ('', 'Missing required option(s): http_post2_url'),
    ('http://test.webhook.url',
     {
         'type': 'http_post2',
         'http_post2_webhook_url': ['http://test.webhook.url']
     }),
])
def test_http_required_error(http_post2_url, expected_data):
    try:
        rule = {
            'name': 'Test HTTP Post Alerter Without Payload',
            'type': 'any',
            'alert': []
        }

        if http_post2_url:
            rule['http_post2_url'] = http_post2_url

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = HTTPPost2Alerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
