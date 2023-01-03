import json
import logging
import socket

from unittest import mock
from elastalert.alerters.gelf import GelfAlerter
from elastalert.loaders import FileRulesLoader


def test_gelf_sent_http(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'http',
        'gelf_endpoint': 'http://example.graylog.site',
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': 5,
    }

    mock_post_request.assert_called_once_with(
        url=rule['gelf_endpoint'],
        headers={'Content-Type': 'application/json'},
        json=mock.ANY,
        verify=False,
        timeout=30,
    )

    assert expected_data == mock_post_request.call_args_list[0][1]['json']
    assert ('elastalert', logging.INFO, 'GELF message sent via HTTP.') == caplog.record_tuples[0]


def test_gelf_sent_http_with_custom_ca(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'http',
        'gelf_endpoint': 'https://example.graylog.site',
        'gelf_ca_cert': './ca.crt',
        'gelf_http_ignore_ssl_errors': False,
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': 5,
    }

    mock_post_request.assert_called_once_with(
        url=rule['gelf_endpoint'],
        headers={'Content-Type': 'application/json'},
        json=mock.ANY,
        verify=rule['gelf_ca_cert'],
        timeout=30,
    )

    assert expected_data == mock_post_request.call_args_list[0][1]['json']
    assert ('elastalert', logging.INFO, 'GELF message sent via HTTP.') == caplog.record_tuples[0]


def test_gelf_sent_http_with_optional_fields(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'http',
        'gelf_endpoint': 'http://example.graylog.site',
        'gelf_http_headers': {'Accept': 'application/json;charset=utf-8'},
        'gelf_log_level': 1,
        'gelf_http_ignore_ssl_errors': True,
        'gelf_timeout': 10,
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    with mock.patch('requests.post') as mock_post_request:
        alert.alert([match])

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': rule['gelf_log_level'],
    }

    mock_post_request.assert_called_once_with(
        url=rule['gelf_endpoint'],
        headers={'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'},
        json=mock.ANY,
        verify=False,
        timeout=10,
    )

    assert expected_data == mock_post_request.call_args_list[0][1]['json']
    assert ('elastalert', logging.INFO, 'GELF message sent via HTTP.') == caplog.record_tuples[0]


def test_gelf_sent_tcp(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'tcp',
        'gelf_host': '127.0.0.1',
        'gelf_port': 12201,
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': 5,
    }

    expected_data = json.dumps(expected_data).encode('utf-8') + b'\x00'

    with mock.patch('socket.socket') as mock_socket:
        alert.alert([match])

    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_socket.return_value.connect.assert_called_once_with(mock.ANY)

    assert expected_data == mock_socket.return_value.sendall.call_args[0][0]
    assert ('elastalert', logging.INFO, 'GELF message sent via TCP.') == caplog.record_tuples[0]


def test_gelf_sent_tcp_with_custom_ca(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'tcp',
        'gelf_host': '127.0.0.1',
        'gelf_port': 12201,
        'gelf_ca_cert': './ca.pem',
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': 5,
    }

    expected_data = json.dumps(expected_data).encode('utf-8') + b'\x00'

    with mock.patch('socket.socket') as mock_socket:
        with mock.patch('ssl.wrap_socket') as mock_ssl_wrap_socket:
            mock_ssl_wrap_socket.return_value = mock_socket
            alert.alert([match])
            mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            mock_socket.return_value.connect.assert_called_once_with(mock.ANY)
            mock_ssl_wrap_socket.assert_called_once_with(mock_socket.return_value, ca_certs=rule['gelf_ca_cert'])

            assert expected_data == mock_ssl_wrap_socket.return_value.sendall.call_args[0][0]
            assert ('elastalert', logging.INFO, 'GELF message sent via TCP.') == caplog.record_tuples[0]


def test_gelf_sent_tcp_with_optional_fields(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'tcp',
        'gelf_host': '127.0.0.1',
        'gelf_port': 12201,
        'gelf_payload': {'username': 'username', 'account_status': 'account_status'},
        'gelf_timeout': 10,
        'gelf_log_level': 1,
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    match = {
        'username': 'test_user',
        'account_status': 'disabled',
    }

    expected_data = {
        'version': '1.1',
        'host': socket.getfqdn(),
        'short_message': '{"Title": "Test Rule", "username": "test_user", "account_status": "disabled"}',
        'level': rule['gelf_log_level'],
    }

    expected_data = json.dumps(expected_data).encode('utf-8') + b'\x00'

    with mock.patch('socket.socket') as mock_socket:
        alert.alert([match])

    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_socket.return_value.connect.assert_called_once_with(mock.ANY)
    mock_socket.return_value.settimeout.assert_called_once_with(rule['gelf_timeout'])

    assert expected_data == mock_socket.return_value.sendall.call_args[0][0]
    assert ('elastalert', logging.INFO, 'GELF message sent via TCP.') == caplog.record_tuples[0]


def test_gelf_http_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'http',
        'gelf_endpoint': 'http://graylog.url/gelf',
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    expected_data = {
        'type': 'gelf',
        'gelf_type': rule['gelf_type']
    }

    actual_data = alert.get_info()
    assert expected_data == actual_data


def test_gelf_tcp_getinfo():

    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'gelf_type': 'tcp',
        'gelf_host': '127.0.0.1',
        'gelf_port': '12201',
        'alert': [],
    }

    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = GelfAlerter(rule)

    expected_data = {
        'type': 'gelf',
        'gelf_type': rule['gelf_type'],
    }

    actual_data = alert.get_info()
    assert expected_data == actual_data
