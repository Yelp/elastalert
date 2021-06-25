import logging
import pytest

from unittest import mock

from elastalert.alerters.zabbix import ZabbixAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_zabbix_basic(caplog):
    caplog.set_level(logging.WARNING)
    rule = {
        'name': 'Basic Zabbix test',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'alert': [],
        'alert_subject': 'Test Zabbix',
        'zbx_host': 'example.com',
        'zbx_key': 'example-key'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ZabbixAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00Z',
        'somefield': 'foobarbaz'
    }
    with mock.patch('pyzabbix.ZabbixSender.send') as mock_zbx_send:
        alert.alert([match])

        zabbix_metrics = {
            "host": "example.com",
            "key": "example-key",
            "value": "1",
            "clock": 1609459200
        }
        alerter_args = mock_zbx_send.call_args.args
        assert vars(alerter_args[0][0]) == zabbix_metrics
        log_messeage = "Missing zabbix host 'example.com' or host's item 'example-key', alert will be discarded"
        assert ('elastalert', logging.WARNING, log_messeage) == caplog.record_tuples[0]


def test_zabbix_getinfo():
    rule = {
        'name': 'Basic Zabbix test',
        'type': 'any',
        'alert_text_type': 'alert_text_only',
        'alert': [],
        'alert_subject': 'Test Zabbix',
        'zbx_host': 'example.com',
        'zbx_key': 'example-key'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ZabbixAlerter(rule)

    expected_data = {
        'type': 'zabbix Alerter'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('zbx_host, zbx_key, expected_data', [
    ('',            '',            'Missing required option(s): zbx_host, zbx_key'),
    ('example.com', '',            'Missing required option(s): zbx_host, zbx_key'),
    ('',            'example-key', 'Missing required option(s): zbx_host, zbx_key'),
    ('example.com', 'example-key',
        {
            'type': 'zabbix Alerter'
        })
])
def test_zabbix_required_error(zbx_host, zbx_key, expected_data):
    try:
        rule = {
            'name': 'Basic Zabbix test',
            'type': 'any',
            'alert_text_type': 'alert_text_only',
            'alert': [],
            'alert_subject': 'Test Zabbix'
        }

        if zbx_host:
            rule['zbx_host'] = zbx_host

        if zbx_key:
            rule['zbx_key'] = zbx_key

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ZabbixAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_zabbix_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Basic Zabbix test',
            'type': 'any',
            'alert_text_type': 'alert_text_only',
            'alert': [],
            'alert_subject': 'Test Zabbix',
            'zbx_host': 'example.com',
            'zbx_key': 'example-key'
        }
        match = {
            '@timestamp': '2021-01-01T00:00:00Z',
            'somefield': 'foobarbaz'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ZabbixAlerter(rule)
        alert.alert([match])

    assert 'Error sending alert to Zabbix: ' in str(ea)
