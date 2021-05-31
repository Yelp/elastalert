import mock

from elastalert.alerters.zabbix import ZabbixAlerter
from elastalert.loaders import FileRulesLoader


def test_zabbix_basic():
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
