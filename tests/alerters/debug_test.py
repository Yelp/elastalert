import logging

from elastalert.alerters.debug import DebugAlerter
from elastalert.loaders import FileRulesLoader


def test_debug_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DebugAlerter(rule)

    expected_data = {
        'type': 'debug'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


def test_debug_alerter(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Debug Event Alerter',
        'type': 'any',
        'alert': [],
        'timestamp_field': 'timestamp'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DebugAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'name': 'debug-test-name'
    }
    alert.alert([match])

    excepted1 = 'Alert for Test Debug Event Alerter at None:'
    assert ('elastalert', logging.INFO, excepted1) == caplog.record_tuples[0]

    excepted2 = 'Test Debug Event Alerter\n\n@timestamp: 2021-01-01T00:00:00\n'
    excepted2 += 'name: debug-test-name\n'
    assert ('elastalert', logging.INFO, excepted2) == caplog.record_tuples[1]


def test_debug_alerter_querykey(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'Test Debug Event Alerter',
        'type': 'any',
        'alert': [],
        'timestamp_field': 'timestamp',
        'query_key': 'hostname'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = DebugAlerter(rule)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'name': 'debug-test-name',
        'hostname': 'aProbe'
    }
    alert.alert([match])

    excepted1 = 'Alert for Test Debug Event Alerter, aProbe at None:'
    assert ('elastalert', logging.INFO, excepted1) == caplog.record_tuples[0]

    excepted2 = 'Test Debug Event Alerter\n\n@timestamp: 2021-01-01T00:00:00\n'
    excepted2 += 'hostname: aProbe\nname: debug-test-name\n'
    assert ('elastalert', logging.INFO, excepted2) == caplog.record_tuples[1]
