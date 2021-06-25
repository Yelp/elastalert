import pytest

from elastalert.alerters.stomp import StompAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_stomp_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'stomp_hostname': 'localhost',
        'stomp_hostport': '61613',
        'stomp_login': 'admin',
        'stomp_password': 'admin',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = StompAlerter(rule)

    expected_data = {
        'type': 'stomp'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


def test_stomp_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'timestamp_field': '@timestamp',
            'alert_subject': 'Cool subject',
            'stomp_hostname': 'localhost',
            'stomp_hostport': '61613',
            'stomp_login': 'admin',
            'stomp_password': 'admin',
            'alert': [],
            'rule_file': '/tmp/foo.yaml'
        }
        match = {
            '@timestamp': '2021-01-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = StompAlerter(rule)
        alert.alert([match])

    assert 'Error posting to Stomp: ' in str(ea)
