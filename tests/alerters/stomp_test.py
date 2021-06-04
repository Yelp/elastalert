from elastalert.alerters.stomp import StompAlerter
from elastalert.loaders import FileRulesLoader


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
