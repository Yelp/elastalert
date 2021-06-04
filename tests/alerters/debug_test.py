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
