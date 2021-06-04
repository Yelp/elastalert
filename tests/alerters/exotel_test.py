from elastalert.alerters.exotel import ExotelAlerter
from elastalert.loaders import FileRulesLoader


def test_exotel_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'exotel_account_sid': 'xxxxx1',
        'exotel_auth_token': 'xxxxx2',
        'exotel_to_number': 'xxxxx3',
        'exotel_from_number': 'xxxxx4',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = ExotelAlerter(rule)

    expected_data = {
        'type': 'exotel',
        'exotel_account': 'xxxxx1'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data
