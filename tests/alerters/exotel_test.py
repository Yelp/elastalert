import pytest

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


@pytest.mark.parametrize('exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number, expected_data', [
    ('',      '',      '',      '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', '',      '',      '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      'xxxx2', '',      '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      '',      'xxxx3', '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      '',      '',      'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', 'xxxx2', '',      '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', '',      'xxxx3', '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', '',      '',      'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      'xxxx2', 'xxxx3', '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      'xxxx2', '',      'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      '',      'xxxx3', 'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', 'xxxx2', 'xxxx3', '',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', '',      'xxxx3', 'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('',      'xxxx2', 'xxxx3', 'xxxx4',
        'Missing required option(s): exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number'),
    ('xxxx1', 'xxxx2', 'xxxx3', 'xxxx4',
        {
            'type': 'exotel',
            'exotel_account': 'xxxx1'
        }),
])
def test_exotel_required_error(exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number, expected_data):
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert': []
        }

        if exotel_account_sid != '':
            rule['exotel_account_sid'] = exotel_account_sid

        if exotel_auth_token != '':
            rule['exotel_auth_token'] = exotel_auth_token

        if exotel_to_number != '':
            rule['exotel_to_number'] = exotel_to_number

        if exotel_from_number != '':
            rule['exotel_from_number'] = exotel_from_number

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ExotelAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)
