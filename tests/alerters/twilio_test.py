import pytest

from elastalert.alerters.twilio import TwilioAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_twilio_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'twilio_account_sid': 'xxxxx1',
        'twilio_auth_token': 'xxxxx2',
        'twilio_to_number': 'xxxxx3',
        'twilio_from_number': 'xxxxx4',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = TwilioAlerter(rule)

    expected_data = {
        'type': 'twilio',
        'twilio_client_name': 'xxxxx4'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('twilio_account_sid, twilio_auth_token, twilio_to_number, expected_data', [
    ('',      '',      '',     'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('xxxx1', '',      '',     'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('',      'xxxx2', '',     'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('',      '',      'INFO', 'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('xxxx1', 'xxxx2', '',     'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('xxxx1', '',      'INFO', 'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('',      'xxxx2', 'INFO', 'Missing required option(s): twilio_account_sid, twilio_auth_token, twilio_to_number'),
    ('xxxx1', 'xxxx2', 'INFO',
        {
            'type': 'twilio',
            'twilio_client_name': 'xxxxx4'
        }),
])
def test_twilio_required_error(twilio_account_sid, twilio_auth_token, twilio_to_number, expected_data):
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'twilio_from_number': 'xxxxx4',
            'alert': []
        }

        if twilio_account_sid != '':
            rule['twilio_account_sid'] = twilio_account_sid

        if twilio_auth_token != '':
            rule['twilio_auth_token'] = twilio_auth_token

        if twilio_to_number != '':
            rule['twilio_to_number'] = twilio_to_number

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = TwilioAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


@pytest.mark.parametrize('twilio_use_copilot, twilio_message_service_sid, twilio_from_number, expected_data', [
    (True,  None,   'test', True),
    (False, 'test',  None,  True),
])
def test_twilio_use_copilot(twilio_use_copilot, twilio_message_service_sid, twilio_from_number, expected_data):
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'twilio_account_sid': 'xxxxx1',
            'twilio_auth_token': 'xxxxx2',
            'twilio_to_number': 'xxxxx3',
            'alert': []
        }

        if twilio_use_copilot != '':
            rule['twilio_use_copilot'] = twilio_use_copilot

        if twilio_message_service_sid != '':
            rule['twilio_message_service_sid'] = twilio_message_service_sid

        if twilio_from_number != '':
            rule['twilio_from_number'] = twilio_from_number

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = TwilioAlerter(rule)

        match = {
            '@timestamp': '2021-01-01T00:00:00',
            'somefield': 'foobarbaz'
        }
        alert.alert([match])
    except EAException:
        assert expected_data
