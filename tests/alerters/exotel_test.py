import logging
import pytest

from unittest import mock

from requests import RequestException

from elastalert.alerters.exotel import ExotelAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


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


exotel_required_error_expected_data = 'Missing required option(s): exotel_account_sid, '
exotel_required_error_expected_data += 'exotel_auth_token, exotel_to_number, exotel_from_number'


@pytest.mark.parametrize('exotel_account_sid, exotel_auth_token, exotel_to_number, exotel_from_number, expected_data', [
    ('',      '',      '',      '',      exotel_required_error_expected_data),
    ('xxxx1', '',      '',      '',      exotel_required_error_expected_data),
    ('',      'xxxx2', '',      '',      exotel_required_error_expected_data),
    ('',      '',      'xxxx3', '',      exotel_required_error_expected_data),
    ('',      '',      '',      'xxxx4', exotel_required_error_expected_data),
    ('xxxx1', 'xxxx2', '',      '',      exotel_required_error_expected_data),
    ('xxxx1', '',      'xxxx3', '',      exotel_required_error_expected_data),
    ('xxxx1', '',      '',      'xxxx4', exotel_required_error_expected_data),
    ('',      'xxxx2', 'xxxx3', '',      exotel_required_error_expected_data),
    ('',      'xxxx2', '',      'xxxx4', exotel_required_error_expected_data),
    ('',      '',      'xxxx3', 'xxxx4', exotel_required_error_expected_data),
    ('xxxx1', 'xxxx2', 'xxxx3', '',      exotel_required_error_expected_data),
    ('xxxx1', '',      'xxxx3', 'xxxx4', exotel_required_error_expected_data),
    ('',      'xxxx2', 'xxxx3', 'xxxx4', exotel_required_error_expected_data),
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

        if exotel_account_sid:
            rule['exotel_account_sid'] = exotel_account_sid

        if exotel_auth_token:
            rule['exotel_auth_token'] = exotel_auth_token

        if exotel_to_number:
            rule['exotel_to_number'] = exotel_to_number

        if exotel_from_number:
            rule['exotel_from_number'] = exotel_from_number

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = ExotelAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_exotel(caplog):
    caplog.set_level(logging.INFO)
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
    match = {
        '@timestamp': '2021-01-10T00:00:00',
        'sender_ip': '1.1.1.1',
        'hostname': 'aProbe'
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)

    with mock.patch('elastalert.alerters.exotel.Exotel.sms') as mock_exotel:
        mock_exotel.return_value = 200
        alert = ExotelAlerter(rule)
        alert.alert([match])
        expected = [
            mock.call()('xxxxx4', 'xxxxx3', 'Test Rule')
        ]

        assert mock_exotel.mock_calls == expected
        assert ('elastalert', logging.INFO, 'Trigger sent to Exotel') == caplog.record_tuples[0]


def test_exotel_status_cod_not_200():
    with pytest.raises(EAException) as ea:
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
        match = {
            '@timestamp': '2021-01-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)

        with mock.patch('elastalert.alerters.exotel.Exotel.sms') as mock_exotel:
            mock_exotel.return_value = 201
            alert = ExotelAlerter(rule)
            alert.alert([match])

        assert 'Error posting to Exotel, response code is' in str(ea)


def test_exotel_request_error():
    with pytest.raises(EAException) as ea:
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
        match = {
            '@timestamp': '2021-01-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)

        mock_run = mock.MagicMock(side_effect=RequestException)
        with mock.patch('elastalert.alerters.exotel.Exotel.sms', mock_run), pytest.raises(RequestException) as mock_exotel:
            mock_exotel.return_value = 200
            alert = ExotelAlerter(rule)
            alert.alert([match])
    assert 'Error posting to Exotel' in str(ea)
