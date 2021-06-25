import datetime
import pytest

from elastalert.alerters.ses import SesAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_ses_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'ses_from_addr': 'test2@aaa.com',
        'ses_email': 'test@aaa.com',
        'ses_aws_access_key_id': 'access key id',
        'ses_aws_secret_access_key': 'secret access key',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SesAlerter(rule)

    expected_data = {
        'type': 'ses',
        'recipients': ['test@aaa.com']
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('ses_email, ses_from_addr, expected_data', [
    ('',             '',              'Missing required option(s): ses_email, ses_from_addr'),
    ('test@aaa.com', '',              'Missing required option(s): ses_email, ses_from_addr'),
    ('',             'test2@aaa.com', 'Missing required option(s): ses_email, ses_from_addr'),
    ('test@aaa.com', 'test2@aaa.com',
        {
            'type': 'ses',
            'recipients': ['test@aaa.com']
        }),
])
def test_ses_required_error(ses_email, ses_from_addr, expected_data):
    try:
        rule = {
            'name': 'Test Telegram Rule',
            'type': 'any',
            'alert': []
        }

        if ses_email:
            rule['ses_email'] = ses_email

        if ses_from_addr:
            rule['ses_from_addr'] = ses_from_addr

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = SesAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


@pytest.mark.parametrize('query_key, expected_data', [
    ('hostname', 'ElastAlert 2: Test SES rule! - aProbe'),
    ('test',     'ElastAlert 2: Test SES rule!'),
    ('',         'ElastAlert 2: Test SES rule!'),
])
def test_ses_create_default_title(query_key, expected_data):
    rule = {
        'name': 'Test SES rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'type': 'any',
        'alert': 'alerta'
    }
    if query_key:
        rule['query_key'] = query_key

    match = [
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        },
        {
            '@timestamp': '2014-10-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname2': 'aProbe'
        }
    ]
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SesAlerter(rule)

    result = alert.create_default_title(match)
    assert expected_data == result


def test_ses_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'ses_from_addr': 'test2@aaa.com',
            'ses_email': 'test@aaa.com',
            'ses_aws_access_key_id': 'access key id',
            'ses_aws_secret_access_key': 'secret access key',
            'alert': []
        }
        match = {
            '@timestamp': '2021-01-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = SesAlerter(rule)
        alert.alert([match])

    assert 'Error sending Amazon SES: ' in str(ea)
