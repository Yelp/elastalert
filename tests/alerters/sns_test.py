import pytest

from elastalert.alerters.sns import SnsAlerter
from elastalert.loaders import FileRulesLoader
from elastalert.util import EAException


def test_sns_getinfo():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'alert_subject': 'Cool subject',
        'ses_email': 'test@aaa.com',
        'sns_topic_arn': 'topic arn',
        'sns_aws_access_key_id': 'access key id',
        'sns_aws_secret_access_key': 'secret access key',
        'alert': []
    }
    rules_loader = FileRulesLoader({})
    rules_loader.load_modules(rule)
    alert = SnsAlerter(rule)

    expected_data = {
        'type': 'sns'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('sns_topic_arn, expected_data', [
    ('', 'Missing required option(s): sns_topic_arn'),
    ('xxxx',
        {
            'type': 'sns'
        })
])
def test_sns_required_error(sns_topic_arn, expected_data):
    try:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'alert': []
        }

        if sns_topic_arn:
            rule['sns_topic_arn'] = sns_topic_arn

        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = SnsAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception as ea:
        assert expected_data in str(ea)


def test_sns_ea_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'Test Rule',
            'type': 'any',
            'alert_subject': 'Cool subject',
            'ses_email': 'test@aaa.com',
            'sns_topic_arn': 'topic arn',
            'sns_aws_access_key_id': 'access key id',
            'sns_aws_secret_access_key': 'secret access key',
            'alert': []
        }
        match = {
            '@timestamp': '2021-01-10T00:00:00',
            'sender_ip': '1.1.1.1',
            'hostname': 'aProbe'
        }
        rules_loader = FileRulesLoader({})
        rules_loader.load_modules(rule)
        alert = SnsAlerter(rule)
        alert.alert([match])

    assert 'Error sending Amazon SNS: ' in str(ea)
