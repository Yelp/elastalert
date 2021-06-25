import base64
import datetime
import logging
import pytest

from unittest import mock

from elastalert.alerters.email import EmailAlerter
from elastalert.util import EAException
from tests.alerts_test import mock_rule


def test_email(caplog):
    caplog.set_level(logging.INFO)
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body
        assert ('elastalert', logging.INFO, "Sent email to ['testing@test.test', 'test@test.test']") == caplog.record_tuples[0]


@pytest.mark.parametrize('email_from_field, email_add_domain, match_data, expected_data', [
    ('data.user', '',             [{'data': {'user': 'qlo'}}],          ['qlo@example.com']),
    ('data.user', '@example.com', [{'data': {'user': 'qlo'}}],          ['qlo@example.com']),
    ('data.user', 'example.com',  [{'data': {'user': '@qlo'}}],         ['@qlo']),
    ('data.user', 'example.com',  [{'data': {'user': ['qlo', 'foo']}}], ['qlo@example.com', 'foo@example.com']),
    ('data.user', 'example.com',  [{'data': {'foo': 'qlo'}}],           ['testing@test.test']),
    ('data.user', 'example.com',  [{'data': {'user': 17}}],             ['testing@test.test'])
])
def test_email_from_field(email_from_field, email_add_domain, match_data, expected_data):
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test'],
        'email_add_domain': 'example.com',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_from_field': 'data.user',
        'owner': 'owner_value'
    }
    if email_from_field:
        rule['email_from_field'] = email_from_field
    if email_add_domain:
        rule['email_add_domain'] = email_add_domain
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert(match_data)
        assert mock_smtp.mock_calls[4][1][1] == expected_data


def test_email_with_unicode_strings():
    rule = {
        'name': 'test alert',
        'email': 'testing@test.test',
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test'], mock.ANY),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_with_auth():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'alert_subject': 'Test alert for {0}',
        'alert_subject_args': ['test_term'],
        'smtp_auth_file': 'file.txt',
        'rule_file': '/tmp/foo.yaml'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cert_key():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'alert_subject': 'Test alert for {0}',
        'alert_subject_args': ['test_term'],
        'smtp_auth_file': 'file.txt',
        'smtp_cert_file': 'dummy/cert.crt',
        'smtp_key_file': 'dummy/client.key',
        'rule_file': '/tmp/foo.yaml'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.read_yaml') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile='dummy/cert.crt', keyfile='dummy/client.key'),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cc():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'cc': 'tester@testing.testing'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test',
                            'tester@testing.testing'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_bcc():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'bcc': 'tester@testing.testing'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test',
                            'tester@testing.testing'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' not in body
        assert 'From: testfrom@test.test' in body


def test_email_with_cc_and_bcc():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'cc': ['test1@test.com', 'test2@test.com'],
        'bcc': 'tester@testing.testing'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test',
                            'test1@test.com',
                            'test2@test.com',
                            'tester@testing.testing'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: test1@test.com,test2@test.com' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_args():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'alert_subject': 'Test alert for {0} {1}',
        'alert_subject_args': ['test_term', 'test.term'],
        'alert_text': 'Test alert for {0} and {1} {2}',
        'alert_text_args': ['test_arg1', 'test_arg2', 'test.arg3'],
        'alert_missing_value': '<CUSTOM MISSING VALUE>'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'test_arg1': 'testing', 'test': {'term': ':)', 'arg3': '☃'}}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]
        # Extract the MIME encoded message body
        body_text = base64.b64decode(body.split('\n\n')[-1][:-1]).decode('utf-8')

        assert 'testing' in body_text
        assert '<CUSTOM MISSING VALUE>' in body_text
        assert '☃' in body_text

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value :)' in body


def test_email_query_key_in_subject():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'query_key': 'username'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'username': 'werbenjagermanjensen'}])

        body = mock_smtp.mock_calls[4][1][2]
        lines = body.split('\n')
        found_subject = False
        for line in lines:
            if line.startswith('Subject'):
                assert 'werbenjagermanjensen' in line
                found_subject = True
        assert found_subject


def test_email_getinfo():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    alert = EmailAlerter(rule)

    expected_data = {
        'type': 'email',
        'recipients': ['testing@test.test', 'test@test.test']}
    actual_data = alert.get_info()
    assert expected_data == actual_data


@pytest.mark.parametrize('email, expected_data', [
    (['testing@test.test', 'test@test.test'],  True),
    (['testing@test.test', 'test@test.test'],
        {
            'type': 'email',
            'recipients': ['testing@test.test', 'test@test.test']
        }),
])
def test_email_key_error(email, expected_data):
    try:
        rule = {
            'name': 'test alert',
            'from_addr': 'testfrom@test.test',
            'type': mock_rule(),
            'timestamp_field': '@timestamp',
            'email_reply_to': 'test@example.com',
            'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}',
            'alert_subject_args': ['test_term', 'owner'],
            'snowman': '☃'
        }

        if email:
            rule['email'] = email

        alert = EmailAlerter(rule)

        actual_data = alert.get_info()
        assert expected_data == actual_data
    except Exception:
        assert expected_data


@pytest.mark.parametrize('query_key, expected_data', [
    ('hostname', 'ElastAlert: Test email rule! - aProbe'),
    ('test',     'ElastAlert: Test email rule!'),
    ('',         'ElastAlert: Test email rule!'),
])
def test_email_create_default_title(query_key, expected_data):
    rule = {
        'name': 'Test email rule!',
        'alerta_api_url': 'http://elastalerthost:8080/api/alert',
        'timeframe': datetime.timedelta(hours=1),
        'timestamp_field': '@timestamp',
        'type': 'any',
        'alert': 'email',
        'email': 'test@test.com'
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
    alert = EmailAlerter(rule)

    result = alert.create_default_title(match)
    assert expected_data == result


def test_email_smtp_port():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'smtp_port': 35,
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 35),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_smtp_ssl_true():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'smtp_ssl': True,
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP_SSL') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[1][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_smtp_ssl_true_and_smtp_port():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'smtp_ssl': True,
        'smtp_port': 455,
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP_SSL') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 455, certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[1][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_smtp_exception():
    with pytest.raises(EAException) as ea:
        rule = {
            'name': 'test alert',
            'email': ['testing@test.test', 'test@test.test'],
            'from_addr': 'testfrom@test.test',
            'type': mock_rule(),
            'timestamp_field': '@timestamp',
            'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}',
            'alert_subject_args': ['test_term'],
            'smtp_auth_file': 'file.txt',
            'rule_file': '/tmp/foo.yaml'
        }
        with mock.patch('elastalert.alerters.email.SMTP_SSL'):
            with mock.patch('elastalert.alerts.read_yaml') as mock_open:
                mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
                alert = EmailAlerter(rule)
                alert.alert([{'test_term': 'test_value'}])
    assert 'Error connecting to SMTP host: ' in str(ea)


def test_email_format_html():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'smtp_ssl': True,
        'smtp_port': 455,
        'email_format': 'html',
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'owner': 'owner_value',
        'alert_subject': 'Test alert for {0}, owned by {1}',
        'alert_subject_args': ['test_term', 'owner'],
        'snowman': '☃'
    }
    with mock.patch('elastalert.alerters.email.SMTP_SSL') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost', 455, certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test'
                        ],
                        mock.ANY
                    ),
                    mock.call().quit()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[1][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body
        assert 'Content-Type: text/html; charset="utf-8"' in body
