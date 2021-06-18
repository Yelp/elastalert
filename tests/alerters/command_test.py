import json
import subprocess
import logging

import pytest
from unittest import mock

from elastalert.alerters.command import CommandAlerter
from elastalert.alerts import BasicMatchString
from elastalert.util import EAException
from tests.alerts_test import mock_rule


def test_command_getinfo():
    # Test command as list with a formatted arg
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s']}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz',
             'nested': {'field': 1}}
    with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    expected_data = {
        'type': 'command',
        'command': '/bin/test/ --arg foobarbaz'
    }
    actual_data = alert.get_info()
    assert expected_data == actual_data


def test_command_old_style_string_format1(caplog):
    caplog.set_level(logging.INFO)
    # Test command as string with formatted arg (old-style string format)
    rule = {'command': '/bin/test/ --arg %(somefield)s'}
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz',
             'nested': {'field': 1}}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test --arg foobarbaz', stdin=subprocess.PIPE, shell=False)
    assert ('elastalert', logging.WARNING, 'Warning! You could be vulnerable to shell injection!') == caplog.record_tuples[0]
    assert ('elastalert', logging.INFO, 'Alert sent to Command') == caplog.record_tuples[1]


def test_command_old_style_string_format2():
    # Test command as string without formatted arg (old-style string format)
    rule = {'command': '/bin/test/foo.sh'}
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz',
             'nested': {'field': 1}}
    alert = CommandAlerter(rule)
    with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
        alert.alert([match])
    assert mock_popen.called_with('/bin/test/foo.sh', stdin=subprocess.PIPE, shell=True)


def test_command_pipe_match_json():
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'pipe_match_json': True}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
        mock_subprocess = mock.Mock()
        mock_popen.return_value = mock_subprocess
        mock_subprocess.communicate.return_value = (None, None)
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert mock_subprocess.communicate.called_with(input=json.dumps(match))


def test_command_pipe_alert_text():
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'pipe_alert_text': True, 'type': mock_rule(), 'name': 'Test'}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    alert_text = str(BasicMatchString(rule, match))
    with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
        mock_subprocess = mock.Mock()
        mock_popen.return_value = mock_subprocess
        mock_subprocess.communicate.return_value = (None, None)
        alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert mock_subprocess.communicate.called_with(input=alert_text.encode())


def test_command_fail_on_non_zero_exit():
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'fail_on_non_zero_exit': True}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    with pytest.raises(Exception) as exception:
        with mock.patch("elastalert.alerters.command.subprocess.Popen") as mock_popen:
            mock_subprocess = mock.Mock()
            mock_popen.return_value = mock_subprocess
            mock_subprocess.wait.return_value = 1
            alert.alert([match])
    assert mock_popen.called_with(['/bin/test', '--arg', 'foobarbaz'], stdin=subprocess.PIPE, shell=False)
    assert "Non-zero exit code while running command" in str(exception)


def test_command_os_error():
    rule = {'command': ['/bin/test/', '--arg', '%(somefield)s'],
            'pipe_alert_text': True, 'type': mock_rule(), 'name': 'Test'}
    alert = CommandAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz'}
    with pytest.raises(EAException) as ea:
        mock_run = mock.MagicMock(side_effect=OSError)
        with mock.patch("elastalert.alerters.command.subprocess.Popen", mock_run), pytest.raises(OSError) as mock_popen:
            mock_subprocess = mock.Mock()
            mock_popen.return_value = mock_subprocess
            mock_subprocess.communicate.return_value = (None, None)
            alert.alert([match])
    assert 'Error while running command /bin/test/ --arg foobarbaz: ' in str(ea)


def test_command_key_error():
    with pytest.raises(EAException) as ea:
        rule = {}
        alert = CommandAlerter(rule)
        match = {'@timestamp': '2014-01-01T00:00:00',
                 'somefield': 'foobarbaz',
                 'nested': {'field': 1}}
        with mock.patch("elastalert.alerters.command.subprocess.Popen"):
            alert.alert([match])
    assert 'Error formatting command:' in str(ea)
