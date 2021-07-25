# -*- coding: utf-8 -*-
import datetime
import logging
import os
import pytest

from elastalert.config import load_conf
from elastalert.util import EAException

from unittest import mock


def test_config_loads():
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.yaml'
    test_args.rule = None
    test_args.debug = False
    test_args.es_debug_trace = None

    conf = load_conf(test_args)

    assert conf['rules_folder'] == '/opt/elastalert/rules'
    assert conf['run_every'] == datetime.timedelta(seconds=10)
    assert conf['buffer_time'] == datetime.timedelta(minutes=15)

    assert conf['es_host'] == 'elasticsearch'
    assert conf['es_port'] == 9200

    assert conf['es_username'] == 'elastic'
    assert conf['es_password'] == 'password_from_env'

    assert conf['writeback_index'] == 'elastalert_status'

    assert conf['alert_time_limit'] == datetime.timedelta(days=2)


def test_config_loads_ea_execption():
    with pytest.raises(EAException) as ea:
        os.environ['ELASTIC_PASS'] = 'password_from_env'

        test_args = mock.Mock()
        test_args.config = ''
        test_args.rule = None
        test_args.debug = False
        test_args.es_debug_trace = None

        load_conf(test_args)

    assert 'No --config or config.yaml found' in str(ea)


@pytest.mark.parametrize('config, expected', [
    ('/example.config.type_error.run_every.yaml', 'Invalid time format used: '),
    ('/example.config.type_error.buffer_time.yaml', 'Invalid time format used: ')
])
def test_config_loads_type_error(config, expected):
    with pytest.raises(EAException) as ea:
        os.environ['ELASTIC_PASS'] = 'password_from_env'
        dir_path = os.path.dirname(os.path.realpath(__file__))

        test_args = mock.Mock()
        test_args.config = dir_path + config
        test_args.rule = None
        test_args.debug = False
        test_args.es_debug_trace = None

        load_conf(test_args)

    assert expected in str(ea)


@pytest.mark.parametrize('config, expected', [
    ('/example.config.not_found.run_every.yaml', 'must contain '),
    ('/example.config.not_found.es_host.yaml', 'must contain '),
    ('/example.config.not_found.es_port.yaml', 'must contain '),
    ('/example.config.not_found.writeback_index.yaml', 'must contain '),
    ('/example.config.not_found.buffer_time.yaml', 'must contain ')
])
def test_config_loads_required_globals_error(config, expected):
    with pytest.raises(EAException) as ea:
        os.environ['ELASTIC_PASS'] = 'password_from_env'
        dir_path = os.path.dirname(os.path.realpath(__file__))

        test_args = mock.Mock()
        test_args.config = dir_path + config
        test_args.rule = None
        test_args.debug = False
        test_args.verbose = None
        test_args.es_debug_trace = None

        load_conf(test_args)

    assert expected in str(ea)


def test_config_loads_debug(caplog):
    caplog.set_level(logging.INFO)
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.yaml'
    test_args.rule = None
    test_args.debug = True
    test_args.verbose = None
    test_args.es_debug_trace = None

    load_conf(test_args)

    expected_msg = 'Note: In debug mode, alerts will be logged to console but NOT actually sent.\n'
    expected_msg += '            To send them but remain verbose, use --verbose instead.'
    assert ('elastalert', logging.INFO, expected_msg) == caplog.record_tuples[0]


def test_config_loads_debug_and_verbose(caplog):
    caplog.set_level(logging.INFO)
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.yaml'
    test_args.rule = None
    test_args.debug = True
    test_args.verbose = True
    test_args.es_debug_trace = None

    load_conf(test_args)

    expected_msg = 'Note: --debug and --verbose flags are set. --debug takes precedent.'
    assert ('elastalert', logging.INFO, expected_msg) == caplog.record_tuples[0]


def test_config_loads_old_query_limit():
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.old_query_limit.yaml'
    test_args.rule = None
    test_args.debug = False
    test_args.es_debug_trace = None

    conf = load_conf(test_args)

    assert conf['rules_folder'] == '/opt/elastalert/rules'
    assert conf['run_every'] == datetime.timedelta(seconds=10)
    assert conf['buffer_time'] == datetime.timedelta(minutes=15)
    assert conf['es_host'] == 'elasticsearch'
    assert conf['es_port'] == 9200
    assert conf['es_username'] == 'elastic'
    assert conf['es_password'] == 'password_from_env'
    assert conf['writeback_index'] == 'elastalert_status'
    assert conf['alert_time_limit'] == datetime.timedelta(days=2)
    assert conf['old_query_limit'] == datetime.timedelta(days=3)


def test_config_loads_logging(capfd):
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.logging.yaml'
    test_args.rule = None
    test_args.debug = True
    test_args.verbose = True
    test_args.es_debug_trace = None

    load_conf(test_args)

    expected1 = 'Note: --debug and --verbose flags are set. --debug takes precedent.'
    expected2 = 'Note: In debug mode, alerts will be logged to console but NOT actually sent.\n'
    expected3 = '           To send them but remain verbose, use --verbose instead.\n'
    out, err = capfd.readouterr()
    assert expected1 in err
    assert expected2 in err
    assert expected3 in err


def test_config_loads_logging2(caplog):
    os.environ['ELASTIC_PASS'] = 'password_from_env'
    dir_path = os.path.dirname(os.path.realpath(__file__))

    test_args = mock.Mock()
    test_args.config = dir_path + '/example.config.yaml'
    test_args.rule = None
    test_args.debug = True
    test_args.verbose = False
    test_args.es_debug_trace = None

    load_conf(test_args)

    expected1 = 'Note: In debug mode, alerts will be logged to console but NOT actually sent.'
    expected2 = '            To send them but remain verbose, use --verbose instead.'
    user, level, message = caplog.record_tuples[0]
    assert expected1 in message
    assert expected2 in message
