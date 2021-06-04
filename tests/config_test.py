# -*- coding: utf-8 -*-
import os
from unittest import mock
import datetime

from elastalert.config import load_conf


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
