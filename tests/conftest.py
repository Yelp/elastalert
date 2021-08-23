# -*- coding: utf-8 -*-
import datetime
import logging
import os

from unittest import mock
import pytest

import elastalert.elastalert
import elastalert.util
from elastalert.util import dt_to_ts
from elastalert.util import ts_to_dt

writeback_index = 'wb'


def pytest_addoption(parser):
    parser.addoption(
        "--runelasticsearch", action="store_true", default=False, help="run elasticsearch tests"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runelasticsearch"):
        # --runelasticsearch given in cli: run elasticsearch tests, skip ordinary unit tests
        skip_unit_tests = pytest.mark.skip(reason="not running when --runelasticsearch option is used to run")
        for item in items:
            if "elasticsearch" not in item.keywords:
                item.add_marker(skip_unit_tests)
    else:
        # skip elasticsearch tests
        skip_elasticsearch = pytest.mark.skip(reason="need --runelasticsearch option to run")
        for item in items:
            if "elasticsearch" in item.keywords:
                item.add_marker(skip_elasticsearch)


@pytest.fixture(scope='function', autouse=True)
def reset_loggers():
    """Prevent logging handlers from capturing temporary file handles.

    For example, a test that uses the `capsys` fixture and calls
    `logging.exception()` will initialize logging with a default handler that
    captures `sys.stderr`.  When the test ends, the file handles will be closed
    and `sys.stderr` will be returned to its original handle, but the logging
    will have a dangling reference to the temporary handle used in the `capsys`
    fixture.

    """
    logger = logging.getLogger()
    for handler in logger.handlers:
        logger.removeHandler(handler)


class mock_es_indices_client(object):
    def __init__(self):
        self.exists = mock.Mock(return_value=True)


class mock_es_client(object):
    def __init__(self, host='es', port=14900):
        self.host = host
        self.port = port
        self.return_hits = []
        self.search = mock.Mock()
        self.deprecated_search = mock.Mock()
        self.create = mock.Mock()
        self.index = mock.Mock()
        self.delete = mock.Mock()
        self.info = mock.Mock(return_value={'status': 200, 'name': 'foo', 'version': {'number': '2.0'}})
        self.ping = mock.Mock(return_value=True)
        self.indices = mock_es_indices_client()
        self.es_version = mock.Mock(return_value='2.0')
        self.is_atleastfive = mock.Mock(return_value=False)
        self.is_atleastsix = mock.Mock(return_value=False)
        self.is_atleastsixtwo = mock.Mock(return_value=False)
        self.is_atleastsixsix = mock.Mock(return_value=False)
        self.is_atleastseven = mock.Mock(return_value=False)
        self.resolve_writeback_index = mock.Mock(return_value=writeback_index)


class mock_es_sixsix_client(object):
    def __init__(self, host='es', port=14900):
        self.host = host
        self.port = port
        self.return_hits = []
        self.search = mock.Mock()
        self.deprecated_search = mock.Mock()
        self.create = mock.Mock()
        self.index = mock.Mock()
        self.delete = mock.Mock()
        self.info = mock.Mock(return_value={'status': 200, 'name': 'foo', 'version': {'number': '6.6.0'}})
        self.ping = mock.Mock(return_value=True)
        self.indices = mock_es_indices_client()
        self.es_version = mock.Mock(return_value='6.6.0')
        self.is_atleastfive = mock.Mock(return_value=True)
        self.is_atleastsix = mock.Mock(return_value=True)
        self.is_atleastsixtwo = mock.Mock(return_value=False)
        self.is_atleastsixsix = mock.Mock(return_value=True)
        self.is_atleastseven = mock.Mock(return_value=False)

        def writeback_index_side_effect(index, doc_type):
            if doc_type == 'silence':
                return index + '_silence'
            elif doc_type == 'past_elastalert':
                return index + '_past'
            elif doc_type == 'elastalert_status':
                return index + '_status'
            elif doc_type == 'elastalert_error':
                return index + '_error'
            return index

        self.resolve_writeback_index = mock.Mock(side_effect=writeback_index_side_effect)


class mock_rule_loader(object):
    def __init__(self, conf):
        self.base_config = conf
        self.load = mock.Mock()
        self.get_hashes = mock.Mock()
        self.load_configuration = mock.Mock()


class mock_ruletype(object):
    def __init__(self):
        self.add_data = mock.Mock()
        self.add_count_data = mock.Mock()
        self.add_terms_data = mock.Mock()
        self.matches = []
        self.get_match_data = lambda x: x
        self.get_match_str = lambda x: "some stuff happened"
        self.garbage_collect = mock.Mock()


class mock_alert(object):
    def __init__(self):
        self.alert = mock.Mock()

    def get_info(self):
        return {'type': 'mock'}


@pytest.fixture
def ea():
    rules = [{'es_host': '',
              'es_port': 14900,
              'name': 'anytest',
              'index': 'idx',
              'filter': [],
              'include': ['@timestamp'],
              'aggregation': datetime.timedelta(0),
              'realert': datetime.timedelta(0),
              'processed_hits': {},
              'timestamp_field': '@timestamp',
              'match_enhancements': [],
              'rule_file': 'blah.yaml',
              'max_query_size': 10000,
              'ts_to_dt': ts_to_dt,
              'dt_to_ts': dt_to_ts,
              '_source_enabled': True,
              'run_every': datetime.timedelta(seconds=15)}]
    conf = {'rules_folder': 'rules',
            'run_every': datetime.timedelta(minutes=10),
            'buffer_time': datetime.timedelta(minutes=5),
            'alert_time_limit': datetime.timedelta(hours=24),
            'es_host': 'es',
            'es_port': 14900,
            'writeback_index': 'wb',
            'rules': rules,
            'max_query_size': 10000,
            'old_query_limit': datetime.timedelta(weeks=1),
            'disable_rules_on_error': False,
            'scroll_keepalive': '30s',
            'custom_pretty_ts_format': '%Y-%m-%d %H:%M'}
    elastalert.util.elasticsearch_client = mock_es_client
    conf['rules_loader'] = mock_rule_loader(conf)
    elastalert.elastalert.elasticsearch_client = mock_es_client
    with mock.patch('elastalert.elastalert.load_conf') as load_conf:
        with mock.patch('elastalert.elastalert.BackgroundScheduler'):
            load_conf.return_value = conf
            conf['rules_loader'].load.return_value = rules
            conf['rules_loader'].get_hashes.return_value = {}
            ea = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    ea.rules[0]['type'] = mock_ruletype()
    ea.rules[0]['alert'] = [mock_alert()]
    ea.writeback_es = mock_es_client()
    ea.writeback_es.search.return_value = {'hits': {'hits': []}, 'total': 0}
    ea.writeback_es.deprecated_search.return_value = {'hits': {'hits': []}}
    ea.writeback_es.index.return_value = {'_id': 'ABCD', 'created': True}
    ea.current_es = mock_es_client('', '')
    ea.thread_data.current_es = ea.current_es
    ea.thread_data.num_hits = 0
    ea.thread_data.num_dupes = 0
    return ea


@pytest.fixture
def ea_sixsix():
    rules = [{'es_host': '',
              'es_port': 14900,
              'name': 'anytest',
              'index': 'idx',
              'filter': [],
              'include': ['@timestamp'],
              'run_every': datetime.timedelta(seconds=1),
              'aggregation': datetime.timedelta(0),
              'realert': datetime.timedelta(0),
              'processed_hits': {},
              'timestamp_field': '@timestamp',
              'match_enhancements': [],
              'rule_file': 'blah.yaml',
              'max_query_size': 10000,
              'ts_to_dt': ts_to_dt,
              'dt_to_ts': dt_to_ts,
              '_source_enabled': True}]
    conf = {'rules_folder': 'rules',
            'run_every': datetime.timedelta(minutes=10),
            'buffer_time': datetime.timedelta(minutes=5),
            'alert_time_limit': datetime.timedelta(hours=24),
            'es_host': 'es',
            'es_port': 14900,
            'writeback_index': writeback_index,
            'rules': rules,
            'max_query_size': 10000,
            'old_query_limit': datetime.timedelta(weeks=1),
            'disable_rules_on_error': False,
            'scroll_keepalive': '30s',
            'custom_pretty_ts_format': '%Y-%m-%d %H:%M'}
    conf['rules_loader'] = mock_rule_loader(conf)
    elastalert.elastalert.elasticsearch_client = mock_es_sixsix_client
    elastalert.util.elasticsearch_client = mock_es_sixsix_client
    with mock.patch('elastalert.elastalert.load_conf') as load_conf:
        with mock.patch('elastalert.elastalert.BackgroundScheduler'):
            load_conf.return_value = conf
            conf['rules_loader'].load.return_value = rules
            conf['rules_loader'].get_hashes.return_value = {}
            ea_sixsix = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    ea_sixsix.rules[0]['type'] = mock_ruletype()
    ea_sixsix.rules[0]['alert'] = [mock_alert()]
    ea_sixsix.writeback_es = mock_es_sixsix_client()
    ea_sixsix.writeback_es.search.return_value = {'hits': {'hits': []}}
    ea_sixsix.writeback_es.deprecated_search.return_value = {'hits': {'hits': []}}
    ea_sixsix.writeback_es.index.return_value = {'_id': 'ABCD'}
    ea_sixsix.current_es = mock_es_sixsix_client('', -1)
    return ea_sixsix


@pytest.fixture(scope='function')
def environ():
    """py.test fixture to get a fresh mutable environment."""
    old_env = os.environ
    new_env = dict(list(old_env.items()))
    os.environ = new_env
    yield os.environ
    os.environ = old_env
