# -*- coding: utf-8 -*-
import datetime

import mock
import pytest

import elastalert.elastalert
import elastalert.util
from elastalert.util import dt_to_ts
from elastalert.util import ts_to_dt


mock_info = {'status': 200, 'name': 'foo', 'version': {'number': '2.0'}}


class mock_es_client(object):
    def __init__(self, host='es', port=14900):
        self.host = host
        self.port = port
        self.return_hits = []
        self.search = mock.Mock()
        self.create = mock.Mock()
        self.index = mock.Mock()
        self.delete = mock.Mock()
        self.info = mock.Mock(return_value=mock_info)


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
              '_source_enabled': True}]
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
            'scroll_keepalive': '30s'}
    elastalert.elastalert.elasticsearch_client = mock_es_client
    with mock.patch('elastalert.elastalert.get_rule_hashes'):
        with mock.patch('elastalert.elastalert.load_rules') as load_conf:
            load_conf.return_value = conf
            ea = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    ea.rules[0]['type'] = mock_ruletype()
    ea.rules[0]['alert'] = [mock_alert()]
    ea.writeback_es = mock_es_client()
    ea.writeback_es.search.return_value = {'hits': {'hits': []}}
    ea.writeback_es.index.return_value = {'_id': 'ABCD'}
    ea.current_es = mock_es_client('', '')
    return ea
