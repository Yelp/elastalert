# -*- coding: utf-8 -*-
import copy
import datetime
import json
import threading

import elasticsearch
from unittest import mock
import pytest
from elasticsearch.exceptions import ConnectionError
from elasticsearch.exceptions import ElasticsearchException

from elastalert.enhancements import BaseEnhancement
from elastalert.enhancements import DropMatchException
from elastalert.enhancements import TimeEnhancement
from elastalert.kibana import dashboard_temp
from elastalert.util import dt_to_ts
from elastalert.util import dt_to_unix
from elastalert.util import dt_to_unixms
from elastalert.util import EAException
from elastalert.util import ts_now
from elastalert.util import ts_to_dt
from elastalert.util import unix_to_dt

START_TIMESTAMP = '2014-09-26T12:34:45Z'
END_TIMESTAMP = '2014-09-27T12:34:45Z'
START = ts_to_dt(START_TIMESTAMP)
END = ts_to_dt(END_TIMESTAMP)


def _set_hits(ea_inst, hits):
    res = {'hits': {'total': len(hits), 'hits': hits}}
    ea_inst.client_es.return_value = res


def generate_hits(timestamps, **kwargs):
    hits = []
    for i, ts in enumerate(timestamps):
        data = {'_id': 'id{}'.format(i),
                '_source': {'@timestamp': ts},
                '_type': 'logs',
                '_index': 'idx'}
        for key, item in kwargs.items():
            data['_source'][key] = item
        # emulate process_hits(), add metadata to _source
        for field in ['_id', '_type', '_index']:
            data['_source'][field] = data[field]
        hits.append(data)
    return {'hits': {'total': len(hits), 'hits': hits}}


def assert_alerts(ea_inst, calls):
    """ Takes a list of lists of timestamps. Asserts that an alert was called for each list, containing those timestamps. """
    assert ea_inst.rules[0]['alert'][0].alert.call_count == len(calls)
    for call_num, call_args in enumerate(ea_inst.rules[0]['alert'][0].alert.call_args_list):
        assert not any([match['@timestamp'] not in calls[call_num] for match in call_args[0][0]])
        assert len(call_args[0][0]) == len(calls[call_num])


def test_starttime(ea):
    invalid = ['2014-13-13',
               '2014-11-24T30:00:00',
               'Not A Timestamp']
    for ts in invalid:
        with pytest.raises((TypeError, ValueError)):
            ts_to_dt(ts)


def test_init_rule(ea):
    # Simulate state of a rule just loaded from a file
    ea.rules[0]['minimum_starttime'] = datetime.datetime.now()
    new_rule = copy.copy(ea.rules[0])
    list(map(new_rule.pop, ['agg_matches', 'current_aggregate_id', 'processed_hits', 'minimum_starttime']))

    # Properties are copied from ea.rules[0]
    ea.rules[0]['starttime'] = '2014-01-02T00:11:22'
    ea.rules[0]['processed_hits'] = ['abcdefg']
    new_rule = ea.init_rule(new_rule, False)
    for prop in ['starttime', 'agg_matches', 'current_aggregate_id', 'processed_hits', 'minimum_starttime', 'run_every']:
        assert new_rule[prop] == ea.rules[0][prop]

    # Properties are fresh
    new_rule = ea.init_rule(new_rule, True)
    new_rule.pop('starttime')
    assert 'starttime' not in new_rule
    assert new_rule['processed_hits'] == {}

    # Assert run_every is unique
    new_rule['run_every'] = datetime.timedelta(seconds=17)
    new_rule = ea.init_rule(new_rule, True)
    assert new_rule['run_every'] == datetime.timedelta(seconds=17)


def test_query(ea):
    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    ea.thread_data.current_es.search.assert_called_with(body={
        'query': {'filtered': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}}},
        'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea.rules[0]['max_query_size'], scroll=ea.conf['scroll_keepalive'])


def test_query_sixsix(ea_sixsix):
    ea_sixsix.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea_sixsix.run_query(ea_sixsix.rules[0], START, END)
    ea_sixsix.thread_data.current_es.search.assert_called_with(body={
        'query': {'bool': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}}},
        'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea_sixsix.rules[0]['max_query_size'], scroll=ea_sixsix.conf['scroll_keepalive'])


def test_query_with_fields(ea):
    ea.rules[0]['_source_enabled'] = False
    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    ea.thread_data.current_es.search.assert_called_with(body={
        'query': {'filtered': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}}},
        'sort': [{'@timestamp': {'order': 'asc'}}], 'fields': ['@timestamp']}, index='idx', ignore_unavailable=True,
        size=ea.rules[0]['max_query_size'], scroll=ea.conf['scroll_keepalive'])


def test_query_sixsix_with_fields(ea_sixsix):
    ea_sixsix.rules[0]['_source_enabled'] = False
    ea_sixsix.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea_sixsix.run_query(ea_sixsix.rules[0], START, END)
    ea_sixsix.thread_data.current_es.search.assert_called_with(body={
        'query': {'bool': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}}},
        'sort': [{'@timestamp': {'order': 'asc'}}], 'stored_fields': ['@timestamp']}, index='idx',
        ignore_unavailable=True,
        size=ea_sixsix.rules[0]['max_query_size'], scroll=ea_sixsix.conf['scroll_keepalive'])


def test_query_with_unix(ea):
    ea.rules[0]['timestamp_type'] = 'unix'
    ea.rules[0]['dt_to_ts'] = dt_to_unix
    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    start_unix = dt_to_unix(START)
    end_unix = dt_to_unix(END)
    ea.thread_data.current_es.search.assert_called_with(
        body={'query': {'filtered': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': end_unix, 'gt': start_unix}}}]}}}},
            'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea.rules[0]['max_query_size'], scroll=ea.conf['scroll_keepalive'])


def test_query_sixsix_with_unix(ea_sixsix):
    ea_sixsix.rules[0]['timestamp_type'] = 'unix'
    ea_sixsix.rules[0]['dt_to_ts'] = dt_to_unix
    ea_sixsix.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea_sixsix.run_query(ea_sixsix.rules[0], START, END)
    start_unix = dt_to_unix(START)
    end_unix = dt_to_unix(END)
    ea_sixsix.thread_data.current_es.search.assert_called_with(
        body={'query': {'bool': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': end_unix, 'gt': start_unix}}}]}}}},
            'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea_sixsix.rules[0]['max_query_size'], scroll=ea_sixsix.conf['scroll_keepalive'])


def test_query_with_unixms(ea):
    ea.rules[0]['timestamp_type'] = 'unixms'
    ea.rules[0]['dt_to_ts'] = dt_to_unixms
    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    start_unix = dt_to_unixms(START)
    end_unix = dt_to_unixms(END)
    ea.thread_data.current_es.search.assert_called_with(
        body={'query': {'filtered': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': end_unix, 'gt': start_unix}}}]}}}},
            'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea.rules[0]['max_query_size'], scroll=ea.conf['scroll_keepalive'])


def test_query_sixsix_with_unixms(ea_sixsix):
    ea_sixsix.rules[0]['timestamp_type'] = 'unixms'
    ea_sixsix.rules[0]['dt_to_ts'] = dt_to_unixms
    ea_sixsix.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea_sixsix.run_query(ea_sixsix.rules[0], START, END)
    start_unix = dt_to_unixms(START)
    end_unix = dt_to_unixms(END)
    ea_sixsix.thread_data.current_es.search.assert_called_with(
        body={'query': {'bool': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': end_unix, 'gt': start_unix}}}]}}}},
            'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'],
        ignore_unavailable=True,
        size=ea_sixsix.rules[0]['max_query_size'], scroll=ea_sixsix.conf['scroll_keepalive'])


def test_no_hits(ea):
    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    assert ea.rules[0]['type'].add_data.call_count == 0


def test_no_terms_hits(ea):
    ea.rules[0]['use_terms_query'] = True
    ea.rules[0]['query_key'] = 'QWERTY'
    ea.rules[0]['doc_type'] = 'uiop'
    ea.thread_data.current_es.deprecated_search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    assert ea.rules[0]['type'].add_terms_data.call_count == 0


def test_some_hits(ea):
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    hits_dt = generate_hits([START, END])
    ea.thread_data.current_es.search.return_value = hits
    ea.run_query(ea.rules[0], START, END)
    assert ea.rules[0]['type'].add_data.call_count == 1
    ea.rules[0]['type'].add_data.assert_called_with([x['_source'] for x in hits_dt['hits']['hits']])


def test_some_hits_unix(ea):
    ea.rules[0]['timestamp_type'] = 'unix'
    ea.rules[0]['dt_to_ts'] = dt_to_unix
    ea.rules[0]['ts_to_dt'] = unix_to_dt
    hits = generate_hits([dt_to_unix(START), dt_to_unix(END)])
    hits_dt = generate_hits([START, END])
    ea.thread_data.current_es.search.return_value = copy.deepcopy(hits)
    ea.run_query(ea.rules[0], START, END)
    assert ea.rules[0]['type'].add_data.call_count == 1
    ea.rules[0]['type'].add_data.assert_called_with([x['_source'] for x in hits_dt['hits']['hits']])


def _duplicate_hits_generator(timestamps, **kwargs):
    """Generator repeatedly returns identical hits dictionaries
    """
    while True:
        yield generate_hits(timestamps, **kwargs)


def test_duplicate_timestamps(ea):
    ea.thread_data.current_es.search.side_effect = _duplicate_hits_generator([START_TIMESTAMP] * 3, blah='duplicate')
    ea.run_query(ea.rules[0], START, ts_to_dt('2014-01-01T00:00:00Z'))

    assert len(ea.rules[0]['type'].add_data.call_args_list[0][0][0]) == 3
    assert ea.rules[0]['type'].add_data.call_count == 1

    # Run the query again, duplicates will be removed and not added
    ea.run_query(ea.rules[0], ts_to_dt('2014-01-01T00:00:00Z'), END)
    assert ea.rules[0]['type'].add_data.call_count == 1


def test_match(ea):
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    ea.thread_data.current_es.search.return_value = hits
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)

    ea.rules[0]['alert'][0].alert.called_with({'@timestamp': END_TIMESTAMP})
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def test_run_rule_calls_garbage_collect(ea):
    start_time = '2014-09-26T00:00:00Z'
    end_time = '2014-09-26T12:00:00Z'
    ea.buffer_time = datetime.timedelta(hours=1)
    ea.run_every = datetime.timedelta(hours=1)
    with mock.patch.object(ea.rules[0]['type'], 'garbage_collect') as mock_gc, \
            mock.patch.object(ea, 'run_query'):
        ea.run_rule(ea.rules[0], ts_to_dt(end_time), ts_to_dt(start_time))

    # Running ElastAlert every hour for 12 hours, we should see self.garbage_collect called 12 times.
    assert mock_gc.call_count == 12

    # The calls should be spaced 1 hour apart
    expected_calls = [ts_to_dt(start_time) + datetime.timedelta(hours=i) for i in range(1, 13)]
    for e in expected_calls:
        mock_gc.assert_any_call(e)


def run_rule_query_exception(ea, mock_es):
    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es_init:
        mock_es_init.return_value = mock_es
        ea.run_rule(ea.rules[0], END, START)

    # Assert neither add_data nor garbage_collect were called
    # and that starttime did not change
    assert ea.rules[0].get('starttime') == START
    assert ea.rules[0]['type'].add_data.call_count == 0
    assert ea.rules[0]['type'].garbage_collect.call_count == 0
    assert ea.rules[0]['type'].add_count_data.call_count == 0


def test_query_exception(ea):
    mock_es = mock.Mock()
    mock_es.search.side_effect = ElasticsearchException
    run_rule_query_exception(ea, mock_es)


def test_query_exception_count_query(ea):
    ea.rules[0]['use_count_query'] = True
    ea.rules[0]['doc_type'] = 'blahblahblahblah'
    mock_es = mock.Mock()
    mock_es.count.side_effect = ElasticsearchException
    run_rule_query_exception(ea, mock_es)


def test_match_with_module(ea):
    mod = BaseEnhancement(ea.rules[0])
    mod.process = mock.Mock()
    ea.rules[0]['match_enhancements'] = [mod]
    test_match(ea)
    mod.process.assert_called_with({'@timestamp': END, 'num_hits': 0, 'num_matches': 1})


def test_match_with_module_from_pending(ea):
    mod = BaseEnhancement(ea.rules[0])
    mod.process = mock.Mock()
    ea.rules[0]['match_enhancements'] = [mod]
    ea.rules[0].pop('aggregation')
    pending_alert = {'match_body': {'foo': 'bar'}, 'rule_name': ea.rules[0]['name'],
                     'alert_time': START_TIMESTAMP, '@timestamp': START_TIMESTAMP}
    # First call, return the pending alert, second, no associated aggregated alerts
    ea.writeback_es.deprecated_search.side_effect = [{'hits': {'hits': [{'_id': 'ABCD', '_index': 'wb', '_source': pending_alert}]}},
                                                     {'hits': {'hits': []}}]
    ea.send_pending_alerts()
    assert mod.process.call_count == 0

    # If aggregation is set, enhancement IS called
    pending_alert = {'match_body': {'foo': 'bar'}, 'rule_name': ea.rules[0]['name'],
                     'alert_time': START_TIMESTAMP, '@timestamp': START_TIMESTAMP}
    ea.writeback_es.deprecated_search.side_effect = [{'hits': {'hits': [{'_id': 'ABCD', '_index': 'wb', '_source': pending_alert}]}},
                                                     {'hits': {'hits': []}}]
    ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
    ea.send_pending_alerts()
    assert mod.process.call_count == 1


def test_match_with_module_with_agg(ea):
    mod = BaseEnhancement(ea.rules[0])
    mod.process = mock.Mock()
    ea.rules[0]['match_enhancements'] = [mod]
    ea.rules[0]['aggregation'] = datetime.timedelta(minutes=15)
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    ea.thread_data.current_es.search.return_value = hits
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert mod.process.call_count == 0


def test_match_with_enhancements_first(ea):
    mod = BaseEnhancement(ea.rules[0])
    mod.process = mock.Mock()
    ea.rules[0]['match_enhancements'] = [mod]
    ea.rules[0]['aggregation'] = datetime.timedelta(minutes=15)
    ea.rules[0]['run_enhancements_first'] = True
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    ea.thread_data.current_es.search.return_value = hits
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        with mock.patch.object(ea, 'add_aggregated_alert') as add_alert:
            ea.run_rule(ea.rules[0], END, START)
    mod.process.assert_called_with({'@timestamp': END, 'num_hits': 0, 'num_matches': 1})
    assert add_alert.call_count == 1

    # Assert that dropmatchexception behaves properly
    mod.process = mock.MagicMock(side_effect=DropMatchException)
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        with mock.patch.object(ea, 'add_aggregated_alert') as add_alert:
            ea.run_rule(ea.rules[0], END, START)
    mod.process.assert_called_with({'@timestamp': END, 'num_hits': 0, 'num_matches': 1})
    assert add_alert.call_count == 0


def test_agg_matchtime(ea):
    ea.max_aggregation = 1337
    hits_timestamps = ['2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45']
    alerttime1 = dt_to_ts(ts_to_dt(hits_timestamps[0]) + datetime.timedelta(minutes=10))
    hits = generate_hits(hits_timestamps)
    ea.thread_data.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es:
        # Aggregate first two, query over full range
        mock_es.return_value = ea.thread_data.current_es
        ea.rules[0]['aggregate_by_match_time'] = True
        ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
        ea.rules[0]['type'].matches = [{'@timestamp': h} for h in hits_timestamps]
        ea.run_rule(ea.rules[0], END, START)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.writeback_es.index.call_args_list[0][1]['body']
    call2 = ea.writeback_es.index.call_args_list[1][1]['body']
    call3 = ea.writeback_es.index.call_args_list[2][1]['body']
    assert call1['match_body']['@timestamp'] == '2014-09-26T12:34:45'
    assert not call1['alert_sent']
    assert 'aggregate_id' not in call1
    assert call1['alert_time'] == alerttime1

    assert call2['match_body']['@timestamp'] == '2014-09-26T12:40:45'
    assert not call2['alert_sent']
    assert call2['aggregate_id'] == 'ABCD'

    assert call3['match_body']['@timestamp'] == '2014-09-26T12:47:45'
    assert not call3['alert_sent']
    assert 'aggregate_id' not in call3

    # First call - Find all pending alerts (only entries without agg_id)
    # Second call - Find matches with agg_id == 'ABCD'
    # Third call - Find matches with agg_id == 'CDEF'
    ea.writeback_es.deprecated_search.side_effect = [{'hits': {'hits': [{'_id': 'ABCD', '_index': 'wb', '_source': call1},
                                                                        {'_id': 'CDEF', '_index': 'wb', '_source': call3}]}},
                                                     {'hits': {'hits': [{'_id': 'BCDE', '_index': 'wb', '_source': call2}]}},
                                                     {'hits': {'total': 0, 'hits': []}}]

    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es:
        ea.send_pending_alerts()
        # Assert that current_es was refreshed from the aggregate rules
        assert mock_es.called_with(host='', port='')
        assert mock_es.call_count == 2
    assert_alerts(ea, [hits_timestamps[:2], hits_timestamps[2:]])

    call1 = ea.writeback_es.deprecated_search.call_args_list[7][1]['body']
    call2 = ea.writeback_es.deprecated_search.call_args_list[8][1]['body']
    call3 = ea.writeback_es.deprecated_search.call_args_list[9][1]['body']
    call4 = ea.writeback_es.deprecated_search.call_args_list[10][1]['body']

    assert 'alert_time' in call2['filter']['range']
    assert call3['query']['query_string']['query'] == 'aggregate_id:"ABCD"'
    assert call4['query']['query_string']['query'] == 'aggregate_id:"CDEF"'
    assert ea.writeback_es.deprecated_search.call_args_list[9][1]['size'] == 1337


def test_agg_not_matchtime(ea):
    ea.max_aggregation = 1337
    hits_timestamps = ['2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45']
    match_time = ts_to_dt('2014-09-26T12:55:00Z')
    hits = generate_hits(hits_timestamps)
    ea.thread_data.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        with mock.patch('elastalert.elastalert.ts_now', return_value=match_time):
            ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
            ea.rules[0]['type'].matches = [{'@timestamp': h} for h in hits_timestamps]
            ea.run_rule(ea.rules[0], END, START)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.writeback_es.index.call_args_list[0][1]['body']
    call2 = ea.writeback_es.index.call_args_list[1][1]['body']
    call3 = ea.writeback_es.index.call_args_list[2][1]['body']
    assert call1['match_body']['@timestamp'] == '2014-09-26T12:34:45'
    assert not call1['alert_sent']
    assert 'aggregate_id' not in call1
    assert call1['alert_time'] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call2['match_body']['@timestamp'] == '2014-09-26T12:40:45'
    assert not call2['alert_sent']
    assert call2['aggregate_id'] == 'ABCD'

    assert call3['match_body']['@timestamp'] == '2014-09-26T12:47:45'
    assert not call3['alert_sent']
    assert call3['aggregate_id'] == 'ABCD'


def test_agg_cron(ea):
    ea.max_aggregation = 1337
    hits_timestamps = ['2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45']
    hits = generate_hits(hits_timestamps)
    ea.thread_data.current_es.search.return_value = hits
    alerttime1 = dt_to_ts(ts_to_dt('2014-09-26T12:46:00'))
    alerttime2 = dt_to_ts(ts_to_dt('2014-09-26T13:04:00'))

    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        with mock.patch('elastalert.elastalert.croniter.get_next') as mock_ts:
            # Aggregate first two, query over full range
            mock_ts.side_effect = [dt_to_unix(ts_to_dt('2014-09-26T12:46:00')),
                                   dt_to_unix(ts_to_dt('2014-09-26T13:04:00'))]
            ea.rules[0]['aggregation'] = {'schedule': '*/5 * * * *'}
            ea.rules[0]['type'].matches = [{'@timestamp': h} for h in hits_timestamps]
            ea.run_rule(ea.rules[0], END, START)

    # Assert that the three matches were added to Elasticsearch
    call1 = ea.writeback_es.index.call_args_list[0][1]['body']
    call2 = ea.writeback_es.index.call_args_list[1][1]['body']
    call3 = ea.writeback_es.index.call_args_list[2][1]['body']

    assert call1['match_body']['@timestamp'] == '2014-09-26T12:34:45'
    assert not call1['alert_sent']
    assert 'aggregate_id' not in call1
    assert call1['alert_time'] == alerttime1

    assert call2['match_body']['@timestamp'] == '2014-09-26T12:40:45'
    assert not call2['alert_sent']
    assert call2['aggregate_id'] == 'ABCD'

    assert call3['match_body']['@timestamp'] == '2014-09-26T12:47:45'
    assert call3['alert_time'] == alerttime2
    assert not call3['alert_sent']
    assert 'aggregate_id' not in call3


def test_agg_no_writeback_connectivity(ea):
    """ Tests that if writeback_es throws an exception, the matches will be added to 'agg_matches' and when
    run again, that they will be passed again to add_aggregated_alert """
    hit1, hit2, hit3 = '2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45'
    hits = generate_hits([hit1, hit2, hit3])
    ea.thread_data.current_es.search.return_value = hits
    ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
    ea.rules[0]['type'].matches = [{'@timestamp': hit1},
                                   {'@timestamp': hit2},
                                   {'@timestamp': hit3}]
    ea.writeback_es.index.side_effect = elasticsearch.exceptions.ElasticsearchException('Nope')
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        with mock.patch.object(ea, 'find_pending_aggregate_alert', return_value=None):
            ea.run_rule(ea.rules[0], END, START)

    assert ea.rules[0]['agg_matches'] == [{'@timestamp': hit1, 'num_hits': 0, 'num_matches': 3},
                                          {'@timestamp': hit2, 'num_hits': 0, 'num_matches': 3},
                                          {'@timestamp': hit3, 'num_hits': 0, 'num_matches': 3}]

    ea.thread_data.current_es.search.return_value = {'hits': {'total': 0, 'hits': []}}
    ea.add_aggregated_alert = mock.Mock()

    with mock.patch.object(ea, 'run_query'):
        ea.run_rule(ea.rules[0], END, START)

    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit1, 'num_hits': 0, 'num_matches': 3}, ea.rules[0])
    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit2, 'num_hits': 0, 'num_matches': 3}, ea.rules[0])
    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit3, 'num_hits': 0, 'num_matches': 3}, ea.rules[0])


def test_agg_with_aggregation_key(ea):
    ea.max_aggregation = 1337
    hits_timestamps = ['2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:43:45']
    match_time = ts_to_dt('2014-09-26T12:45:00Z')
    hits = generate_hits(hits_timestamps)
    ea.thread_data.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es:
        mock_es.return_value = ea.thread_data.current_es
        with mock.patch('elastalert.elastalert.ts_now', return_value=match_time):
            ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
            ea.rules[0]['type'].matches = [{'@timestamp': h} for h in hits_timestamps]
            # Hit1 and Hit3 should be aggregated together, since they have same query_key value
            ea.rules[0]['type'].matches[0]['key'] = 'Key Value 1'
            ea.rules[0]['type'].matches[1]['key'] = 'Key Value 2'
            ea.rules[0]['type'].matches[2]['key'] = 'Key Value 1'
            ea.rules[0]['aggregation_key'] = 'key'
            ea.run_rule(ea.rules[0], END, START)

    # Assert that the three matches were added to elasticsearch
    call1 = ea.writeback_es.index.call_args_list[0][1]['body']
    call2 = ea.writeback_es.index.call_args_list[1][1]['body']
    call3 = ea.writeback_es.index.call_args_list[2][1]['body']
    assert call1['match_body']['key'] == 'Key Value 1'
    assert not call1['alert_sent']
    assert 'aggregate_id' not in call1
    assert 'aggregation_key' in call1
    assert call1['aggregation_key'] == 'Key Value 1'
    assert call1['alert_time'] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call2['match_body']['key'] == 'Key Value 2'
    assert not call2['alert_sent']
    assert 'aggregate_id' not in call2
    assert 'aggregation_key' in call2
    assert call2['aggregation_key'] == 'Key Value 2'
    assert call2['alert_time'] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    assert call3['match_body']['key'] == 'Key Value 1'
    assert not call3['alert_sent']
    # Call3 should have it's aggregate_id set to call1's _id
    # It should also have the same alert_time as call1
    assert call3['aggregate_id'] == 'ABCD'
    assert 'aggregation_key' in call3
    assert call3['aggregation_key'] == 'Key Value 1'
    assert call3['alert_time'] == dt_to_ts(match_time + datetime.timedelta(minutes=10))

    # First call - Find all pending alerts (only entries without agg_id)
    # Second call - Find matches with agg_id == 'ABCD'
    # Third call - Find matches with agg_id == 'CDEF'
    ea.writeback_es.deprecated_search.side_effect = [{'hits': {'hits': [{'_id': 'ABCD', '_index': 'wb', '_source': call1},
                                                                        {'_id': 'CDEF', '_index': 'wb', '_source': call2}]}},
                                                     {'hits': {'hits': [{'_id': 'BCDE', '_index': 'wb', '_source': call3}]}},
                                                     {'hits': {'total': 0, 'hits': []}}]

    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es:
        mock_es.return_value = ea.thread_data.current_es
        ea.send_pending_alerts()
        # Assert that current_es was refreshed from the aggregate rules
        assert mock_es.called_with(host='', port='')
        assert mock_es.call_count == 2
    assert_alerts(ea, [[hits_timestamps[0], hits_timestamps[2]], [hits_timestamps[1]]])

    call1 = ea.writeback_es.deprecated_search.call_args_list[7][1]['body']
    call2 = ea.writeback_es.deprecated_search.call_args_list[8][1]['body']
    call3 = ea.writeback_es.deprecated_search.call_args_list[9][1]['body']
    call4 = ea.writeback_es.deprecated_search.call_args_list[10][1]['body']

    assert 'alert_time' in call2['filter']['range']
    assert call3['query']['query_string']['query'] == 'aggregate_id:"ABCD"'
    assert call4['query']['query_string']['query'] == 'aggregate_id:"CDEF"'
    assert ea.writeback_es.deprecated_search.call_args_list[9][1]['size'] == 1337


def test_silence(ea):
    # Silence test rule for 4 hours
    ea.args.rule = 'test_rule.yaml'  # Not a real name, just has to be set
    ea.args.silence = 'hours=4'
    ea.silence()

    # Don't alert even with a match
    match = [{'@timestamp': '2014-11-17T00:00:00'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 0

    # Mock ts_now() to +5 hours, alert on match
    match = [{'@timestamp': '2014-11-17T00:00:00'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.elasticsearch_client'):
            # Converted twice to add tzinfo
            mock_ts.return_value = ts_to_dt(dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5)))
            ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def test_compound_query_key(ea):
    ea.rules[0]['query_key'] = 'this,that,those'
    ea.rules[0]['compound_query_key'] = ['this', 'that', 'those']
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP], this='abc', that='☃', those=4)
    ea.thread_data.current_es.search.return_value = hits
    ea.run_query(ea.rules[0], START, END)
    call_args = ea.rules[0]['type'].add_data.call_args_list[0]
    assert 'this,that,those' in call_args[0][0][0]
    assert call_args[0][0][0]['this,that,those'] == 'abc, ☃, 4'


def test_silence_query_key(ea):
    # Silence test rule for 4 hours
    ea.args.rule = 'test_rule.yaml'  # Not a real name, just has to be set
    ea.args.silence = 'hours=4'
    ea.silence('anytest.qlo')

    # Don't alert even with a match
    match = [{'@timestamp': '2014-11-17T00:00:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    ea.rules[0]['query_key'] = 'username'
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 0

    # If there is a new record with a different value for the query_key, we should get an alert
    match = [{'@timestamp': '2014-11-17T00:00:01', 'username': 'dpopes'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Mock ts_now() to +5 hours, alert on match
    match = [{'@timestamp': '2014-11-17T00:00:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.elasticsearch_client'):
            # Converted twice to add tzinfo
            mock_ts.return_value = ts_to_dt(dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5)))
            ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 2


def test_realert(ea):
    hits = ['2014-09-26T12:35:%sZ' % (x) for x in range(60)]
    matches = [{'@timestamp': x} for x in hits]
    ea.thread_data.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.rules[0]['realert'] = datetime.timedelta(seconds=50)
        ea.rules[0]['type'].matches = matches
        ea.run_rule(ea.rules[0], END, START)
        assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Doesn't alert again
    matches = [{'@timestamp': x} for x in hits]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
        ea.rules[0]['type'].matches = matches
        assert ea.rules[0]['alert'][0].alert.call_count == 1

    # mock ts_now() to past the realert time
    matches = [{'@timestamp': hits[0]}]
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.elasticsearch_client'):
            # mock_ts is converted twice to add tzinfo
            mock_ts.return_value = ts_to_dt(dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(minutes=10)))
            ea.rules[0]['type'].matches = matches
            ea.run_rule(ea.rules[0], END, START)
            assert ea.rules[0]['alert'][0].alert.call_count == 2


def test_realert_with_query_key(ea):
    ea.rules[0]['query_key'] = 'username'
    ea.rules[0]['realert'] = datetime.timedelta(minutes=10)

    # Alert and silence username: qlo
    match = [{'@timestamp': '2014-11-17T00:00:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Dont alert again for same username
    match = [{'@timestamp': '2014-11-17T00:05:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Do alert with a different value
    match = [{'@timestamp': '2014-11-17T00:05:00', 'username': ''}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 2

    # Alert with query_key missing
    match = [{'@timestamp': '2014-11-17T00:05:00'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 3

    # Still alert with a different value
    match = [{'@timestamp': '2014-11-17T00:05:00', 'username': 'ghengis_khan'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 4


def test_realert_with_nested_query_key(ea):
    ea.rules[0]['query_key'] = 'user.name'
    ea.rules[0]['realert'] = datetime.timedelta(minutes=10)

    # Alert and silence username: qlo
    match = [{'@timestamp': '2014-11-17T00:00:00', 'user': {'name': 'qlo'}}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Dont alert again for same username
    match = [{'@timestamp': '2014-11-17T00:05:00', 'user': {'name': 'qlo'}}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def test_count(ea):
    ea.rules[0]['use_count_query'] = True
    ea.rules[0]['doc_type'] = 'doctype'
    with mock.patch('elastalert.elastalert.elasticsearch_client'), \
            mock.patch.object(ea, 'get_hits_count') as mock_hits:
        ea.run_rule(ea.rules[0], END, START)

    # Assert that es.count is run against every run_every timeframe between START and END
    start = START
    query = {
        'query': {'filtered': {
            'filter': {'bool': {'must': [{'range': {'@timestamp': {'lte': END_TIMESTAMP, 'gt': START_TIMESTAMP}}}]}}}}}
    while END - start > ea.run_every:
        end = start + ea.run_every
        query['query']['filtered']['filter']['bool']['must'][0]['range']['@timestamp']['lte'] = dt_to_ts(end)
        query['query']['filtered']['filter']['bool']['must'][0]['range']['@timestamp']['gt'] = dt_to_ts(start)
        mock_hits.assert_any_call(mock.ANY, start, end, mock.ANY)
        start = start + ea.run_every


def run_and_assert_segmented_queries(ea, start, end, segment_size):
    with mock.patch.object(ea, 'run_query') as mock_run_query:
        ea.run_rule(ea.rules[0], end, start)
        original_end, original_start = end, start
        for call_args in mock_run_query.call_args_list:
            end = min(start + segment_size, original_end)
            assert call_args[0][1:3] == (start, end)
            start += segment_size

        # Assert elastalert_status was created for the entire time range
        assert ea.writeback_es.index.call_args_list[-1][1]['body']['starttime'] == dt_to_ts(original_start)
        if ea.rules[0].get('aggregation_query_element'):
            assert ea.writeback_es.index.call_args_list[-1][1]['body']['endtime'] == dt_to_ts(
                original_end - (original_end - end))
            assert original_end - end < segment_size
        else:
            assert ea.writeback_es.index.call_args_list[-1][1]['body']['endtime'] == dt_to_ts(original_end)


def test_query_segmenting_reset_num_hits(ea):
    # Tests that num_hits gets reset every time run_query is run
    def assert_num_hits_reset():
        assert ea.thread_data.num_hits == 0
        ea.thread_data.num_hits += 10
    with mock.patch.object(ea, 'run_query') as mock_run_query:
        mock_run_query.side_effect = assert_num_hits_reset()
        ea.run_rule(ea.rules[0], END, START)
    assert mock_run_query.call_count > 1


def test_query_segmenting(ea):
    # buffer_time segments with normal queries
    ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=53)
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        run_and_assert_segmented_queries(ea, START, END, ea.rules[0]['buffer_time'])

    # run_every segments with count queries
    ea.rules[0]['use_count_query'] = True
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        run_and_assert_segmented_queries(ea, START, END, ea.run_every)

    # run_every segments with terms queries
    ea.rules[0].pop('use_count_query')
    ea.rules[0]['use_terms_query'] = True
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        run_and_assert_segmented_queries(ea, START, END, ea.run_every)

    # buffer_time segments with terms queries
    ea.rules[0].pop('use_terms_query')
    ea.rules[0]['aggregation_query_element'] = {'term': 'term_val'}
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=30)
        run_and_assert_segmented_queries(ea, START, END, ea.rules[0]['buffer_time'])

    # partial segment size scenario
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=53)
        run_and_assert_segmented_queries(ea, START, END, ea.rules[0]['buffer_time'])

    # run every segmenting
    ea.rules[0]['use_run_every_query_size'] = True
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        run_and_assert_segmented_queries(ea, START, END, ea.run_every)


def test_get_starttime(ea):
    endtime = '2015-01-01T00:00:00Z'
    mock_es = mock.Mock()
    mock_es.search.return_value = {'hits': {'hits': [{'_source': {'endtime': endtime}}]}}
    mock_es.info.return_value = {'version': {'number': '2.0'}}
    ea.writeback_es = mock_es

    # 4 days old, will return endtime
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        mock_ts.return_value = ts_to_dt('2015-01-05T00:00:00Z')  # 4 days ahead of the endtime
        assert ea.get_starttime(ea.rules[0]) == ts_to_dt(endtime)

    # 10 days old, will return None
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        mock_ts.return_value = ts_to_dt('2015-01-11T00:00:00Z')  # 10 days ahead of the endtime
        assert ea.get_starttime(ea.rules[0]) is None


def test_set_starttime(ea):
    # standard query, no starttime, no last run
    end = ts_to_dt('2014-10-10T10:10:10')
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == end - ea.buffer_time

    # Standard query, no starttime, rule specific buffer_time
    ea.rules[0].pop('starttime')
    ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=37)
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == end - datetime.timedelta(minutes=37)
    ea.rules[0].pop('buffer_time')

    # Standard query, no starttime, last run
    ea.rules[0].pop('starttime')
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = ts_to_dt('2014-10-10T00:00:00')
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == ts_to_dt('2014-10-10T00:00:00')

    # Standard query, no starttime, last run, assure buffer_time doesn't go past
    ea.rules[0].pop('starttime')
    ea.rules[0]['buffer_time'] = datetime.timedelta(weeks=1000)
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = ts_to_dt('2014-10-09T00:00:00')
        # First call sets minumum_time
        ea.set_starttime(ea.rules[0], end)
    # Second call uses buffer_time, but it goes past minimum
    ea.set_starttime(ea.rules[0], end)
    assert ea.rules[0]['starttime'] == ts_to_dt('2014-10-09T00:00:00')

    # Standard query, starttime
    ea.rules[0].pop('buffer_time')
    ea.rules[0].pop('minimum_starttime')
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 0
    assert ea.rules[0]['starttime'] == end - ea.buffer_time

    # Count query, starttime, no previous endtime
    ea.rules[0]['use_count_query'] = True
    ea.rules[0]['doc_type'] = 'blah'
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 0
    assert ea.rules[0]['starttime'] == end - ea.run_every

    # Count query, with previous endtime
    with mock.patch('elastalert.elastalert.elasticsearch_client'), \
            mock.patch.object(ea, 'get_hits_count'):
        ea.run_rule(ea.rules[0], END, START)
    ea.set_starttime(ea.rules[0], end)
    assert ea.rules[0]['starttime'] == END

    # buffer_time doesn't go past previous endtime
    ea.rules[0].pop('use_count_query')
    ea.rules[0]['previous_endtime'] = end - ea.buffer_time * 2
    ea.set_starttime(ea.rules[0], end)
    assert ea.rules[0]['starttime'] == ea.rules[0]['previous_endtime']

    # Make sure starttime is updated if previous_endtime isn't used
    ea.rules[0]['previous_endtime'] = end - ea.buffer_time / 2
    ea.rules[0]['starttime'] = ts_to_dt('2014-10-09T00:00:01')
    ea.set_starttime(ea.rules[0], end)
    assert ea.rules[0]['starttime'] == end - ea.buffer_time

    # scan_entire_timeframe
    ea.rules[0].pop('previous_endtime')
    ea.rules[0].pop('starttime')
    ea.rules[0]['timeframe'] = datetime.timedelta(days=3)
    ea.rules[0]['scan_entire_timeframe'] = True
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
    assert ea.rules[0]['starttime'] == end - datetime.timedelta(days=3)


def test_kibana_dashboard(ea):
    match = {'@timestamp': '2014-10-11T00:00:00'}
    mock_es = mock.Mock()
    ea.rules[0]['use_kibana_dashboard'] = 'my dashboard'
    with mock.patch('elastalert.elastalert.elasticsearch_client') as mock_es_init:
        mock_es_init.return_value = mock_es

        # No dashboard found
        mock_es.deprecated_search.return_value = {'hits': {'total': 0, 'hits': []}}
        with pytest.raises(EAException):
            ea.use_kibana_link(ea.rules[0], match)
        mock_call = mock_es.deprecated_search.call_args_list[0][1]
        assert mock_call['body'] == {'query': {'term': {'_id': 'my dashboard'}}}

        # Dashboard found
        mock_es.index.return_value = {'_id': 'ABCDEFG'}
        mock_es.deprecated_search.return_value = {'hits': {'hits': [{'_source': {'dashboard': json.dumps(dashboard_temp)}}]}}
        url = ea.use_kibana_link(ea.rules[0], match)
        assert 'ABCDEFG' in url
        db = json.loads(mock_es.index.call_args_list[0][1]['body']['dashboard'])
        assert 'anytest' in db['title']

        # Query key filtering added
        ea.rules[0]['query_key'] = 'foobar'
        match['foobar'] = 'baz'
        url = ea.use_kibana_link(ea.rules[0], match)
        db = json.loads(mock_es.index.call_args_list[-1][1]['body']['dashboard'])
        assert db['services']['filter']['list']['1']['field'] == 'foobar'
        assert db['services']['filter']['list']['1']['query'] == '"baz"'

        # Compound query key
        ea.rules[0]['query_key'] = 'foo,bar'
        ea.rules[0]['compound_query_key'] = ['foo', 'bar']
        match['foo'] = 'cat'
        match['bar'] = 'dog'
        match['foo,bar'] = 'cat, dog'
        url = ea.use_kibana_link(ea.rules[0], match)
        db = json.loads(mock_es.index.call_args_list[-1][1]['body']['dashboard'])
        found_filters = 0
        for filter_id, filter_dict in list(db['services']['filter']['list'].items()):
            if (filter_dict['field'] == 'foo' and filter_dict['query'] == '"cat"') or \
                    (filter_dict['field'] == 'bar' and filter_dict['query'] == '"dog"'):
                found_filters += 1
                continue
        assert found_filters == 2


def test_rule_changes(ea):
    ea.rule_hashes = {'rules/rule1.yaml': 'ABC',
                      'rules/rule2.yaml': 'DEF'}
    run_every = datetime.timedelta(seconds=1)
    ea.rules = [ea.init_rule(rule, True) for rule in [{'rule_file': 'rules/rule1.yaml', 'name': 'rule1', 'filter': [],
                                                       'run_every': run_every},
                                                      {'rule_file': 'rules/rule2.yaml', 'name': 'rule2', 'filter': [],
                                                       'run_every': run_every}]]
    ea.rules[1]['processed_hits'] = ['save me']
    new_hashes = {'rules/rule1.yaml': 'ABC',
                  'rules/rule3.yaml': 'XXX',
                  'rules/rule2.yaml': '!@#$'}

    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            mock_load.side_effect = [{'filter': [], 'name': 'rule2', 'rule_file': 'rules/rule2.yaml', 'run_every': run_every},
                                     {'filter': [], 'name': 'rule3', 'rule_file': 'rules/rule3.yaml', 'run_every': run_every}]
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()

    # All 3 rules still exist
    assert ea.rules[0]['name'] == 'rule1'
    assert ea.rules[1]['name'] == 'rule2'
    assert ea.rules[1]['processed_hits'] == ['save me']
    assert ea.rules[2]['name'] == 'rule3'

    # Assert 2 and 3 were reloaded
    assert mock_load.call_count == 2
    mock_load.assert_any_call('rules/rule2.yaml', ea.conf)
    mock_load.assert_any_call('rules/rule3.yaml', ea.conf)

    # A new rule with a conflicting name wont load
    new_hashes = copy.copy(new_hashes)
    new_hashes.update({'rules/rule4.yaml': 'asdf'})
    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            with mock.patch.object(ea, 'send_notification_email') as mock_send:
                mock_load.return_value = {'filter': [], 'name': 'rule3', 'new': 'stuff',
                                          'rule_file': 'rules/rule4.yaml', 'run_every': run_every}
                mock_hashes.return_value = new_hashes
                ea.load_rule_changes()
                mock_send.assert_called_once_with(exception=mock.ANY, rule_file='rules/rule4.yaml')
    assert len(ea.rules) == 3
    assert not any(['new' in rule for rule in ea.rules])

    # A new rule with is_enabled=False wont load
    new_hashes = copy.copy(new_hashes)
    new_hashes.update({'rules/rule4.yaml': 'asdf'})
    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            mock_load.return_value = {'filter': [], 'name': 'rule4', 'new': 'stuff', 'is_enabled': False,
                                      'rule_file': 'rules/rule4.yaml', 'run_every': run_every}
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()
    assert len(ea.rules) == 3
    assert not any(['new' in rule for rule in ea.rules])

    # An old rule which didn't load gets reloaded
    new_hashes = copy.copy(new_hashes)
    new_hashes['rules/rule4.yaml'] = 'qwerty'
    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            mock_load.return_value = {'filter': [], 'name': 'rule4', 'new': 'stuff', 'rule_file': 'rules/rule4.yaml',
                                      'run_every': run_every}
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()
    assert len(ea.rules) == 4

    # Disable a rule by removing the file
    new_hashes.pop('rules/rule4.yaml')
    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            mock_load.return_value = {'filter': [], 'name': 'rule4', 'new': 'stuff', 'rule_file': 'rules/rule4.yaml',
                                      'run_every': run_every}
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()
    ea.scheduler.remove_job.assert_called_with(job_id='rule4')


def test_strf_index(ea):
    """ Test that the get_index function properly generates indexes spanning days """
    ea.rules[0]['index'] = 'logstash-%Y.%m.%d'
    ea.rules[0]['use_strftime_index'] = True

    # Test formatting with times
    start = ts_to_dt('2015-01-02T12:34:45Z')
    end = ts_to_dt('2015-01-02T16:15:14Z')
    assert ea.get_index(ea.rules[0], start, end) == 'logstash-2015.01.02'
    end = ts_to_dt('2015-01-03T01:02:03Z')
    assert set(ea.get_index(ea.rules[0], start, end).split(',')) == set(['logstash-2015.01.02', 'logstash-2015.01.03'])

    # Test formatting for wildcard
    assert ea.get_index(ea.rules[0]) == 'logstash-*'
    ea.rules[0]['index'] = 'logstash-%Y.%m'
    assert ea.get_index(ea.rules[0]) == 'logstash-*'
    ea.rules[0]['index'] = 'logstash-%Y.%m-stuff'
    assert ea.get_index(ea.rules[0]) == 'logstash-*-stuff'


def test_count_keys(ea):
    ea.rules[0]['timeframe'] = datetime.timedelta(minutes=60)
    ea.rules[0]['top_count_keys'] = ['this', 'that']
    ea.rules[0]['type'].matches = {'@timestamp': END}
    ea.rules[0]['doc_type'] = 'blah'
    buckets = [{'aggregations': {
        'filtered': {'counts': {'buckets': [{'key': 'a', 'doc_count': 10}, {'key': 'b', 'doc_count': 5}]}}}},
        {'aggregations': {'filtered': {
            'counts': {'buckets': [{'key': 'd', 'doc_count': 10}, {'key': 'c', 'doc_count': 12}]}}}}]
    ea.thread_data.current_es.deprecated_search.side_effect = buckets
    counts = ea.get_top_counts(ea.rules[0], START, END, ['this', 'that'])
    calls = ea.thread_data.current_es.deprecated_search.call_args_list
    assert calls[0][1]['search_type'] == 'count'
    assert calls[0][1]['body']['aggs']['filtered']['aggs']['counts']['terms'] == {'field': 'this', 'size': 5,
                                                                                  'min_doc_count': 1}
    assert counts['top_events_this'] == {'a': 10, 'b': 5}
    assert counts['top_events_that'] == {'d': 10, 'c': 12}


def test_exponential_realert(ea):
    ea.rules[0]['exponential_realert'] = datetime.timedelta(days=1)  # 1 day ~ 10 * 2**13 seconds
    ea.rules[0]['realert'] = datetime.timedelta(seconds=10)

    until = ts_to_dt('2015-03-24T00:00:00')
    ts5s = until + datetime.timedelta(seconds=5)
    ts15s = until + datetime.timedelta(seconds=15)
    ts1m = until + datetime.timedelta(minutes=1)
    ts5m = until + datetime.timedelta(minutes=5)
    ts4h = until + datetime.timedelta(hours=4)

    test_values = [(ts5s, until, 0),  # Exp will increase to 1, 10*2**0 = 10s
                   (ts15s, until, 0),  # Exp will stay at 0, 10*2**0 = 10s
                   (ts15s, until, 1),  # Exp will increase to 2, 10*2**1 = 20s
                   (ts1m, until, 2),  # Exp will decrease to 1, 10*2**2 = 40s
                   (ts1m, until, 3),  # Exp will increase to 4, 10*2**3 = 1m20s
                   (ts5m, until, 1),  # Exp will lower back to 0, 10*2**1 = 20s
                   (ts4h, until, 9),  # Exp will lower back to 0, 10*2**9 = 1h25m
                   (ts4h, until, 10),  # Exp will lower back to 9, 10*2**10 = 2h50m
                   (ts4h, until, 11)]  # Exp will increase to 12, 10*2**11 = 5h
    results = (1, 0, 2, 1, 4, 0, 0, 9, 12)
    next_res = iter(results)
    for args in test_values:
        ea.silence_cache[ea.rules[0]['name']] = (args[1], args[2])
        next_alert, exponent = ea.next_alert_time(ea.rules[0], ea.rules[0]['name'], args[0])
        assert exponent == next(next_res)


def test_wait_until_responsive(ea):
    """Unblock as soon as ElasticSearch becomes responsive."""

    # Takes a while before becoming responsive.
    ea.writeback_es.indices.exists.side_effect = [
        ConnectionError(),  # ES is not yet responsive.
        False,  # index does not yet exist.
        True,
    ]

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0, 4.0]
    timeout = datetime.timedelta(seconds=3.5)
    with mock.patch('time.sleep') as sleep:
        ea.wait_until_responsive(timeout=timeout, clock=clock)

    # Sleep as little as we can.
    sleep.mock_calls == [
        mock.call(1.0),
    ]


def test_wait_until_responsive_timeout_es_not_available(ea, caplog):
    """Bail out if ElasticSearch doesn't (quickly) become responsive."""

    # Never becomes responsive :-)
    ea.writeback_es.ping.return_value = False
    ea.writeback_es.indices.exists.return_value = False

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0]
    timeout = datetime.timedelta(seconds=2.5)
    with mock.patch('time.sleep') as sleep:
        with pytest.raises(SystemExit) as exc:
            ea.wait_until_responsive(timeout=timeout, clock=clock)
        assert exc.value.code == 1

    # Ensure we get useful diagnostics.
    user, level, message = caplog.record_tuples[0]
    assert 'Could not reach ElasticSearch at "es:14900".' in message

    # Slept until we passed the deadline.
    sleep.mock_calls == [
        mock.call(1.0),
        mock.call(1.0),
        mock.call(1.0),
    ]


def test_wait_until_responsive_timeout_index_does_not_exist(ea, caplog):
    """Bail out if ElasticSearch doesn't (quickly) become responsive."""

    # Never becomes responsive :-)
    ea.writeback_es.ping.return_value = True
    ea.writeback_es.indices.exists.return_value = False

    clock = mock.MagicMock()
    clock.side_effect = [0.0, 1.0, 2.0, 3.0]
    timeout = datetime.timedelta(seconds=2.5)
    with mock.patch('time.sleep') as sleep:
        with pytest.raises(SystemExit) as exc:
            ea.wait_until_responsive(timeout=timeout, clock=clock)
        assert exc.value.code == 1

    # Ensure we get useful diagnostics.
    user, level, message = caplog.record_tuples[0]
    assert 'Writeback index "wb" does not exist, did you run `elastalert-create-index`?' in message

    # Slept until we passed the deadline.
    sleep.mock_calls == [
        mock.call(1.0),
        mock.call(1.0),
        mock.call(1.0),
    ]


def test_stop(ea):
    """ The purpose of this test is to make sure that calling ElastAlerter.stop() will break it
    out of a ElastAlerter.start() loop. This method exists to provide a mechanism for running
    ElastAlert with threads and thus must be tested with threads. mock_loop verifies the loop
    is running and will call stop after several iterations. """

    # Exit the thread on the fourth iteration
    def mock_loop():
        for i in range(3):
            assert ea.running
            yield
        ea.stop()

    with mock.patch.object(ea, 'sleep_for', return_value=None):
        with mock.patch.object(ea, 'sleep_for') as mock_run:
            mock_run.side_effect = mock_loop()
            start_thread = threading.Thread(target=ea.start)
            # Set as daemon to prevent a failed test from blocking exit
            start_thread.daemon = True
            start_thread.start()

            # Give it a few seconds to run the loop
            start_thread.join(5)

            assert not ea.running
            assert not start_thread.is_alive()
            assert mock_run.call_count == 4


def test_notify_email(ea):
    mock_smtp = mock.Mock()
    ea.rules[0]['notify_email'] = ['foo@foo.foo', 'bar@bar.bar']
    with mock.patch('elastalert.elastalert.SMTP') as mock_smtp_f:
        mock_smtp_f.return_value = mock_smtp

        # Notify_email from rules, array
        ea.send_notification_email('omg', rule=ea.rules[0])
        assert set(mock_smtp.sendmail.call_args_list[0][0][1]) == set(ea.rules[0]['notify_email'])

        # With ea.notify_email
        ea.notify_email = ['baz@baz.baz']
        ea.send_notification_email('omg', rule=ea.rules[0])
        assert set(mock_smtp.sendmail.call_args_list[1][0][1]) == set(['baz@baz.baz'] + ea.rules[0]['notify_email'])

        # With ea.notify email but as single string
        ea.rules[0]['notify_email'] = 'foo@foo.foo'
        ea.send_notification_email('omg', rule=ea.rules[0])
        assert set(mock_smtp.sendmail.call_args_list[2][0][1]) == set(['baz@baz.baz', 'foo@foo.foo'])

        # None from rule
        ea.rules[0].pop('notify_email')
        ea.send_notification_email('omg', rule=ea.rules[0])
        assert set(mock_smtp.sendmail.call_args_list[3][0][1]) == set(['baz@baz.baz'])


def test_uncaught_exceptions(ea):
    e = Exception("Errors yo!")

    # With disabling set to false
    ea.disable_rules_on_error = False
    ea.handle_uncaught_exception(e, ea.rules[0])
    assert len(ea.rules) == 1
    assert len(ea.disabled_rules) == 0

    # With disabling set to true
    ea.disable_rules_on_error = True
    ea.handle_uncaught_exception(e, ea.rules[0])
    assert len(ea.rules) == 0
    assert len(ea.disabled_rules) == 1

    # Changing the file should re-enable it
    ea.rule_hashes = {'blah.yaml': 'abc'}
    new_hashes = {'blah.yaml': 'def'}
    with mock.patch.object(ea.conf['rules_loader'], 'get_hashes') as mock_hashes:
        with mock.patch.object(ea.conf['rules_loader'], 'load_configuration') as mock_load:
            mock_load.side_effect = [ea.disabled_rules[0]]
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()
    assert len(ea.rules) == 1
    assert len(ea.disabled_rules) == 0

    # Notify email is sent
    ea.notify_email = 'qlo@example.com'
    with mock.patch.object(ea, 'send_notification_email') as mock_email:
        ea.handle_uncaught_exception(e, ea.rules[0])
    assert mock_email.call_args_list[0][1] == {'exception': e, 'rule': ea.disabled_rules[0]}


def test_get_top_counts_handles_no_hits_returned(ea):
    with mock.patch.object(ea, 'get_hits_terms') as mock_hits:
        mock_hits.return_value = None

        rule = ea.rules[0]
        starttime = datetime.datetime.now() - datetime.timedelta(minutes=10)
        endtime = datetime.datetime.now()
        keys = ['foo']

        all_counts = ea.get_top_counts(rule, starttime, endtime, keys)
        assert all_counts == {'top_events_foo': {}}


def test_remove_old_events(ea):
    now = ts_now()
    minute = datetime.timedelta(minutes=1)
    ea.rules[0]['processed_hits'] = {'foo': now - minute,
                                     'bar': now - minute * 5,
                                     'baz': now - minute * 15}
    ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=10)

    # With a query delay, only events older than 20 minutes will be removed (none)
    ea.rules[0]['query_delay'] = datetime.timedelta(minutes=10)
    ea.remove_old_events(ea.rules[0])
    assert len(ea.rules[0]['processed_hits']) == 3

    # With no query delay, the 15 minute old event will be removed
    ea.rules[0].pop('query_delay')
    ea.remove_old_events(ea.rules[0])
    assert len(ea.rules[0]['processed_hits']) == 2
    assert 'baz' not in ea.rules[0]['processed_hits']


def test_query_with_whitelist_filter_es(ea):
    ea.rules[0]['_source_enabled'] = False
    ea.rules[0]['five'] = False
    ea.rules[0]['filter'] = [{'query_string': {'query': 'baz'}}]
    ea.rules[0]['compare_key'] = "username"
    ea.rules[0]['whitelist'] = ['xudan1', 'xudan12', 'aa1', 'bb1']
    new_rule = copy.copy(ea.rules[0])
    ea.init_rule(new_rule, True)
    assert 'NOT username:"xudan1" AND NOT username:"xudan12" AND NOT username:"aa1"' \
           in new_rule['filter'][-1]['query']['query_string']['query']


def test_query_with_whitelist_filter_es_five(ea_sixsix):
    ea_sixsix.rules[0]['_source_enabled'] = False
    ea_sixsix.rules[0]['filter'] = [{'query_string': {'query': 'baz'}}]
    ea_sixsix.rules[0]['compare_key'] = "username"
    ea_sixsix.rules[0]['whitelist'] = ['xudan1', 'xudan12', 'aa1', 'bb1']
    new_rule = copy.copy(ea_sixsix.rules[0])
    ea_sixsix.init_rule(new_rule, True)
    assert 'NOT username:"xudan1" AND NOT username:"xudan12" AND NOT username:"aa1"' in \
           new_rule['filter'][-1]['query_string']['query']


def test_query_with_blacklist_filter_es(ea):
    ea.rules[0]['_source_enabled'] = False
    ea.rules[0]['filter'] = [{'query_string': {'query': 'baz'}}]
    ea.rules[0]['compare_key'] = "username"
    ea.rules[0]['blacklist'] = ['xudan1', 'xudan12', 'aa1', 'bb1']
    new_rule = copy.copy(ea.rules[0])
    ea.init_rule(new_rule, True)
    assert 'username:"xudan1" OR username:"xudan12" OR username:"aa1"' in \
           new_rule['filter'][-1]['query']['query_string']['query']


def test_query_with_blacklist_filter_es_five(ea_sixsix):
    ea_sixsix.rules[0]['_source_enabled'] = False
    ea_sixsix.rules[0]['filter'] = [{'query_string': {'query': 'baz'}}]
    ea_sixsix.rules[0]['compare_key'] = "username"
    ea_sixsix.rules[0]['blacklist'] = ['xudan1', 'xudan12', 'aa1', 'bb1']
    ea_sixsix.rules[0]['blacklist'] = ['xudan1', 'xudan12', 'aa1', 'bb1']
    new_rule = copy.copy(ea_sixsix.rules[0])
    ea_sixsix.init_rule(new_rule, True)
    assert 'username:"xudan1" OR username:"xudan12" OR username:"aa1"' in new_rule['filter'][-1]['query_string'][
        'query']


def test_handle_rule_execution_error(ea, caplog):
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.rules[0]['aggregate_by_match_time'] = True
        ea.rules[0]['summary_table_fields'] = ['@timestamp']
        ea.rules[0]['aggregation_key'] = ['service.name']
        ea.rules[0]['alert_text_type'] = 'aggregation_summary_only'
        ea.rules[0]['query_delay'] = 'a'
        new_rule = copy.copy(ea.rules[0])
        ea.init_rule(new_rule, True)

        ea.handle_rule_execution(ea.rules[0])
        user, level, message = caplog.record_tuples[0]
        assert '[handle_rule_execution]Error parsing query_delay send time format' in message


def test_remove_old_events_error(ea, caplog):
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.rules[0]['aggregate_by_match_time'] = True
        ea.rules[0]['summary_table_fields'] = ['@timestamp']
        ea.rules[0]['aggregation_key'] = ['service.name']
        ea.rules[0]['alert_text_type'] = 'aggregation_summary_only'
        ea.rules[0]['query_delay'] = 'a'
        new_rule = copy.copy(ea.rules[0])
        ea.init_rule(new_rule, True)

        ea.remove_old_events(ea.rules[0])
        user, level, message = caplog.record_tuples[0]
        assert '[remove_old_events]Error parsing query_delay send time format' in message


def test_add_aggregated_alert_error(ea, caplog):
    mod = BaseEnhancement(ea.rules[0])
    mod.process = mock.Mock()
    ea.rules[0]['match_enhancements'] = [mod]
    ea.rules[0]['aggregation'] = {"hour": 5}
    ea.rules[0]['run_enhancements_first'] = True
    ea.rules[0]['aggregate_by_match_time'] = True
    hits = generate_hits([START_TIMESTAMP, END_TIMESTAMP])
    ea.thread_data.current_es.search.return_value = hits
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.elasticsearch_client'):
        ea.run_rule(ea.rules[0], END, START)
        user, level, message = caplog.record_tuples[0]
        exceptd = "[add_aggregated_alert]"
        exceptd += "Error parsing aggregate send time format unsupported operand type(s) for +: 'datetime.datetime' and 'dict'"
        assert exceptd in message


def test_get_elasticsearch_client_same_rule(ea):
    x = ea.get_elasticsearch_client(ea.rules[0])
    y = ea.get_elasticsearch_client(ea.rules[0])
    assert x is y, "Should return same client for the same rule"


def test_get_elasticsearch_client_different_rule(ea):
    x_rule = ea.rules[0]
    x = ea.get_elasticsearch_client(x_rule)

    y_rule = copy.copy(x_rule)
    y_rule['name'] = 'different_rule'
    y = ea.get_elasticsearch_client(y_rule)

    assert x is not y, 'Should return unique client for each rule'


def test_base_enhancement_process_error(ea):
    try:
        be = BaseEnhancement(ea.rules[0])
        be.process('')
        assert False
    except NotImplementedError:
        assert True


def test_time_enhancement(ea):
    be = BaseEnhancement(ea.rules[0])
    te = TimeEnhancement(be)
    match = {
        '@timestamp': '2021-01-01T00:00:00',
        'somefield': 'foobarbaz'
    }
    te.process(match)
    excepted = '2021-01-01 00:00 UTC'
    assert match['@timestamp'] == excepted
