# -*- coding: utf-8 -*-
import copy
import datetime
import json

import elasticsearch
import mock
import pytest
from elasticsearch.exceptions import ElasticsearchException

from elastalert.enhancements import BaseEnhancement
from elastalert.kibana import dashboard_temp
from elastalert.util import dt_to_ts
from elastalert.util import EAException
from elastalert.util import ts_add
from elastalert.util import ts_delta
from elastalert.util import ts_to_dt


START = '2014-09-26T12:34:45'
END = '2014-09-27T12:34:45'


def _set_hits(ea_inst, hits):
    res = {'hits': {'hits': hits}}
    ea_inst.client_es.return_value = res


def generate_hits(timestamps, **kwargs):
    hits = []
    id_iter = xrange(len(timestamps)).__iter__()
    for ts in timestamps:
        data = {'_id': 'id' + str(id_iter.next()), '_source': {'@timestamp': ts}}
        for key, item in kwargs.iteritems():
            data['_source'][key] = item
        hits.append(data)
    return {'hits': {'hits': hits}}


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
    new_rule = copy.copy(ea.rules[0])
    map(new_rule.pop, ['agg_matches', 'current_aggregate_id', 'processed_hits'])

    # Properties are copied from ea.rules[0]
    ea.rules[0]['starttime'] = '2014-01-02T00:11:22'
    ea.rules[0]['processed_hits'] = ['abcdefg']
    new_rule = ea.init_rule(new_rule, False)
    for prop in ['starttime', 'agg_matches', 'current_aggregate_id', 'processed_hits']:
        assert new_rule[prop] == ea.rules[0][prop]

    # Properties are fresh
    new_rule = ea.init_rule(new_rule, True)
    new_rule.pop('starttime')
    assert 'starttime' not in new_rule
    assert new_rule['processed_hits'] == {}


def test_query(ea):
    ea.current_es.search.return_value = {'hits': {'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    ea.current_es.search.assert_called_with(body={'filter': {'bool': {'must': [{'range': {'@timestamp': {'to': END, 'from': START}}}]}}, 'sort': [{'@timestamp': {'order': 'asc'}}]}, index='idx', _source_include=['@timestamp'], size=100000)


def test_no_hits(ea):
    ea.current_es.search.return_value = {'hits': {'hits': []}}
    ea.run_query(ea.rules[0], START, END)
    assert ea.rules[0]['type'].add_data.call_count == 0


def test_some_hits(ea):
    hits = generate_hits([START, END])
    ea.current_es.search.return_value = hits
    ea.run_query(ea.rules[0], START, END)

    assert ea.rules[0]['type'].add_data.call_count == 1
    ea.rules[0]['type'].add_data.assert_called_with([x['_source'] for x in hits['hits']['hits']])


def test_duplicate_timestamps(ea):
    hits = generate_hits([START] * 3, blah='duplicate')
    ea.current_es.search.return_value = hits
    ea.run_query(ea.rules[0], START, '2014-01-01T00:00:00Z')

    assert len(ea.rules[0]['type'].add_data.call_args_list[0][0][0]) == 3
    assert ea.rules[0]['type'].add_data.call_count == 1

    # Run the query again, duplicates will be removed and not added
    ea.run_query(ea.rules[0], '2014-01-01T00:00:00Z', END)

    assert ea.rules[0]['type'].add_data.call_count == 1


def test_match(ea):
    hits = generate_hits([START, END])
    ea.current_es.search.return_value = hits
    ea.rules[0]['type'].matches = [{'@timestamp': END}]
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)

    ea.rules[0]['alert'][0].alert.called_with({'@timestamp': END})
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def run_rule_query_exception(ea, mock_es):
    with mock.patch('elastalert.elastalert.Elasticsearch') as mock_es_init:
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
    assert mod.process.called_with({'@timestamp': END})


def test_agg(ea):
    hit1, hit2, hit3 = '2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45'
    alerttime1 = ts_to_dt(hit1) + datetime.timedelta(minutes=10)
    hits = generate_hits([hit1, hit2, hit3])
    ea.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        # Aggregate first two, query over full range
        ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
        ea.rules[0]['type'].matches = [{'@timestamp': hit1},
                                       {'@timestamp': hit2},
                                       {'@timestamp': hit3}]
        ea.run_rule(ea.rules[0], END, START)

    # Assert that the three matches were added to elasticsearch
    call1 = ea.writeback_es.create.call_args_list[0][1]['body']
    call2 = ea.writeback_es.create.call_args_list[1][1]['body']
    call3 = ea.writeback_es.create.call_args_list[2][1]['body']

    assert call1['match_body'] == {'@timestamp': '2014-09-26T12:34:45'}
    assert not call1['alert_sent']
    assert 'aggregate_id' not in call1
    assert call1['alert_time'] == alerttime1

    assert call2['match_body'] == {'@timestamp': '2014-09-26T12:40:45'}
    assert not call2['alert_sent']
    assert call2['aggregate_id'] == 'ABCD'

    assert call3['match_body'] == {'@timestamp': '2014-09-26T12:47:45'}
    assert not call3['alert_sent']
    assert 'aggregate_id' not in call3

    # First call - Find all pending alerts
    # Second call - Find matches with agg_id == 'ABCD'
    # Third call - Find matches with agg_id == 'CDEF'
    ea.writeback_es.search.side_effect = [{'hits': {'hits': [{'_id': 'ABCD', '_source': call1},
                                                             {'_id': 'BCDE', '_source': call2},
                                                             {'_id': 'CDEF', '_source': call3}]}},
                                          {'hits': {'hits': [{'_id': 'BCDE', '_source': call2}]}},
                                          {'hits': {'hits': []}}]
    ea.send_pending_alerts()
    assert_alerts(ea, [[hit1, hit2], [hit3]])

    call1 = ea.writeback_es.search.call_args_list[6][1]['body']
    call2 = ea.writeback_es.search.call_args_list[7][1]['body']
    call3 = ea.writeback_es.search.call_args_list[8][1]['body']

    assert 'alert_time' in call1['filter']['range']
    assert call2['query']['query_string']['query'] == 'aggregate_id:ABCD'
    assert call3['query']['query_string']['query'] == 'aggregate_id:CDEF'


def test_agg_no_writeback_connectivity(ea):
    """ Tests that if writeback_es throws an exception, the matches will be added to 'agg_matches' and when
    run again, that they will be passed again to add_aggregated_alert """
    hit1, hit2, hit3 = '2014-09-26T12:34:45', '2014-09-26T12:40:45', '2014-09-26T12:47:45'
    hits = generate_hits([hit1, hit2, hit3])
    ea.current_es.search.return_value = hits
    ea.rules[0]['aggregation'] = datetime.timedelta(minutes=10)
    ea.rules[0]['type'].matches = [{'@timestamp': hit1},
                                   {'@timestamp': hit2},
                                   {'@timestamp': hit3}]
    ea.writeback_es.create.side_effect = elasticsearch.exceptions.ElasticsearchException('Nope')
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)

    assert ea.rules[0]['agg_matches'] == [{'@timestamp': hit1},
                                          {'@timestamp': hit2},
                                          {'@timestamp': hit3}]

    ea.current_es.search.return_value = {'hits': {'hits': []}}
    ea.add_aggregated_alert = mock.Mock()

    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)

    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit1}, ea.rules[0])
    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit2}, ea.rules[0])
    ea.add_aggregated_alert.assert_any_call({'@timestamp': hit3}, ea.rules[0])


def test_silence(ea):
    # Silence test rule for 4 hours
    ea.args.rule = 'test_rule.yaml'  # Not a real name, just has to be set
    ea.args.silence = 'hours=4'
    ea.silence()

    # Don't alert even with a match
    match = [{'@timestamp': '2014-11-17T00:00:00'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 0

    # Mock ts_now() to +5 hours, alert on match
    match = [{'@timestamp': '2014-11-17T00:00:00'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.Elasticsearch'):
            mock_ts.return_value = dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5))
            ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def test_silence_query_key(ea):
    # Silence test rule for 4 hours
    ea.args.rule = 'test_rule.yaml'  # Not a real name, just has to be set
    ea.args.silence = 'hours=4'
    ea.silence()

    # Don't alert even with a match
    match = [{'@timestamp': '2014-11-17T00:00:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    ea.rules[0]['query_key'] = 'username'
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 0

    # Mock ts_now() to +5 hours, alert on match
    match = [{'@timestamp': '2014-11-17T00:00:00', 'username': 'qlo'}]
    ea.rules[0]['type'].matches = match
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.Elasticsearch'):
            mock_ts.return_value = dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(hours=5))
            ea.run_rule(ea.rules[0], END, START)
    assert ea.rules[0]['alert'][0].alert.call_count == 1


def test_realert(ea):
    hits = ['2014-09-26T12:35:%sZ' % (x) for x in range(60)]
    matches = [{'@timestamp': x} for x in hits]
    ea.current_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.rules[0]['realert'] = datetime.timedelta(seconds=50)
        ea.rules[0]['type'].matches = matches
        ea.run_rule(ea.rules[0], END, START)
        assert ea.rules[0]['alert'][0].alert.call_count == 1

    # Doesn't alert again
    matches = [{'@timestamp': x} for x in hits]
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)
        ea.rules[0]['type'].matches = matches
        assert ea.rules[0]['alert'][0].alert.call_count == 1

    # mock ts_now() to past the realert time
    matches = [{'@timestamp': hits[0]}]
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        with mock.patch('elastalert.elastalert.Elasticsearch'):
            mock_ts.return_value = dt_to_ts(datetime.datetime.utcnow() + datetime.timedelta(minutes=10))
            ea.rules[0]['type'].matches = matches
            ea.run_rule(ea.rules[0], END, START)
            assert ea.rules[0]['alert'][0].alert.call_count == 2


def test_count(ea):
    ea.rules[0]['use_count_query'] = True
    ea.rules[0]['doc_type'] = 'doctype'
    with mock.patch('elastalert.elastalert.Elasticsearch'):
        ea.run_rule(ea.rules[0], END, START)

    # Assert that es.count is run against every run_every timeframe between START and END
    end = END
    start = START
    query = {'query': {'filtered': {'filter': {'bool': {'must': [{'range': {'@timestamp': {'to': end, 'from': START}}}]}}}}}
    while ts_delta(start, END) > ea.buffer_time:
        end = ts_add(start, ea.run_every)
        query['query']['filtered']['filter']['bool']['must'][0]['range']['@timestamp']['to'] = end
        query['query']['filtered']['filter']['bool']['must'][0]['range']['@timestamp']['from'] = start
        start = ts_add(start, ea.run_every)
        ea.current_es.count.assert_any_call(body=query, doc_type='doctype', index='idx')


def test_queries_with_rule_buffertime(ea):
    ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=53)
    hits = generate_hits([START])
    mock_es = mock.Mock()
    mock_es.search.return_value = hits
    with mock.patch('elastalert.elastalert.Elasticsearch') as mock_es_init:
        mock_es_init.return_value = mock_es
        ea.run_rule(ea.rules[0], END, START)

    # Assert that es.search is run against every run_every timeframe between START and END
    end = END
    start = START
    query = {'filter': {'bool': {'must': [{'range': {'@timestamp': {'to': end, 'from': START}}}]}},
             'sort': [{'@timestamp': {'order': 'asc'}}]}
    while ts_delta(start, END) > ea.rules[0]['buffer_time']:
        end = ts_add(start, ea.run_every)
        query['filter']['bool']['must'][0]['range']['@timestamp']['to'] = end
        query['filter']['bool']['must'][0]['range']['@timestamp']['from'] = start
        start = ts_add(start, ea.run_every)
        ea.current_es.search.assert_any_call(body=query, size=ea.max_query_size, index='idx', _source_include=['@timestamp'])

    # Assert that num_hits correctly summed every result
    assert ea.num_hits == ea.current_es.search.call_count


def test_get_starttime(ea):
    endtime = '2015-01-01T00:00:00Z'
    mock_es = mock.Mock()
    mock_es.search.return_value = {'hits': {'hits': [{'_source': {'endtime': endtime}}]}}
    ea.writeback_es = mock_es

    # 4 days old, will return endtime
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        mock_ts.return_value = '2015-01-05T00:00:00Z'  # 4 days ahead of the endtime
        assert ea.get_starttime(ea.rules[0]) == endtime

    # 10 days old, will return None
    with mock.patch('elastalert.elastalert.ts_now') as mock_ts:
        mock_ts.return_value = '2015-01-11T00:00:00Z'  # 10 days ahead of the endtime
        assert ea.get_starttime(ea.rules[0]) is None


def test_set_starttime(ea):
    # standard query, no starttime, no last run
    end = '2014-10-10T10:10:10'
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == ts_add(end, -ea.buffer_time)

    # Standard query, no starttime, rule specific buffer_time
    ea.rules[0].pop('starttime')
    ea.rules[0]['buffer_time'] = datetime.timedelta(minutes=37)
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == ts_add(end, -datetime.timedelta(minutes=37))
    ea.rules[0].pop('buffer_time')

    # Standard query, no starttime, last run
    ea.rules[0].pop('starttime')
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = '2014-10-10T00:00:00'
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 1
    assert ea.rules[0]['starttime'] == '2014-10-10T00:00:00'

    # Standard query, starttime
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 0
    assert ea.rules[0]['starttime'] == ts_add(end, -ea.buffer_time)

    # Count query, starttime
    ea.rules[0]['use_count_query'] = True
    with mock.patch.object(ea, 'get_starttime') as mock_gs:
        mock_gs.return_value = None
        ea.set_starttime(ea.rules[0], end)
        assert mock_gs.call_count == 0
    assert ea.rules[0]['starttime'] == ts_add(end, -ea.run_every)


def test_kibana_dashboard(ea):
    match = {'@timestamp': '2014-10-11T00:00:00'}
    mock_es = mock.Mock()
    ea.rules[0]['use_kibana_dashboard'] = 'my dashboard'
    with mock.patch('elastalert.elastalert.Elasticsearch') as mock_es_init:
        mock_es_init.return_value = mock_es

        # No dashboard found
        mock_es.search.return_value = {'hits': {'hits': []}}
        with pytest.raises(EAException):
            ea.use_kibana_link(ea.rules[0], match)
        mock_call = mock_es.search.call_args_list[0][1]
        assert mock_call['body'] == {'query': {'term': {'_id': 'my dashboard'}}}

        # Dashboard found
        mock_es.create.return_value = {'_id': 'ABCDEFG'}
        mock_es.search.return_value = {'hits': {'hits': [{'_source': {'dashboard': json.dumps(dashboard_temp)}}]}}
        url = ea.use_kibana_link(ea.rules[0], match)
        assert 'ABCDEFG' in url
        db = json.loads(mock_es.create.call_args_list[0][1]['body']['dashboard'])
        assert 'anytest' in db['title']


def test_rule_changes(ea):
    ea.rule_hashes = {'rule1.yaml': 'ABC',
                      'rule2.yaml': 'DEF'}
    ea.rules = [ea.init_rule(rule, True) for rule in [{'rule_file': 'rule1.yaml', 'name': 'rule1', 'filter': []},
                                                      {'rule_file': 'rule2.yaml', 'name': 'rule2', 'filter': []}]]
    ea.rules[1]['processed_hits'] = ['save me']
    new_hashes = {'rule1.yaml': 'ABC',
                  'rule3.yaml': 'XXX',
                  'rule2.yaml': '!@#$'}

    with mock.patch('elastalert.elastalert.get_rule_hashes') as mock_hashes:
        with mock.patch('elastalert.elastalert.load_configuration') as mock_load:
            mock_load.side_effect = [{'filter': [], 'name': 'rule2'}, {'filter': [], 'name': 'rule3'}]
            mock_hashes.return_value = new_hashes
            ea.load_rule_changes()

    # All 3 rules still exist
    assert ea.rules[0]['name'] == 'rule1'
    assert ea.rules[1]['name'] == 'rule2'
    assert ea.rules[1]['processed_hits'] == ['save me']
    assert ea.rules[2]['name'] == 'rule3'

    # Assert 2 and 3 were reloaded
    assert mock_load.call_count == 2
    assert mock_load.called_with('rules/rule2.yaml')
    assert mock_load.called_with('rules/rule3.yaml')


def test_strf_index(ea):
    """ Test that the get_index function properly generates indexes spanning days """
    ea.rules[0]['index'] = 'logstash-%Y.%m.%d'
    ea.rules[0]['use_strftime_index'] = True

    # Test formatting with times
    start = '2015-01-02T12:34:45Z'
    end = '2015-01-02T16:15:14Z'
    assert ea.get_index(ea.rules[0], start, end) == 'logstash-2015.01.02'
    end = '2015-01-03T01:02:03Z'
    assert ea.get_index(ea.rules[0], start, end) == 'logstash-2015.01.02,logstash-2015.01.03'

    # Test formatting for wildcard
    assert ea.get_index(ea.rules[0]) == 'logstash-*'
    ea.rules[0]['index'] = 'logstash-%Y.%m'
    assert ea.get_index(ea.rules[0]) == 'logstash-*'
    ea.rules[0]['index'] = 'logstash-%Y.%m-stuff'
    assert ea.get_index(ea.rules[0]) == 'logstash-*-stuff'
