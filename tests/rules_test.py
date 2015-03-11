# -*- coding: utf-8 -*-
import datetime

from elastalert.ruletypes import AnyRule
from elastalert.ruletypes import BlacklistRule
from elastalert.ruletypes import ChangeRule
from elastalert.ruletypes import EventWindow
from elastalert.ruletypes import FlatlineRule
from elastalert.ruletypes import FrequencyRule
from elastalert.ruletypes import SpikeRule
from elastalert.ruletypes import WhitelistRule
from elastalert.util import dt_to_ts
from elastalert.util import ts_to_dt


def hits(x, timestamp='@timestamp', **kwargs):
    ret = []
    for n in range(x):
        ts = '2014-09-26T12:%s:%sZ' % (n / 60, n % 60)
        n += 1
        event = {timestamp: ts}
        event.update(**kwargs)
        ret.append(event)
    return ret


def assert_matches_have(matches, terms):
    assert len(matches) == len(terms)
    for match, term in zip(matches, terms):
        assert term[0] in match
        assert match[term[0]] == term[1]


def test_any():
    event = hits(1)
    rule = AnyRule({})
    rule.add_data([event])
    assert rule.matches == [event]


def test_freq():
    events = hits(60, 'blah', username='qlo')
    rules = {'num_events': 59,
             'timeframe': datetime.timedelta(hours=1),
             'timestamp_field': 'blah'}
    rule = FrequencyRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 1

    # Test wit query_key
    rules['query_key'] = 'username'
    rule = FrequencyRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 1

    # Doesn't match
    events = hits(60, 'blah', username='qlo')
    rules['num_events'] = 61
    rule = FrequencyRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 0

    # garbage collection
    assert 'qlo' in rule.occurrences
    rule.garbage_collect('2014-09-28T12:0:0')
    assert rule.occurrences == {}


def test_freq_count():
    rules = {'num_events': 100,
             'timeframe': datetime.timedelta(hours=1),
             'use_count_query': True}
    # Normal match
    rule = FrequencyRule(rules)
    rule.add_count_data({'2014-10-10T00:00:00': 75})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T00:15:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T00:25:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T00:45:00': 6})
    assert len(rule.matches) == 1

    # First data goes out of timeframe first
    rule = FrequencyRule(rules)
    rule.add_count_data({'2014-10-10T00:00:00': 75})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T00:45:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T00:55:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T01:05:00': 6})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-10T01:00:00': 75})
    assert len(rule.matches) == 1


def test_freq_out_of_order():
    events = hits(60, 'blah', username='qlo')
    rules = {'num_events': 59,
             'timeframe': datetime.timedelta(hours=1),
             'timestamp_field': 'blah'}
    rule = FrequencyRule(rules)
    rule.add_data(events[:10])
    assert len(rule.matches) == 0

    # Try to add events from before the first occurrence
    rule.add_data([{'blah': '2014-09-26T11:00:00', 'username': 'qlo'}] * 50)
    assert len(rule.matches) == 0

    rule.add_data(events[15:20])
    assert len(rule.matches) == 0
    rule.add_data(events[10:15])
    assert len(rule.matches) == 0
    rule.add_data(events[20:55])
    rule.add_data(events[57:])
    assert len(rule.matches) == 0
    rule.add_data(events[55:57])
    assert len(rule.matches) == 1


def test_freq_terms():
    rules = {'num_events': 10,
             'timeframe': datetime.timedelta(hours=1),
             'query_key': 'username'}
    rule = FrequencyRule(rules)

    terms1 = {'2014-01-01T00:01:00Z': [{'key': 'userA', 'doc_count': 1},
                                       {'key': 'userB', 'doc_count': 5}]}
    terms2 = {'2014-01-01T00:10:00Z': [{'key': 'userA', 'doc_count': 8},
                                       {'key': 'userB', 'doc_count': 5}]}
    terms3 = {'2014-01-01T00:25:00Z': [{'key': 'userA', 'doc_count': 3},
                                       {'key': 'userB', 'doc_count': 0}]}
    # Initial data
    rule.add_terms_data(terms1)
    assert len(rule.matches) == 0

    # Match for user B
    rule.add_terms_data(terms2)
    assert len(rule.matches) == 1
    assert rule.matches[0].get('username') == 'userB'

    # Match for user A
    rule.add_terms_data(terms3)
    assert len(rule.matches) == 2
    assert rule.matches[1].get('username') == 'userA'


def test_eventwindow():
    timeframe = datetime.timedelta(minutes=10)
    window = EventWindow(timeframe, getTimestamp=lambda e: e['@timestamp'])
    timestamps = ['2014-01-01T10:00:00',
                  '2014-01-01T10:05:00',
                  '2014-01-01T10:03:00',
                  '2014-01-01T09:55:00',
                  '2014-01-01T10:09:00']
    for ts in timestamps:
        window.append({'@timestamp': ts})

    timestamps.sort()
    for exp, actual in zip(timestamps[1:], window.data):
        assert actual['@timestamp'] == exp

    window.append({'@timestamp': '2014-01-01T10:14:00'})
    timestamps.append('2014-01-01T10:14:00')
    for exp, actual in zip(timestamps[3:], window.data):
        assert actual['@timestamp'] == exp


def test_spike_count():
    rules = {'threshold_ref': 10,
             'spike_height': 2,
             'timeframe': datetime.timedelta(seconds=10),
             'spike_type': 'both',
             'timestamp_field': '@timestamp'}
    rule = SpikeRule(rules)

    # Double rate of events at 20 seconds
    rule.add_count_data({'2014-09-26T00:00:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-09-26T00:00:10': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-09-26T00:00:20': 20})
    assert len(rule.matches) == 1

    # Downward spike
    rule = SpikeRule(rules)
    rule.add_count_data({'2014-09-26T00:00:00': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-09-26T00:00:10': 10})
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-09-26T00:00:20': 0})
    assert len(rule.matches) == 1


def test_spike():
    # Events are 1 per second
    events = hits(100, 'ts')

    # Constant rate, doesn't match
    rules = {'threshold_ref': 10,
             'spike_height': 2,
             'timeframe': datetime.timedelta(seconds=10),
             'spike_type': 'both',
             'use_count_query': False,
             'timestamp_field': 'ts'}
    rule = SpikeRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 0

    # Double the rate of events after [50:]
    events2 = events[:50]
    for event in events[50:]:
        events2.append(event)
        events2.append({'ts': dt_to_ts(ts_to_dt(event['ts']) + datetime.timedelta(milliseconds=1))})
    rules['spike_type'] = 'up'
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 1

    # Doesn't match
    rules['spike_height'] = 3
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 0

    # Downward spike
    events = events[:50] + events[75:]
    rules['spike_type'] = 'down'
    rule = SpikeRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 1

    # Doesn't meet threshold_ref
    # When ref hits 11, cur is only 20
    rules['spike_height'] = 2
    rules['threshold_ref'] = 11
    rules['spike_type'] = 'up'
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 0

    # Doesn't meet threshold_cur
    # Maximum rate of events is 20 per 10 seconds
    rules['threshold_ref'] = 10
    rules['threshold_cur'] = 30
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 0

    # Alert on new data
    # (At least 25 events occur before 30 seconds has elapsed)
    rules.pop('threshold_ref')
    rules['timeframe'] = datetime.timedelta(seconds=30)
    rules['threshold_cur'] = 25
    rules['spike_height'] = 2
    rules['alert_on_new_data'] = True
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 1


def test_spike_query_key():
    events = hits(100, 'ts', username='qlo')
    # Constant rate, doesn't match
    rules = {'threshold_ref': 10,
             'spike_height': 2,
             'timeframe': datetime.timedelta(seconds=10),
             'spike_type': 'both',
             'use_count_query': False,
             'timestamp_field': 'ts',
             'query_key': 'username'}
    rule = SpikeRule(rules)
    rule.add_data(events)
    assert len(rule.matches) == 0

    # Double the rate of events, but with a different usename
    events_bob = hits(100, 'ts', username='bob')
    events2 = events[:50]
    for num in range(50, 99):
        events2.append(events_bob[num])
        events2.append(events[num])
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 0

    # Double the rate of events, with the same username
    events2 = events[:50]
    for num in range(50, 99):
        events2.append(events_bob[num])
        events2.append(events[num])
        events2.append(events[num])
    rule = SpikeRule(rules)
    rule.add_data(events2)
    assert len(rule.matches) == 1


def test_spike_terms():
    rules = {'threshold_ref': 5,
             'spike_height': 2,
             'timeframe': datetime.timedelta(minutes=10),
             'spike_type': 'both',
             'use_count_query': False,
             'timestamp_field': 'ts',
             'query_key': 'username',
             'use_term_query': True}
    terms1 = {'2014-01-01T00:01:00Z': [{'key': 'userA', 'doc_count': 10},
                                       {'key': 'userB', 'doc_count': 5}]}
    terms2 = {'2014-01-01T00:10:00Z': [{'key': 'userA', 'doc_count': 22},
                                       {'key': 'userB', 'doc_count': 5}]}
    terms3 = {'2014-01-01T00:25:00Z': [{'key': 'userA', 'doc_count': 25},
                                       {'key': 'userB', 'doc_count': 27}]}
    terms4 = {'2014-01-01T00:27:00Z': [{'key': 'userA', 'doc_count': 10},
                                       {'key': 'userB', 'doc_count': 12},
                                       {'key': 'userC', 'doc_count': 100}]}
    rule = SpikeRule(rules)

    # Initial input
    rule.add_terms_data(terms1)
    assert len(rule.matches) == 0

    # No spike for UserA because windows not filled
    rule.add_terms_data(terms2)
    assert len(rule.matches) == 0

    # Spike for userB only
    rule.add_terms_data(terms3)
    assert len(rule.matches) == 1
    assert rule.matches[0].get('username') == 'userB'

    # Test no alert for new user over threshold
    rules.pop('threshold_ref')
    rules['threshold_cur'] = 50
    rule = SpikeRule(rules)
    rule.add_terms_data(terms1)
    rule.add_terms_data(terms2)
    rule.add_terms_data(terms3)
    rule.add_terms_data(terms4)
    assert len(rule.matches) == 0

    # Test alert_on_new_data
    rules['alert_on_new_data'] = True
    rule = SpikeRule(rules)
    rule.add_terms_data(terms1)
    rule.add_terms_data(terms2)
    rule.add_terms_data(terms3)
    rule.add_terms_data(terms4)
    assert len(rule.matches) == 1


def test_blacklist():
    events = [{'@timestamp': '2014-09-26T12:34:56Z', 'term': 'good'},
              {'@timestamp': '2014-09-26T12:34:57Z', 'term': 'bad'},
              {'@timestamp': '2014-09-26T12:34:58Z', 'term': 'also good'},
              {'@timestamp': '2014-09-26T12:34:59Z', 'term': 'really bad'},
              {'@timestamp': '2014-09-26T12:35:00Z', 'no_term': 'bad'}]
    rules = {'blacklist': ['bad', 'really bad'],
             'compare_key': 'term',
             'timestamp_field': '@timestamp'}
    rule = BlacklistRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('term', 'bad'), ('term', 'really bad')])


def test_whitelist():
    events = [{'@timestamp': '2014-09-26T12:34:56Z', 'term': 'good'},
              {'@timestamp': '2014-09-26T12:34:57Z', 'term': 'bad'},
              {'@timestamp': '2014-09-26T12:34:58Z', 'term': 'also good'},
              {'@timestamp': '2014-09-26T12:34:59Z', 'term': 'really bad'},
              {'@timestamp': '2014-09-26T12:35:00Z', 'no_term': 'bad'}]
    rules = {'whitelist': ['good', 'also good'],
             'compare_key': 'term',
             'ignore_null': True,
             'timestamp_field': '@timestamp'}
    rule = WhitelistRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('term', 'bad'), ('term', 'really bad')])

    # Don't ignore nulls
    rules['ignore_null'] = False
    rule = WhitelistRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('term', 'bad'), ('term', 'really bad'), ('no_term', 'bad')])


def test_change():
    events = hits(10, username='qlo', term='good')
    events[8].pop('term')
    events[9]['term'] = 'bad'
    rules = {'compare_key': 'term',
             'query_key': 'username',
             'ignore_null': True,
             'timestamp_field': '@timestamp'}
    rule = ChangeRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('term', 'bad')])

    # Don't ignore nulls
    rules['ignore_null'] = False
    rule = ChangeRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('username', 'qlo'), ('term', 'bad')])

    # With timeframe
    rules['timeframe'] = datetime.timedelta(seconds=2)
    rules['ignore_null'] = True
    rule = ChangeRule(rules)
    rule.add_data(events)
    assert_matches_have(rule.matches, [('term', 'bad')])

    # With timeframe, doesn't match
    events = events[:8] + events[9:]
    rules['timeframe'] = datetime.timedelta(seconds=1)
    rule = ChangeRule(rules)
    rule.add_data(events)
    assert rule.matches == []


def test_flatline():
    events = hits(10)
    rules = {'timeframe': datetime.timedelta(seconds=30),
             'threshold': 2,
             'timestamp_field': '@timestamp'}

    rule = FlatlineRule(rules)

    # 1 hit should cause an alert until after at least 30 seconds pass
    rule.add_data(hits(1))
    assert rule.matches == []

    rule.add_data(events)

    # This will be run at the end of the hits
    rule.garbage_collect('2014-09-26T12:00:11Z')
    assert rule.matches == []

    # This would be run if the query returned nothing for a future timestamp
    rule.garbage_collect('2014-09-26T12:00:45Z')
    assert len(rule.matches) == 1


def test_flatline_count():
    rules = {'timeframe': datetime.timedelta(seconds=30),
             'threshold': 1,
             'timestamp_field': '@timestamp'}
    rule = FlatlineRule(rules)
    rule.add_count_data({'2014-10-11T00:00:00': 1})
    rule.garbage_collect('2014-10-11T00:00:10')
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-11T00:00:15': 0})
    rule.garbage_collect('2014-10-11T00:00:20')
    assert len(rule.matches) == 0
    rule.add_count_data({'2014-10-11T00:00:35': 0})
    assert len(rule.matches) == 1
