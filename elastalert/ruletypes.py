# -*- coding: utf-8 -*-
import datetime
from collections import deque

from elasticsearch.client import Elasticsearch
from util import dt_to_ts
from util import EAException
from util import format_index
from util import hashable
from util import lookup_es_key
from util import pretty_ts
from util import ts_now
from util import ts_to_dt


class RuleType(object):
    """ The base class for a rule type.
    The class must implement add_data and add any matches to self.matches.

    :param rules: A rule configuration.
    """
    required_options = frozenset()

    def __init__(self, rules):
        self.matches = []
        self.rules = rules
        self.occurrences = {}

    def add_data(self, data):
        """ The function that the elastalert client calls with results from ES.
        Data is a list of dictionaries, from elasticsearch.

        :param data: A list of events, each of which is a dictionary of terms.
        """
        raise NotImplementedError()

    def add_match(self, event):
        """ This function is called on all matching events. Rules use it to add
        extra information about the context of a match. Event is a dictionary
        containing terms directly from elasticsearch and alerts will report
        all of the information.

        :param event: The matching event, a dictionary of terms.
        """
        # Convert datetime's back to timestamps
        ts = self.rules.get('timestamp_field')
        if ts in event:
            event[ts] = dt_to_ts(event[ts])
        self.matches.append(event)

    def get_match_str(self, match):
        """ Returns a string that gives more context about a match.

        :param match: The matching event, a dictionary of terms.
        :return: A user facing string describing the match.
        """
        return ''

    def garbage_collect(self, timestamp):
        """ Gets called periodically to remove old data that is useless beyond given timestamp.
        May also be used to compute things in the absence of new data.

        :param timestamp: A timestamp indicating the rule has been run up to that point.
        """
        pass

    def add_count_data(self, counts):
        """ Gets called when a rule has use_count_query set to True. Called to add data from querying to the rule.

        :param counts: A dictionary mapping timestamps to hit counts.
        """
        raise NotImplementedError()

    def add_terms_data(self, terms):
        """ Gets called when a rule has use_terms_query set to True.

        :param terms: A list of buckets with a key, corresponding to query_key, and the count """
        raise NotImplementedError()


class CompareRule(RuleType):
    """ A base class for matching a specific term by passing it to a compare function """
    required_options = frozenset(['compare_key'])

    def compare(self, event):
        """ An event is a match iff this returns true """
        raise NotImplementedError()

    def add_data(self, data):
        # If compare returns true, add it as a match
        for event in data:
            if self.compare(event):
                self.add_match(event)


class BlacklistRule(CompareRule):
    """ A CompareRule where the compare function checks a given key against a blacklist """
    required_options = frozenset(['compare_key', 'blacklist'])

    def compare(self, event):
        term = lookup_es_key(event, self.rules['compare_key'])
        if term in self.rules['blacklist']:
            return True
        return False


class WhitelistRule(CompareRule):
    """ A CompareRule where the compare function checks a given term against a whitelist """
    required_options = frozenset(['compare_key', 'whitelist', 'ignore_null'])

    def compare(self, event):
        term = lookup_es_key(event, self.rules['compare_key'])
        if term is None:
            return not self.rules['ignore_null']
        if term not in self.rules['whitelist']:
            return True
        return False


class ChangeRule(CompareRule):
    """ A rule that will store values for a certain term and match if those values change """
    required_options = frozenset(['query_key', 'compare_key', 'ignore_null'])
    change_map = {}
    occurrence_time = {}

    def compare(self, event):
        key = hashable(lookup_es_key(event, self.rules['query_key']))
        val = lookup_es_key(event, self.rules['compare_key'])
        if not val and self.rules['ignore_null']:
            return False
        changed = False

        # If we have seen this key before, compare it to the new value
        if key in self.occurrences:
            changed = self.occurrences[key] != val
            if changed:
                self.change_map[key] = (self.occurrences[key], val)

                # If using timeframe, only return true if the time delta is < timeframe
                if key in self.occurrence_time:
                    changed = event[self.rules['timestamp_field']] - self.occurrence_time[key] <= self.rules['timeframe']

        # Update the current value and time
        self.occurrences[key] = val
        if 'timeframe' in self.rules:
            self.occurrence_time[key] = event[self.rules['timestamp_field']]

        return changed

    def add_match(self, match):
        # TODO this is not technically correct
        # if the term changes multiple times before an alert is sent
        # this data will be overwritten with the most recent change
        change = self.change_map.get(hashable(lookup_es_key(match, self.rules['query_key'])))
        extra = {}
        if change:
            extra = {'old_value': change[0],
                     'new_value': change[1]}
        super(ChangeRule, self).add_match(dict(match.items() + extra.items()))


class FrequencyRule(RuleType):
    """ A rule that matches if num_events number of events occur within a timeframe """
    required_options = frozenset(['num_events', 'timeframe'])

    def __init__(self, *args):
        super(FrequencyRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = lambda event: event[0]['fields'][self.ts_field]

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')
        for ts, count in data.iteritems():
            event = ({'fields': {self.ts_field: ts}, self.ts_field: ts}, count)
            self.occurrences.setdefault('all', EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
            self.check_for_match('all')

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                count = bucket['doc_count']
                event = ({'fields': {self.ts_field: timestamp},
                         self.ts_field: timestamp,
                         self.rules['query_key']: bucket['key']}, count)
                self.occurrences.setdefault(bucket['key'], EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
                self.check_for_match(bucket['key'])

    def add_data(self, data):
        if 'query_key' in self.rules:
            qk = self.rules['query_key']
        else:
            qk = None

        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'

            # Store the timestamps of recent occurrences, per key
            self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))
            self.check_for_match(key)

    def check_for_match(self, key):
        # Match if, after removing old events, we hit num_events
        if self.occurrences[key].count() >= self.rules['num_events']:
            event = self.occurrences[key].data[-1][0]
            self.add_match(event)
            self.occurrences.pop(key)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.iteritems():
            if timestamp - window.data[-1][0][self.ts_field] > self.rules['timeframe']:
                stale_keys.append(key)
        map(self.occurrences.pop, stale_keys)

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        if self.rules.get('timestamp_type') == 'long':
            starttime = dt_to_ts(match['fields'][self.ts_field] - self.rules['timeframe'])
            endtime = dt_to_ts(match['fields'][self.ts_field])
        else:
            starttime = pretty_ts(dt_to_ts(ts_to_dt(match[self.ts_field]) - self.rules['timeframe']), lt)
            endtime = pretty_ts(match[self.ts_field], lt)
        message = 'At least %d events occurred between %s and %s\n\n' % (self.rules['num_events'],
                                                                         starttime,
                                                                         endtime)
        return message


class AnyRule(RuleType):
    """ A rule that will match on any input data """

    def add_data(self, data):
        for datum in data:
            self.add_match(datum)


class EventWindow(object):
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(self, timeframe, onRemoved=None, getTimestamp=lambda e: e[0]['fields'][self.rules['timestamp_field']]):
        self.timeframe = timeframe
        self.onRemoved = onRemoved
        self.get_ts = getTimestamp
        self.data = deque()
        self.running_count = 0

    def append(self, event):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        # If the event occurred before our 'latest' event
        if len(self.data) and self.get_ts(self.data[-1]) > self.get_ts(event):
            self.append_middle(event)
        else:
            self.data.append(event)
            self.running_count += event[1]
        while self.duration() >= self.timeframe:
            oldest = self.data.popleft()
            self.running_count -= oldest[1]
            self.onRemoved and self.onRemoved(oldest)

    def duration(self):
        """ Get the size in timedelta of the window. """
        if not self.data:
            return datetime.timedelta(0)
        return self.get_ts(self.data[-1]) - self.get_ts(self.data[0])

    def count(self):
        """ Count the number of events in the window. """
        return self.running_count

    def __iter__(self):
        return iter(self.data)

    def append_middle(self, event):
        """ Attempt to place the event in the correct location in our deque.
        Returns True if successful, otherwise False. """
        rotation = 0
        ts = self.get_ts(event)

        # Append left if ts is earlier than first event
        if self.get_ts(self.data[0]) > ts:
            self.data.appendleft(event)
            self.running_count += event[1]
            return

        # Rotate window until we can insert event
        while self.get_ts(self.data[-1]) > ts:
            self.data.rotate(1)
            rotation += 1
            if rotation == len(self.data):
                # This should never happen
                return
        self.data.append(event)
        self.running_count += event[1]
        self.data.rotate(-rotation)


class SpikeRule(RuleType):
    """ A rule that uses two sliding windows to compare relative event frequency. """
    required_options = frozenset(['timeframe', 'spike_height', 'spike_type'])

    def __init__(self, *args):
        super(SpikeRule, self).__init__(*args)
        self.timeframe = self.rules['timeframe']

        self.ref_windows = {}
        self.cur_windows = {}

        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = lambda e: e[0]['fields'][self.ts_field]
        self.first_event = {}
        self.skip_checks = {}

        self.ref_window_filled_once = False

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')
        for ts, count in data.iteritems():
            self.handle_event({'fields': {self.ts_field: ts}, self.ts_field: ts}, count, 'all')

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                count = bucket['doc_count']
                event = {'fields': {self.ts_field: timestamp},
                         self.ts_field: timestamp,
                         self.rules['query_key']: bucket['key']}
                key = bucket['key']
                self.handle_event(event, count, key)

    def add_data(self, data):
        for event in data:
            qk = self.rules.get('query_key', 'all')
            if qk != 'all':
                qk = event.get(qk, 'other')
                if qk is None:
                    qk = 'other'
            self.handle_event(event, 1, qk)

    def clear_windows(self, qk, event):
        # Reset the state and prevent alerts until windows filled again
        self.cur_windows[qk].data = deque()
        self.ref_windows[qk].data = deque()
        self.first_event.pop(qk)
        self.skip_checks[qk] = event['fields'][self.ts_field] + self.rules['timeframe'] * 2

    def handle_event(self, event, count, qk='all'):
        self.first_event.setdefault(qk, event)

        self.ref_windows.setdefault(qk, EventWindow(self.timeframe, getTimestamp=self.get_ts))
        self.cur_windows.setdefault(qk, EventWindow(self.timeframe, self.ref_windows[qk].append, self.get_ts))

        self.cur_windows[qk].append((event, count))

        # Don't alert if ref window has not yet been filled for this key AND
        if event['fields'][self.ts_field] - self.first_event[qk]['fields'][self.ts_field] < self.rules['timeframe'] * 2:
            # ElastAlert has not been running long enough for any alerts OR
            if not self.ref_window_filled_once:
                return
            # This rule is not using alert_on_new_data (with query_key) OR
            if not (self.rules.get('query_key') and self.rules.get('alert_on_new_data')):
                return
            # An alert for this qk has recently fired
            if qk in self.skip_checks and event[self.ts_field] < self.skip_checks[qk]:
                return
        else:
            self.ref_window_filled_once = True

        if self.find_matches(self.ref_windows[qk].count(), self.cur_windows[qk].count()):
            match = self.cur_windows[qk].data[-1][0]
            self.add_match(match, qk)
            self.clear_windows(qk, match)

    def add_match(self, match, qk):
        extra_info = {}
        spike_count = self.cur_windows[qk].count()
        reference_count = self.ref_windows[qk].count()
        extra_info = {'spike_count': spike_count,
                      'reference_count': reference_count}

        match = dict(match.items() + extra_info.items())

        super(SpikeRule, self).add_match(match)

    def find_matches(self, ref, cur):
        """ Determines if an event spike or dip happening. """

        # Apply threshold limits
        if (cur < self.rules.get('threshold_cur', 0) or
                ref < self.rules.get('threshold_ref', 0)):
            return False

        spike_up, spike_down = False, False
        if cur <= ref / self.rules['spike_height']:
            spike_down = True
        if cur >= ref * self.rules['spike_height']:
            spike_up = True

        if (self.rules['spike_type'] in ['both', 'up'] and spike_up) or \
           (self.rules['spike_type'] in ['both', 'down'] and spike_down):
            return True
        return False

    def get_match_str(self, match):
        timestamp = dt_to_ts(match['fields'][self.rules['timestamp_field']])

        message = 'An abnormal number (%d) of events occurred around %s.\n' % (match['spike_count'],
                                                                               timestamp)
        message += 'Preceding that time, there were only %d events within %s\n\n' % (match['reference_count'], self.rules['timeframe'])
        return message

    def garbage_collect(self, ts):
        # Windows are sized according to their newest event
        # This is a placeholder to accurately size windows in the absence of events
        for qk in self.cur_windows.keys():
            # If we havn't seen this key in a long time, forget it
            if qk != 'all' and self.ref_windows[qk].count() == 0 and self.cur_windows[qk].count() == 0:
                self.cur_windows.pop(qk)
                self.ref_windows.pop(qk)
                continue
            placeholder = {'fields': {self.ts_field: ts}}
            # The placeholder may trigger an alert, in which case, qk will be expected
            if qk != 'all':
                placeholder.update({self.rules['query_key']: qk})
            self.handle_event(placeholder, 0, qk)


class FlatlineRule(FrequencyRule):
    """ A rule that matches when there is a low number of events given a timeframe. """
    required_options = frozenset(['timeframe', 'threshold'])

    def __init__(self, *args):
        super(FlatlineRule, self).__init__(*args)
        self.threshold = self.rules['threshold']

        # Dictionary mapping query keys to the first events
        self.first_event = {}

    def check_for_match(self, key):
        most_recent_ts = self.get_ts(self.occurrences[key].data[-1])
        if self.first_event.get(key) is None:
            self.first_event[key] = most_recent_ts

        # Don't check for matches until timeframe has elapsed
        if most_recent_ts - self.first_event[key] < self.rules['timeframe']:
            return

        # Match if, after removing old events, we hit num_events
        count = self.occurrences[key].count()
        if count < self.rules['threshold']:
            event = self.occurrences[key].data[-1][0]
            event.update(key=key, count=count)
            self.add_match(event)

            # we after adding this match, let's remove this key so we don't realert on it
            self.occurrences.pop(key)
            del self.first_event[key]

    def get_match_str(self, match):
        if self.rules.get('timestamp_type') == 'long':
            starttime = dt_to_ts(match['fields'][self.ts_field] - self.rules['timeframe'])
            endtime = dt_to_ts(match['fields'][self.ts_field])
        else:
            lt = self.rules.get('use_local_time')
            starttime = pretty_ts(dt_to_ts(ts_to_dt(match[self.ts_field]) - self.rules['timeframe']), lt)
            endtime = pretty_ts(match[self.ts_field], lt)
        message = 'An abnormally low number of events occurred around %s.\n' % endtime
        message += 'Between %s and %s, there were less than %s events.\n\n' % starttime, endtime, self.rules['threshold']
        return message

    def garbage_collect(self, ts):
        # We add an event with a count of zero to the EventWindow for each key. This will cause the EventWindow
        # to remove events that occured more than one `timeframe` ago, and call onRemoved on them.
        for key in self.occurrences.keys():
            self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(({'fields': {self.ts_field: ts}, self.ts_field: ts}, 0))
            self.check_for_match(key)


class NewTermsRule(RuleType):
    """ Alerts on a new value in a list of fields. """

    def __init__(self, *args):
        super(NewTermsRule, self).__init__(*args)
        self.seen_values = {}
        # Allow the use of query_key or fields
        if 'fields' not in self.rules:
            if 'query_key' not in self.rules:
                raise EAException("fields or query_key must be specified")
            self.fields = self.rules['query_key']
        else:
            self.fields = self.rules['fields']
        if not self.fields:
            raise EAException("fields must not be an empty list")
        if type(self.fields) != list:
            self.fields = [self.fields]
        if self.rules.get('use_terms_query') and len(self.fields) != 1:
            raise EAException("use_terms_query can only be used with one field at a time")
        self.get_all_terms()

    def get_all_terms(self):
        """ Performs a terms aggregation for each field to get every existing term. """
        self.es = Elasticsearch(host=self.rules['es_host'], port=self.rules['es_port'])
        window_size = datetime.timedelta(**self.rules.get('terms_window_size', {'days': 30}))

        field_name = {"field": "", "size": 2147483647}  # Integer.MAX_VALUE
        query_template = {"aggs": {"values": {"terms": field_name}}}
        if self.rules.get('use_strftime_index'):
            end = ts_now()
            start = end - window_size
            index = format_index(self.rules['index'], start, end)
        else:
            index = self.rules['index']

        for field in self.fields:
            field_name['field'] = field
            res = self.es.search(body=query_template, index=index, ignore_unavailable=True, timeout=50)
            buckets = res['aggregations']['values']['buckets']
            keys = [bucket['key'] for bucket in buckets]
            self.seen_values[field] = keys

    def add_data(self, data):
        for document in data:
            for field in self.fields:
                value = document.get(field)
                if not value and self.rules.get('alert_on_missing_field'):
                    document['missing_field'] = field
                    self.add_match(document)
                elif value:
                    if value not in self.seen_values[field]:
                        document['new_field'] = field
                        self.add_match(document)
                        self.seen_values[field].append(value)

    def add_terms_data(self, terms):
        # With terms query, len(self.fields) is always 1
        field = self.fields[0]
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                if bucket['doc_count']:
                    if bucket['key'] not in self.seen_values[field]:
                        match = {field: bucket['key'],
                                 self.rules['timestamp_field']: timestamp,
                                 'new_field': field}
                        self.add_match(match)
