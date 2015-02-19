# -*- coding: utf-8 -*-
import datetime
from collections import deque

from util import dt_to_ts
from util import EAException
from util import lookup_es_key
from util import hashable
from util import pretty_ts
from util import ts_delta
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
                    changed = ts_delta(self.occurrence_time[key], event[self.rules['timestamp_field']]) <= self.rules['timeframe']

        # Update the current value and time
        self.occurrences[key] = val
        if 'timeframe' in self.rules:
            self.occurrence_time[key] = event[self.rules['timestamp_field']]

        return changed

    def add_match(self, match):
        # TODO this is not technically correct
        # if the term changes multiple times before an alert is sent
        # this data will be overwritten with the most recent change
        change = self.change_map.get(match[self.rules['query_key']])
        extra = {}
        if change:
            extra = {'old_value': change[0],
                     'new_value': change[1]}
        self.matches.append(dict(match.items() + extra.items()))


class FrequencyRule(RuleType):
    """ A rule that matches if num_events number of events occur within a timeframe """
    required_options = frozenset(['num_events', 'timeframe'])

    def __init__(self, *args):
        super(FrequencyRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = lambda event: event[0][self.ts_field]
        if self.rules.get('use_count_query') and any((self.rules.get('query_key'),
                                                      self.rules.get('top_count_keys'))):
            raise EAException("use_count_query cannot be used with query_key or top_count_keys")

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')
        for ts, count in data.iteritems():
            event = ({self.ts_field: ts}, count)
            self.occurrences.setdefault('all', EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
            self.check_for_match()

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                count = bucket['doc_count']
                event = ({self.ts_field: timestamp,
                          self.rules['query_key']: bucket['key']}, count)
                self.occurrences.setdefault(bucket['key'], EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
                self.check_for_match()

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
            self.check_for_match()

    def check_for_match(self):
        for key in self.occurrences.keys():
            # Match if, after removing old events, we hit num_events
            if self.occurrences[key].count() >= self.rules['num_events']:
                event = self.occurrences[key].data[-1][0]
                self.add_match(event)
                self.occurrences.pop(key)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.iteritems():
            if ts_delta(window.data[-1][0][self.ts_field], timestamp) > self.rules['timeframe']:
                stale_keys.append(key)
        map(self.occurrences.pop, stale_keys)

    def add_match(self, event):
        """ Adds time of first event in timeframe and the number of events """
        # If no query_key, we use the key 'all' for everything
        if 'query_key' in self.rules:
            key = hashable(lookup_es_key(event, self.rules['query_key']))
        else:
            key = 'all'

        extra = {}
        top_count_keys = self.rules.get('top_count_keys')
        if top_count_keys:
            number = self.rules.get('top_count_number', 5)
            extra = get_top_counts(map(lambda e: e[0], self.occurrences[key].data), top_count_keys, number)
        self.matches.append(dict(event.items() + extra.items()))

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        starttime = pretty_ts(dt_to_ts(ts_to_dt(match[self.ts_field]) - self.rules['timeframe']), lt)
        endtime = pretty_ts(match[self.ts_field], lt)
        message = 'At least %d events occurred between %s and %s\n\n' % (self.rules['num_events'],
                                                                         starttime,
                                                                         endtime)
        return message


class AnyRule(RuleType):
    """ A rule that will match on any input data """

    def add_data(self, data):
        self.matches += data


class EventWindow(object):
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(self, timeframe, onRemoved=None, getTimestamp=lambda e: e[0]['@timestamp']):
        self.timeframe = timeframe
        self.onRemoved = onRemoved
        self.get_ts = getTimestamp
        self.data = deque()

    def append(self, event):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        # If the event occurred before our 'latest' event
        if len(self.data) and ts_delta(self.get_ts(event), self.get_ts(self.data[-1])) > datetime.timedelta(0):
            self.append_middle(event)
        else:
            self.data.append(event)

        while self.duration() >= self.timeframe:
            oldest = self.data.popleft()
            self.onRemoved and self.onRemoved(oldest)

    def duration(self):
        """ Get the size in timedelta of the window. """
        if not self.data:
            return datetime.timedelta(0)
        return ts_delta(self.get_ts(self.data[0]), self.get_ts(self.data[-1]))

    def count(self):
        """ Count the number of events in the window. """
        return sum(map(lambda e: e[1], self.data))

    def __iter__(self):
        return iter(self.data)

    def append_middle(self, event):
        """ Attempt to place the event in the correct location in our deque.
        Returns True if successful, otherwise False. """
        rotation = 0
        ts = self.get_ts(event)

        # Append left if ts is earlier than first event
        if ts_delta(ts, self.get_ts(self.data[0])) > datetime.timedelta(0):
            self.data.appendleft(event)
            return

        # Rotate window until we can insert event
        while ts_delta(ts, self.get_ts(self.data[-1])) > datetime.timedelta(0):
            self.data.rotate(1)
            rotation += 1
            if rotation == len(self.data):
                # This should never happen
                return
        self.data.append(event)
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
        self.get_ts = lambda e: e[0][self.ts_field]
        self.first_event = {}

        self.ref_window_filled_once = False

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')
        for ts, count in data.iteritems():
            self.handle_event({self.ts_field: ts}, count, 'all')

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                count = bucket['doc_count']
                event = {self.ts_field: timestamp,
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
        self.cur_windows[qk].data = deque()
        self.ref_windows[qk].data = deque()

        # Mark this alert time as the new starting time, to prevent alerting again immediately
        self.first_event[qk] = event

    def handle_event(self, event, count, qk='all'):
        self.first_event.setdefault(qk, event)

        self.ref_windows.setdefault(qk, EventWindow(self.timeframe, getTimestamp=self.get_ts))
        self.cur_windows.setdefault(qk, EventWindow(self.timeframe, self.ref_windows[qk].append, self.get_ts))

        self.cur_windows[qk].append((event, count))

        # Don't alert if ref window has not yet been filled
        if ts_delta(self.first_event[qk][self.ts_field], event[self.ts_field]) < self.rules['timeframe'] * 2:
            # Unless query_key and alert_on_new_data are both set and the ref window has been filled once
            if not (self.rules.get('query_key') and self.rules.get('alert_on_new_data')) or not self.ref_window_filled_once:
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

        # If we have a top_count_keys, use that to build counts based on the spike data
        top_count_keys = self.rules.get('top_count_keys')
        if top_count_keys:
            number = self.rules.get('top_count_number', 5)
            extra_info.update(get_top_counts(map(lambda e: e[0], self.cur_windows[qk].data), top_count_keys, number))

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
        message = 'An abnormal number (%d) of events occurred around %s.\n' % (match['spike_count'],
                                                                               pretty_ts(match[self.rules['timestamp_field']], self.rules.get('use_local_time')))
        message += 'Preceding that time, there were only %d events within %s\n\n' % (match['reference_count'], self.rules['timeframe'])
        return message

    def garbage_collect(self, ts):
        # Windows are sized according to their newest event
        # This is a placeholder to accurately size windows in the absence of events
        for qk in self.cur_windows.keys():
            placeholder = {self.ts_field: ts}
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
        if self.rules.get('query_key'):
            raise EAException('Flatline rule cannot use query_key')
        self.first_event = None

    def check_for_match(self):
        most_recent_ts = self.get_ts(self.occurrences['all'].data[-1])
        if not self.first_event:
            self.first_event = most_recent_ts

        # Don't check for matches until timeframe has elapsed
        if ts_delta(self.first_event, most_recent_ts) < self.rules['timeframe']:
            return

        # Match if, after removing old events, we hit num_events
        if self.occurrences['all'].count() < self.rules['threshold']:
            event = self.occurrences['all'].data[-1][0]
            self.add_match(event)
            self.occurrences.pop('all')
            self.first_event = None

    def get_match_str(self, match):
        ts = match[self.rules['timestamp_field']]
        lt = self.rules.get('use_local_time')
        message = 'An abnormally low number of events occurred around %s.\n' % (pretty_ts(ts, lt))
        message += 'Between %s and %s, there were less than %s events.\n\n' % (pretty_ts(dt_to_ts(ts_to_dt(ts) - self.rules['timeframe']), lt),
                                                                               pretty_ts(ts, lt),
                                                                               self.rules['threshold'])
        return message

    def garbage_collect(self, ts):
        # Windows are sized according to their newest event
        # This is a placeholder to accurately size windows in the absence of events
        self.occurrences.setdefault('all', EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(({self.ts_field: ts}, 0))
        self.check_for_match()


def get_top_counts(events, keys, number=5):
    """ Counts the number of events for each unique value for each key field.
    Returns a dictionary with top_events_<key> mapped to the top 5 counts for each key. """
    all_counts = {}
    for key in keys:
        terms = {}
        for event in events:
            value = hashable(lookup_es_key(event, key))
            terms[value] = terms.get(value, 0) + 1
        counts = terms.items()
        counts.sort(key=lambda x: x[1], reverse=True)
        # Save a dict with the top 5 events by key
        all_counts['top_events_%s' % (key)] = dict(counts[:number])
    return all_counts
