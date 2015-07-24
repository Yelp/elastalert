# -*- coding: utf-8 -*-
from ruletypes import *

class CardinalityRule(RuleType):
    """ A rule that matches if max_cardinality of a field is reached within a timeframe """
    required_options = frozenset(['max_cardinality', 'timeframe', 'cardinality_term'])

    def __init__(self, *args):
        super(CardinalityRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = lambda event: event[0][self.ts_field]
        self.cardinality_term = self.rules['cardinality_term']
        self.cardinality_cache = {}

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
            self.cardinality_cache.setdefault(key,{})
            if self.cardinality_term in event.keys():
                if event[self.cardinality_term] not in self.cardinality_cache[key].keys():
                    # Store the timestamps of recent occurrences, per key
                    self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))
                    self.check_for_match(key)                
                # update timestamp of that key as the timestamp of lastest occurrence 
                self.cardinality_cache[key][event[self.cardinality_term]]=event[self.ts_field]

    def check_for_match(self, key):
        # Match if, after removing old events, we hit num_events
        if self.occurrences[key].count() >= self.rules['max_cardinality']:
            event = self.occurrences[key].data[-1][0]
            self.add_match(event)
            self.occurrences.pop(key)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        for term in self.cardinality_cache.keys():
            for unique_id in self.cardinality_cache[term].keys():
                if timestamp -  self.cardinality_cache[term][unique_id] > self.rules['timeframe']:
                    del self.cardinality_cache[term][unique_id]
        stale_keys = []
        for key, window in self.occurrences.iteritems():
            if window.data[-1][0][self.cardinality_term] not in self.cardinality_cache[key].keys():
                if timestamp - window.data[-1][0][self.ts_field] > self.rules['timeframe']:
                    stale_keys.append(key)
        map(self.occurrences.pop, stale_keys)
        

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        starttime = pretty_ts(dt_to_ts(ts_to_dt(match[self.ts_field]) - self.rules['timeframe']), lt)
        endtime = pretty_ts(match[self.ts_field], lt)
        message = 'A maximum of %d unique %s(s) occurred since last alert or between %s and %s\n\n' % (self.rules['max_cardinality'],self.rules['cardinality_term'],
                                                                         starttime,
                                                                         endtime)
        return message