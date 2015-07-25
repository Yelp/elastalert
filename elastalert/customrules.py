# -*- coding: utf-8 -*-
from ruletypes import *

class CardinalityRule(RuleType):
    """ A rule that matches if max_cardinality of a field is reached within a timeframe """
    required_options = frozenset(['cardinality_term','max_cardinality', 'timeframe'])

    def __init__(self, *args):
        super(CardinalityRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = lambda event: event[0][self.ts_field]

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
            self.occurrences.setdefault(key, CardinalityWindow(self.rules['cardinality_term'],self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))
            self.check_for_match(key)

    def check_for_match(self, key):
        # Match if, after removing old events, we hit max_cardinality
        if self.occurrences[key].count() >= self.rules['max_cardinality']:
            if self.rules['query_key']:
                match = {self.rules['query_key']:key, 'events':{}}}
            else: 
                match = {'events':{}}
            for item in self.occurrences[key].data:
                match['events'][item[0][self.rules['cardinality_term']]]=self.get_ts(item)
            self.add_match(match)
            self.occurrences[key].alerted()

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.iteritems():
            if window.data:
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

class CardinalityWindow(object):
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(self, cardinality_term, timeframe, onRemoved=None, getTimestamp=lambda e: e[0]['@timestamp']):
        self.cterm = cardinality_term
        self.timeframe = timeframe
        self.onRemoved = onRemoved
        self.get_ts = getTimestamp
        self.data = deque()
        self.logBook = {}
        self.running_count = 0

    def alerted(self, timestamp):
        for event in self.data:
            self.logBook[event[0][self.cterm]]['last_alert'] = self.get_ts(self.data[-1])
        self.data = deque()
        self.running_count = 0

    def append(self, event):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        # If the event occurred before our 'latest' event
        if self.cterm in event[0].keys():
            cterm = event[0][self.cterm]
            if cterm in self.logBook.keys():
                if self.get_ts(event) > self.logBook[cterm]['lastest']:
                    self.logBook[cterm]['latest']=self.get_ts(event)
                    if not self.logBook[cterm]['last_alert']:
                        self.appendData(event)
                    elif self.get_ts(event)-self.logBook['last_alert']>=self.timeframe:
                        self.logBook['last_alert'] = None
                        self.appendData(event)
            else:
                self.logBook[cterm]={'latest':self.get_ts(event),'last_alert':None}
                self.appendData(event)
            
    def appendData(self,event):
        self.removeData(event[0][self.cterm])
        if len(self.data) and self.get_ts(self.data[-1]) > self.get_ts(event):
            self.append_middle(event)
        else:
            self.data.append(event)
            self.running_count += event[1]
        while self.duration() >= self.timeframe:
            oldest = self.data.popleft()
            self.running_count -= oldest[1]
            self.onRemoved and self.onRemoved(oldest)

    def removeData(cterm):
        dataToRemove = []
        for ele in self.data:
            if ele[0][self.cterm] == cterm:
                dataToRemove.append(ele)
        for item in dataToRemove:
            self.data.remove(item)

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
