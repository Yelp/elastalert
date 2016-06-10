# -*- coding: utf-8 -*-
import copy
import datetime
import json
import logging
import os
import signal
import sys
import time
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP
from smtplib import SMTPException
from socket import error

import argparse
import dateutil.tz
import kibana
import yaml
from alerts import DebugAlerter
from auth import Auth
from config import get_rule_hashes
from config import load_configuration
from config import load_rules
from croniter import croniter
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch
from elasticsearch.exceptions import ElasticsearchException
from enhancements import DropMatchException
from util import cronite_datetime_to_timestamp
from util import dt_to_ts
from util import EAException
from util import elastalert_logger
from util import format_index
from util import lookup_es_key
from util import pretty_ts
from util import seconds
from util import set_es_key
from util import ts_add
from util import ts_now
from util import ts_to_dt
from util import unix_to_dt
from util import add_raw_postfix


class ElastAlerter():
    """ The main Elastalert runner. This class holds all state about active rules,
    controls when queries are run, and passes information between rules and alerts.

    :param args: An argparse arguments instance. Should contain debug and start

    :param conf: The configuration dictionary. At the top level, this
    contains global options, and under 'rules', contains all state relating
    to rules and alerts. In each rule in conf['rules'], the RuleType and Alerter
    instances live under 'type' and 'alerts', respectively. The conf dictionary
    should not be passed directly from a configuration file, but must be populated
    by config.py:load_rules instead. """

    def parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument('--config', action='store', dest='config', default="config.yaml", help='Global config file (default: config.yaml)')
        parser.add_argument('--debug', action='store_true', dest='debug', help='Suppresses alerts and prints information instead')
        parser.add_argument('--rule', dest='rule', help='Run only a specific rule (by filename, must still be in rules folder)')
        parser.add_argument('--silence', dest='silence', help='Silence rule for a time period. Must be used with --rule. Usage: '
                                                              '--silence <units>=<number>, eg. --silence hours=2')
        parser.add_argument('--start', dest='start', help='YYYY-MM-DDTHH:MM:SS Start querying from this timestamp.'
                                                          'Use "NOW" to start from current time. (Default: present)')
        parser.add_argument('--end', dest='end', help='YYYY-MM-DDTHH:MM:SS Query to this timestamp. (Default: present)')
        parser.add_argument('--verbose', action='store_true', dest='verbose', help='Increase verbosity without suppressing alerts')
        parser.add_argument('--pin_rules', action='store_true', dest='pin_rules', help='Stop ElastAlert from monitoring config file changes')
        parser.add_argument('--es_debug', action='store_true', dest='es_debug', help='Enable verbose logging from Elasticsearch queries')
        parser.add_argument('--es_debug_trace', action='store', dest='es_debug_trace', help='Enable logging from Elasticsearch queries as curl command. Queries will be logged to file')
        self.args = parser.parse_args(args)

    def __init__(self, args):
        self.parse_args(args)
        self.debug = self.args.debug
        self.verbose = self.args.verbose

        if self.verbose or self.debug:
            elastalert_logger.setLevel(logging.INFO)

        if self.debug:
            elastalert_logger.info("Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them, use --verbose.")

        if not self.args.es_debug:
            logging.getLogger('elasticsearch').setLevel(logging.WARNING)

        if self.args.es_debug_trace:
            tracer = logging.getLogger('elasticsearch.trace')
            tracer.setLevel(logging.INFO)
            tracer.addHandler(logging.FileHandler(self.args.es_debug_trace))

        self.conf = load_rules(self.args)
        self.max_query_size = self.conf['max_query_size']
        self.rules = self.conf['rules']
        self.writeback_index = self.conf['writeback_index']
        self.writeback_current_status_index = self.writeback_index + "_current_status"
        self.run_every = self.conf['run_every']
        self.alert_time_limit = self.conf['alert_time_limit']
        self.old_query_limit = self.conf['old_query_limit']
        self.disable_rules_on_error = self.conf['disable_rules_on_error']
        self.notify_email = self.conf.get('notify_email', [])
        self.from_addr = self.conf.get('from_addr', 'ElastAlert')
        self.smtp_host = self.conf.get('smtp_host', 'localhost')
        self.max_aggregation = self.conf.get('max_aggregation', 10000)
        self.alerts_sent = 0
        self.num_hits = 0
        self.current_es = None
        self.current_es_addr = None
        self.buffer_time = self.conf['buffer_time']
        self.silence_cache = {}
        self.rule_hashes = get_rule_hashes(self.conf, self.args.rule)
        self.starttime = self.args.start
        self.disabled_rules = []

        self.es_conn_config = self.build_es_conn_config(self.conf)

        self.writeback_es = self.new_elasticsearch(self.es_conn_config)

        for rule in self.rules:
            self.init_rule(rule)

        if self.args.silence:
            self.silence()

    @staticmethod
    def new_elasticsearch(es_conn_conf):
        """ returns an Elasticsearch instance configured using an es_conn_config """
        auth = Auth()
        es_conn_conf['http_auth'] = auth(host=es_conn_conf['es_host'],
                                         username=es_conn_conf['es_username'],
                                         password=es_conn_conf['es_password'],
                                         aws_region=es_conn_conf['aws_region'],
                                         boto_profile=es_conn_conf['boto_profile'])

        return Elasticsearch(host=es_conn_conf['es_host'],
                             port=es_conn_conf['es_port'],
                             url_prefix=es_conn_conf['es_url_prefix'],
                             use_ssl=es_conn_conf['use_ssl'],
                             connection_class=RequestsHttpConnection,
                             http_auth=es_conn_conf['http_auth'],
                             timeout=es_conn_conf['es_conn_timeout'],
                             send_get_body_as=es_conn_conf['send_get_body_as'])

    @staticmethod
    def build_es_conn_config(conf):
        """ Given a conf dictionary w/ raw config properties 'use_ssl', 'es_host', 'es_port'
        'es_username' and 'es_password', this will return a new dictionary
        with properly initialized values for 'es_host', 'es_port', 'use_ssl' and 'http_auth' which
        will be a basicauth username:password formatted string """
        parsed_conf = {}
        parsed_conf['use_ssl'] = False
        parsed_conf['http_auth'] = None
        parsed_conf['es_username'] = None
        parsed_conf['es_password'] = None
        parsed_conf['aws_region'] = None
        parsed_conf['boto_profile'] = None
        parsed_conf['es_host'] = conf['es_host']
        parsed_conf['es_port'] = conf['es_port']
        parsed_conf['es_url_prefix'] = ''
        parsed_conf['es_conn_timeout'] = 10
        parsed_conf['send_get_body_as'] = conf.get('es_send_get_body_as', 'GET')

        if 'es_username' in conf:
            parsed_conf['es_username'] = conf['es_username']
            parsed_conf['es_password'] = conf['es_password']

        if 'aws_region' in conf:
            parsed_conf['aws_region'] = conf['aws_region']

        if 'boto_profile' in conf:
            parsed_conf['boto_profile'] = conf['boto_profile']

        if 'use_ssl' in conf:
            parsed_conf['use_ssl'] = conf['use_ssl']

        if 'es_conn_timeout' in conf:
            parsed_conf['es_conn_timeout'] = conf['es_conn_timeout']

        if 'es_url_prefix' in conf:
            parsed_conf['es_url_prefix'] = conf['es_url_prefix']

        return parsed_conf

    @staticmethod
    def get_index(rule, starttime=None, endtime=None):
        """ Gets the index for a rule. If strftime is set and starttime and endtime
        are provided, it will return a comma seperated list of indices. If strftime
        is set but starttime and endtime are not provided, it will replace all format
        tokens with a wildcard. """
        index = rule['index']
        if rule.get('use_strftime_index'):
            if starttime and endtime:
                return format_index(index, starttime, endtime)
            else:
                # Replace the substring containing format characters with a *
                format_start = index.find('%')
                format_end = index.rfind('%') + 2
                return index[:format_start] + '*' + index[format_end:]
        else:
            return index

    @staticmethod
    def get_query(filters, starttime=None, endtime=None, sort=True, timestamp_field='@timestamp', to_ts_func=dt_to_ts, desc=False):
        """ Returns a query dict that will apply a list of filters, filter by
        start and end time, and sort results by timestamp.

        :param filters: A list of elasticsearch filters to use.
        :param starttime: A timestamp to use as the start time of the query.
        :param endtime: A timestamp to use as the end time of the query.
        :param sort: If true, sort results by timestamp. (Default True)
        :return: A query dictionary to pass to elasticsearch.
        """
        starttime = to_ts_func(starttime)
        endtime = to_ts_func(endtime)
        filters = copy.copy(filters)
        es_filters = {'filter': {'bool': {'must': filters}}}
        if starttime and endtime:
            es_filters['filter']['bool']['must'].insert(0, {'range': {timestamp_field: {'gt': starttime,
                                                                                        'lte': endtime}}})
        query = {'query': {'filtered': es_filters}}
        if sort:
            query['sort'] = [{timestamp_field: {'order': 'desc' if desc else 'asc'}}]
        return query

    def get_terms_query(self, query, size, field):
        """ Takes a query generated by get_query and outputs a aggregation query """
        query = query['query']
        if 'sort' in query:
            query.pop('sort')
        query['filtered'].update({'aggs': {'counts': {'terms': {'field': field, 'size': size}}}})
        aggs_query = {'aggs': query}
        return aggs_query

    def get_index_start(self, index, timestamp_field='@timestamp'):
        """ Query for one result sorted by timestamp to find the beginning of the index.

        :param index: The index of which to find the earliest event.
        :return: Timestamp of the earliest event.
        """
        query = {'sort': {timestamp_field: {'order': 'asc'}}}
        try:
            res = self.current_es.search(index=index, size=1, body=query, _source_include=[timestamp_field], ignore_unavailable=True)
        except ElasticsearchException as e:
            self.handle_error("Elasticsearch query error: %s" % (e), {'index': index})
            return '1969-12-30T00:00:00Z'
        if len(res['hits']['hits']) == 0:
            # Index is completely empty, return a date before the epoch
            return '1969-12-30T00:00:00Z'
        return res['hits']['hits'][0][timestamp_field]

    @staticmethod
    def process_hits(rule, hits):
        """ Update the _source field for each hit received from ES based on the rule configuration.

        This replaces timestamps with datetime objects,
        folds important fields into _source and creates compound query_keys.

        :return: A list of processed _source dictionaries.
        """

        processed_hits = []
        for hit in hits:
            # Merge fields and _source
            hit.setdefault('_source', {})
            for key, value in hit.get('fields', {}).items():
                # Fields are returned as lists, assume any with length 1 are not arrays in _source
                # Except sometimes they aren't lists. This is dependent on ES version
                hit['_source'].setdefault(key, value[0] if type(value) is list and len(value) == 1 else value)

            # Convert the timestamp to a datetime
            ts = lookup_es_key(hit['_source'], rule['timestamp_field'])
            set_es_key(hit['_source'], rule['timestamp_field'], rule['ts_to_dt'](ts))
            set_es_key(hit, rule['timestamp_field'], lookup_es_key(hit['_source'], rule['timestamp_field']))

            # Tack metadata fields into _source
            for field in ['_id', '_index', '_type']:
                if field in hit:
                    hit['_source'][field] = hit[field]

            if rule.get('compound_query_key'):
                values = [lookup_es_key(hit['_source'], key) for key in rule['compound_query_key']]
                hit['_source'][rule['query_key']] = ', '.join([unicode(value) for value in values])

            processed_hits.append(hit['_source'])

        return processed_hits

    def get_hits(self, rule, starttime, endtime, index):
        """ Query elasticsearch for the given rule and return the results.

        :param rule: The rule configuration.
        :param starttime: The earliest time to query.
        :param endtime: The latest time to query.
        :return: A list of hits, bounded by rule['max_query_size'].
        """
        query = self.get_query(rule['filter'], starttime, endtime, timestamp_field=rule['timestamp_field'], to_ts_func=rule['dt_to_ts'])
        extra_args = {'_source_include': rule['include']}
        if not rule.get('_source_enabled'):
            query['fields'] = rule['include']
            extra_args = {}
        try:
            res = self.current_es.search(index=index, size=rule['max_query_size'], body=query, ignore_unavailable=True, **extra_args)
            logging.debug(str(res))
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running query: %s' % (e), {'rule': rule['name']})
            return None

        hits = res['hits']['hits']
        self.num_hits += len(hits)
        lt = rule.get('use_local_time')
        elastalert_logger.info("Queried rule %s from %s to %s: %s hits" % (rule['name'], pretty_ts(starttime, lt), pretty_ts(endtime, lt), len(hits)))
        hits = self.process_hits(rule, hits)

        # Record doc_type for use in get_top_counts
        if 'doc_type' not in rule and len(hits):
            rule['doc_type'] = hits[0]['_type']
        return hits

    def get_hits_count(self, rule, starttime, endtime, index):
        """ Query elasticsearch for the count of results and returns a list of timestamps
        equal to the endtime. This allows the results to be passed to rules which expect
        an object for each hit.

        :param rule: The rule configuration dictionary.
        :param starttime: The earliest time to query.
        :param endtime: The latest time to query.
        :return: A dictionary mapping timestamps to number of hits for that time period.
        """
        query = self.get_query(rule['filter'], starttime, endtime, timestamp_field=rule['timestamp_field'], sort=False, to_ts_func=rule['dt_to_ts'])

        try:
            res = self.current_es.count(index=index, doc_type=rule['doc_type'], body=query, ignore_unavailable=True)
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running count query: %s' % (e), {'rule': rule['name']})
            return None

        self.num_hits += res['count']
        lt = rule.get('use_local_time')
        elastalert_logger.info("Queried rule %s from %s to %s: %s hits" % (rule['name'], pretty_ts(starttime, lt), pretty_ts(endtime, lt), res['count']))
        return {endtime: res['count']}

    def get_hits_terms(self, rule, starttime, endtime, index, key, qk=None, size=None):
        rule_filter = copy.copy(rule['filter'])
        if qk:
            filter_key = rule['query_key']
            if rule.get('raw_count_keys', True) and not rule['query_key'].endswith('.raw'):
                filter_key = add_raw_postfix(filter_key)
            rule_filter.extend([{'term': {filter_key: qk}}])
        base_query = self.get_query(rule_filter, starttime, endtime, timestamp_field=rule['timestamp_field'], sort=False, to_ts_func=rule['dt_to_ts'])
        if size is None:
            size = rule.get('terms_size', 50)
        query = self.get_terms_query(base_query, size, key)

        try:
            res = self.current_es.search(index=index, doc_type=rule['doc_type'], body=query, search_type='count', ignore_unavailable=True)
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running query: %s' % (e), {'rule': rule['name']})
            return None

        if 'aggregations' not in res:
            return {}
        buckets = res['aggregations']['filtered']['counts']['buckets']
        self.num_hits += len(buckets)
        lt = rule.get('use_local_time')
        elastalert_logger.info('Queried rule %s from %s to %s: %s buckets' % (rule['name'], pretty_ts(starttime, lt), pretty_ts(endtime, lt), len(buckets)))
        return {endtime: buckets}

    def remove_duplicate_events(self, data, rule):
        new_events = []
        for event in data:
            if event['_id'] in rule['processed_hits']:
                continue

            # Remember the new data's IDs
            rule['processed_hits'][event['_id']] = lookup_es_key(event, rule['timestamp_field'])
            new_events.append(event)

        return new_events

    def remove_old_events(self, rule):
        # Anything older than the buffer time we can forget
        now = ts_now()
        remove = []
        buffer_time = rule.get('buffer_time', self.buffer_time)
        for _id, timestamp in rule['processed_hits'].iteritems():
            if now - timestamp > buffer_time:
                remove.append(_id)
        map(rule['processed_hits'].pop, remove)

    def run_query(self, rule, start=None, end=None):
        """ Query for the rule and pass all of the results to the RuleType instance.

        :param rule: The rule configuration.
        :param start: The earliest time to query.
        :param end: The latest time to query.
        Returns True on success and False on failure.
        """
        if start is None:
            start = self.get_index_start(rule['index'])
        if end is None:
            end = ts_now()

        # Reset hit counter and query
        rule_inst = rule['type']
        prev_num_hits = self.num_hits
        max_size = rule.get('max_query_size', self.max_query_size)
        index = self.get_index(rule, start, end)
        if rule.get('use_count_query'):
            data = self.get_hits_count(rule, start, end, index)
        elif rule.get('use_terms_query'):
            data = self.get_hits_terms(rule, start, end, index, rule['query_key'])
        else:
            data = self.get_hits(rule, start, end, index)
            if data:
                data = self.remove_duplicate_events(data, rule)

        # There was an exception while querying
        if data is None:
            return False
        elif data:
            if rule.get('use_count_query'):
                rule_inst.add_count_data(data)
            elif rule.get('use_terms_query'):
                rule_inst.add_terms_data(data)
            else:
                rule_inst.add_data(data)
        # Warn if we hit max_query_size
        if self.num_hits - prev_num_hits == max_size and not rule.get('use_count_query'):
            logging.warning("Hit max_query_size (%s) while querying for %s" % (max_size, rule['name']))

        return True

    def get_starttime(self, rule):
        """ Query ES for the last time we ran this rule.

        :param rule: The rule configuration.
        :return: A timestamp or None.
        """
        query = {'filter': {'term': {'rule_name': '%s' % (rule['name'])}},
                 'sort': {'@timestamp': {'order': 'desc'}}}
        try:
            if self.writeback_es:
                res = self.writeback_es.search(index=self.writeback_index, doc_type='elastalert_status',
                                               size=1, body=query, _source_include=['endtime', 'rule_name'])
                if res['hits']['hits']:
                    endtime = ts_to_dt(res['hits']['hits'][0]['_source']['endtime'])

                    if ts_now() - endtime < self.old_query_limit:
                        return endtime
                    else:
                        elastalert_logger.info("Found expired previous run for %s at %s" % (rule['name'], endtime))
                        return None
        except (ElasticsearchException, KeyError) as e:
            self.handle_error('Error querying for last run: %s' % (e), {'rule': rule['name']})
            self.writeback_es = None

    def set_starttime(self, rule, endtime):
        """ Given a rule and an endtime, sets the appropriate starttime for it. """

        # This means we are starting fresh
        if 'starttime' not in rule:
            # Try to get the last run from elasticsearch
            last_run_end = self.get_starttime(rule)
            if last_run_end:
                rule['minimum_starttime'] = last_run_end
                rule['starttime'] = last_run_end
                return None

        # Use buffer for normal queries, or run_every increments otherwise
        buffer_time = rule.get('buffer_time', self.buffer_time)
        if not rule.get('use_count_query') and not rule.get('use_terms_query'):
            buffer_delta = endtime - buffer_time
            # If we started using a previous run, don't go past that
            if 'minimum_starttime' in rule and rule['minimum_starttime'] > buffer_delta:
                rule['starttime'] = rule['minimum_starttime']
            # If buffer_time doesn't bring us past the previous endtime, use that instead
            elif 'previous_endtime' in rule and rule['previous_endtime'] < buffer_delta:
                rule['starttime'] = rule['previous_endtime']
            else:
                rule['starttime'] = buffer_delta
        else:
            # Query from the end of the last run, if it exists, otherwise a run_every sized window
            rule['starttime'] = rule.get('previous_endtime', endtime - self.run_every)

    def get_segment_size(self, rule):
        """ The segment size is either buffer_size for normal queries or run_every for
        count style queries. This mimicks the query size for when ElastAlert is running continuously. """
        if not rule.get('use_count_query') and not rule.get('use_terms_query'):
            return rule.get('buffer_time', self.buffer_time)
        return self.run_every

    def run_rule(self, rule, endtime, starttime=None):
        """ Run a rule for a given time period, including querying and alerting on results.

        :param rule: The rule configuration.
        :param starttime: The earliest timestamp to query.
        :param endtime: The latest timestamp to query.
        :return: The number of matches that the rule produced.
        """
        run_start = time.time()

        rule_es_conn_config = self.build_es_conn_config(rule)
        self.current_es = self.new_elasticsearch(rule_es_conn_config)
        self.current_es_addr = (rule['es_host'], rule['es_port'])

        # If there are pending aggregate matches, try processing them
        for x in range(len(rule['agg_matches'])):
            match = rule['agg_matches'].pop()
            self.add_aggregated_alert(match, rule)

        # Start from provided time if it's given
        if starttime:
            rule['starttime'] = starttime
        else:
            self.set_starttime(rule, endtime)
        rule['original_starttime'] = rule['starttime']

        # Don't run if starttime was set to the future
        if ts_now() <= rule['starttime']:
            logging.warning("Attempted to use query start time in the future (%s), sleeping instead" % (starttime))
            return 0

        # Run the rule. If querying over a large time period, split it up into segments
        self.num_hits = 0
        segment_size = self.get_segment_size(rule)

        while endtime - rule['starttime'] > segment_size:
            tmp_endtime = rule['starttime'] + segment_size
            if not self.run_query(rule, rule['starttime'], tmp_endtime):
                return 0
            rule['starttime'] = tmp_endtime
            rule['type'].garbage_collect(tmp_endtime)
        if not self.run_query(rule, rule['starttime'], endtime):
            return 0
        rule['type'].garbage_collect(endtime)

        # Process any new matches
        num_matches = len(rule['type'].matches)
        self .update_current_status(num_matches, rule)
        while rule['type'].matches:
            match = rule['type'].matches.pop(0)

            # If realert is set, silence the rule for that duration
            # Silence is cached by query_key, if it exists
            # Default realert time is 0 seconds

            # concatenate query_key (or none) with rule_name to form silence_cache key
            if 'query_key' in rule:
                try:
                    key = '.' + unicode(lookup_es_key(match, rule['query_key']))
                except KeyError:
                    # Some matches may not have a query key
                    # Use a special token for these to not clobber all alerts
                    key = '._missing'
            else:
                key = ''

            if self.is_silenced(rule['name'] + key) or self.is_silenced(rule['name']):
                elastalert_logger.info('Ignoring match for silenced rule %s%s' % (rule['name'], key))
                continue

            if rule['realert']:
                next_alert, exponent = self.next_alert_time(rule, rule['name'] + key, ts_now())
                self.set_realert(rule['name'] + key, next_alert, exponent)

            # If no aggregation, alert immediately
            if not rule['aggregation']:
                self.alert([match], rule)
                continue

            # Add it as an aggregated match
            self.add_aggregated_alert(match, rule)

        # Mark this endtime for next run's start
        rule['previous_endtime'] = endtime

        time_taken = time.time() - run_start
        # Write to ES that we've run this rule against this time period
        body = {'rule_name': rule['name'],
                'endtime': endtime,
                'starttime': rule['original_starttime'],
                'matches': num_matches,
                'hits': self.num_hits,
                '@timestamp': ts_now(),
                'time_taken': time_taken}
        self.writeback('elastalert_status', body)

        return num_matches

    def update_current_status(self, num_matches, rule):
        body = {'rule_name': rule['name'],
                'is_active': str(int(num_matches > 0)),
                '@timestamp': ts_now()}
        self.writeback_es.index(index=self.writeback_current_status_index,
                                doc_type="current_status",
                                body=body,
                                id=rule['name'])

    def init_rule(self, new_rule, new=True):
        ''' Copies some necessary non-config state from an exiting rule to a new rule. '''
        if 'download_dashboard' in new_rule['filter']:
            # Download filters from kibana and set the rules filters to them
            db_filters = self.filters_from_kibana(new_rule, new_rule['filter']['download_dashboard'])
            if db_filters is not None:
                new_rule['filter'] = db_filters
            else:
                raise EAException("Could not download filters from %s" % (new_rule['filter']['download_dashboard']))

        blank_rule = {'agg_matches': [],
                      'current_aggregate_id': None,
                      'processed_hits': {}}
        rule = blank_rule

        # Set rule to either a blank template or existing rule with same name
        if not new:
            for rule in self.rules:
                if rule['name'] == new_rule['name']:
                    break
            else:
                logging.warning("Couldn't find existing rule %s, starting from scratch" % (new_rule['name']))
                rule = blank_rule

        copy_properties = ['agg_matches',
                           'current_aggregate_id',
                           'aggregate_alert_time',
                           'processed_hits',
                           'starttime',
                           'minimum_starttime']
        for prop in copy_properties:
            if prop not in rule:
                continue
            new_rule[prop] = rule[prop]

        return new_rule

    def load_rule_changes(self):
        ''' Using the modification times of rule config files, syncs the running rules
        to match the files in rules_folder by removing, adding or reloading rules. '''
        new_rule_hashes = get_rule_hashes(self.conf, self.args.rule)

        # Check each current rule for changes
        for rule_file, hash_value in self.rule_hashes.iteritems():
            if rule_file not in new_rule_hashes:
                # Rule file was deleted
                elastalert_logger.info('Rule file %s not found, stopping rule execution' % (rule_file))
                self.rules = [rule for rule in self.rules if rule['rule_file'] != rule_file]
                continue
            if hash_value != new_rule_hashes[rule_file]:
                # Rule file was changed, reload rule
                try:
                    new_rule = load_configuration(rule_file, self.conf)
                except EAException as e:
                    message = 'Could not load rule %s: %s' % (rule_file, e)
                    self.handle_error(message)
                    # Want to send email to address specified in the rule. Try and load the YAML to find it.
                    with open(rule_file) as f:
                        try:
                            rule_yaml = yaml.load(f)
                        except yaml.scanner.ScannerError:
                            self.send_notification_email(exception=e)
                            continue

                    self.send_notification_email(exception=e, rule=rule_yaml)
                    continue
                elastalert_logger.info("Reloading configuration for rule %s" % (rule_file))

                # Re-enable if rule had been disabled
                for disabled_rule in self.disabled_rules:
                    if disabled_rule['name'] == new_rule['name']:
                        self.rules.append(disabled_rule)
                        self.disabled_rules.remove(disabled_rule)
                        break

                # Initialize the rule that matches rule_file
                self.rules = [rule if rule['rule_file'] != rule_file else self.init_rule(new_rule, False) for rule in self.rules]

                # If the rule failed to load previously, it needs to be added to self.rules
                if new_rule['name'] not in [rule['name'] for rule in self.rules]:
                    self.rules.append(self.init_rule(new_rule))

        # Load new rules
        if not self.args.rule:
            for rule_file in set(new_rule_hashes.keys()) - set(self.rule_hashes.keys()):
                try:
                    new_rule = load_configuration(rule_file, self.conf)
                    if new_rule['name'] in [rule['name'] for rule in self.rules]:
                        raise EAException("A rule with the name %s already exists" % (new_rule['name']))
                except EAException as e:
                    self.handle_error('Could not load rule %s: %s' % (rule_file, e))
                    self.send_notification_email(exception=e, rule_file=rule_file)
                    continue
                elastalert_logger.info('Loaded new rule %s' % (rule_file))
                self.rules.append(self.init_rule(new_rule))

        self.rule_hashes = new_rule_hashes

    def start(self):
        """ Periodically go through each rule and run it """
        if self.starttime:
            if self.starttime == 'NOW':
                self.starttime = ts_now()
            else:
                try:
                    self.starttime = ts_to_dt(self.starttime)
                except (TypeError, ValueError):
                    self.handle_error("%s is not a valid ISO8601 timestamp (YYYY-MM-DDTHH:MM:SS+XX:00)" % (self.starttime))
                    exit(1)
        self.running = True
        elastalert_logger.info("Starting up")
        while self.running:
            next_run = datetime.datetime.utcnow() + self.run_every

            self.run_all_rules()

            # Quit after end_time has been reached
            if self.args.end:
                endtime = ts_to_dt(self.args.end)

                if next_run.replace(tzinfo=dateutil.tz.tzutc()) > endtime:
                    exit(0)

            if next_run < datetime.datetime.utcnow():
                continue

            # Wait before querying again
            sleep_duration = (next_run - datetime.datetime.utcnow()).seconds
            self.sleep_for(sleep_duration)

    def run_all_rules(self):
        """ Run each rule one time """
        # If writeback_es errored, it's disabled until the next query cycle
        if not self.writeback_es:
            self.writeback_es = self.new_elasticsearch(self.es_conn_config)

        self.send_pending_alerts()

        next_run = datetime.datetime.utcnow() + self.run_every

        for rule in self.rules:
            # Set endtime based on the rule's delay
            delay = rule.get('query_delay')
            if hasattr(self.args, 'end') and self.args.end:
                endtime = ts_to_dt(self.args.end)
            elif delay:
                endtime = ts_now() - delay
            else:
                endtime = ts_now()

            try:
                num_matches = self.run_rule(rule, endtime, self.starttime)
            except EAException as e:
                self.handle_error("Error running rule %s: %s" % (rule['name'], e), {'rule': rule['name']})
            except Exception as e:
                self.handle_uncaught_exception(e, rule)
            else:
                old_starttime = pretty_ts(rule.get('original_starttime'), rule.get('use_local_time'))
                elastalert_logger.info("Ran %s from %s to %s: %s query hits, %s matches,"
                                       " %s alerts sent" % (rule['name'], old_starttime, pretty_ts(endtime, rule.get('use_local_time')),
                                                            self.num_hits, num_matches, self.alerts_sent))
                self.alerts_sent = 0

            self.remove_old_events(rule)

        if next_run < datetime.datetime.utcnow():
            # We were processing for longer than our refresh interval
            # This can happen if --start was specified with a large time period
            # or if we are running too slow to process events in real time.
            logging.warning("Querying from %s to %s took longer than %s!" % (old_starttime, endtime, self.run_every))

        # Only force starttime once
        self.starttime = None

        if not self.args.pin_rules:
            self.load_rule_changes()

    def stop(self):
        """ Stop an elastalert runner that's been started """
        self.running = False

    def sleep_for(self, duration):
        """ Sleep for a set duration """
        elastalert_logger.info("Sleeping for %s seconds" % (duration))
        time.sleep(duration)

    def generate_kibana4_db(self, rule, match):
        ''' Creates a link for a kibana4 dashboard which has time set to the match. '''
        db_name = rule.get('use_kibana4_dashboard')
        start = ts_add(match[rule['timestamp_field']], -rule.get('kibana4_start_timedelta', rule.get('timeframe', datetime.timedelta(minutes=10))))
        end = ts_add(match[rule['timestamp_field']], rule.get('kibana4_end_timedelta', rule.get('timeframe', datetime.timedelta(minutes=10))))
        return kibana.kibana4_dashboard_link(db_name, start, end)

    def generate_kibana_db(self, rule, match):
        ''' Uses a template dashboard to upload a temp dashboard showing the match.
        Returns the url to the dashboard. '''
        db = copy.deepcopy(kibana.dashboard_temp)

        # Set timestamp fields to match our rule especially if
        # we have configured something other than @timestamp
        kibana.set_timestamp_field(db, rule['timestamp_field'])

        # Set filters
        for filter in rule['filter']:
            if filter:
                kibana.add_filter(db, filter)
        kibana.set_included_fields(db, rule['include'])

        # Set index
        index = self.get_index(rule)
        kibana.set_index_name(db, index)

        return self.upload_dashboard(db, rule, match)

    def upload_dashboard(self, db, rule, match):
        ''' Uploads a dashboard schema to the kibana-int elasticsearch index associated with rule.
        Returns the url to the dashboard. '''
        # Set time range
        start = ts_add(match[rule['timestamp_field']], -rule.get('timeframe', datetime.timedelta(minutes=10)))
        end = ts_add(match[rule['timestamp_field']], datetime.timedelta(minutes=10))
        kibana.set_time(db, start, end)

        # Set dashboard name
        db_name = 'ElastAlert - %s - %s' % (rule['name'], end)
        kibana.set_name(db, db_name)

        # Add filter for query_key value
        if 'query_key' in rule:
            for qk in rule.get('compound_query_key', [rule['query_key']]):
                if qk in match:
                    term = {'term': {qk: match[qk]}}
                    kibana.add_filter(db, term)

        # Convert to json
        db_js = json.dumps(db)
        db_body = {'user': 'guest',
                   'group': 'guest',
                   'title': db_name,
                   'dashboard': db_js}

        # Upload
        rule_es_conn_config = self.build_es_conn_config(rule)
        es = self.new_elasticsearch(rule_es_conn_config)

        res = es.create(index='kibana-int',
                        doc_type='temp',
                        body=db_body)

        # Return dashboard URL
        kibana_url = rule.get('kibana_url')
        if not kibana_url:
            kibana_url = 'http://%s:%s/_plugin/kibana/' % (rule['es_host'],
                                                           rule['es_port'])
        return kibana_url + '#/dashboard/temp/%s' % (res['_id'])

    def get_dashboard(self, rule, db_name):
        """ Download dashboard which matches use_kibana_dashboard from elasticsearch. """
        rule_es_conn_config = self.build_es_conn_config(rule)
        es = self.new_elasticsearch(rule_es_conn_config)
        if not db_name:
            raise EAException("use_kibana_dashboard undefined")
        query = {'query': {'term': {'_id': db_name}}}
        try:
            res = es.search(index='kibana-int', doc_type='dashboard', body=query, _source_include=['dashboard'])
        except ElasticsearchException as e:
            raise EAException("Error querying for dashboard: %s" % (e))

        if res['hits']['hits']:
            return json.loads(res['hits']['hits'][0]['_source']['dashboard'])
        else:
            raise EAException("Could not find dashboard named %s" % (db_name))

    def use_kibana_link(self, rule, match):
        """ Uploads an existing dashboard as a temp dashboard modified for match time.
        Returns the url to the dashboard. """
        # Download or get cached dashboard
        dashboard = rule.get('dashboard_schema')
        if not dashboard:
            db_name = rule.get('use_kibana_dashboard')
            dashboard = self.get_dashboard(rule, db_name)
        if dashboard:
            rule['dashboard_schema'] = dashboard
        else:
            return None
        dashboard = copy.deepcopy(dashboard)
        return self.upload_dashboard(dashboard, rule, match)

    def filters_from_kibana(self, rule, db_name):
        """ Downloads a dashboard from kibana and returns corresponding filters, None on error. """
        try:
            db = rule.get('dashboard_schema')
            if not db:
                db = self.get_dashboard(rule, db_name)
            filters = kibana.filters_from_dashboard(db)
        except EAException:
            return None
        return filters

    def alert(self, matches, rule, alert_time=None):
        """ Wraps alerting, kibana linking and enhancements in an exception handler """
        try:
            return self.send_alert(matches, rule, alert_time=alert_time)
        except Exception as e:
            self.handle_uncaught_exception(e, rule)

    def send_alert(self, matches, rule, alert_time=None):
        """ Send out an alert.

        :param matches: A list of matches.
        :param rule: A rule configuration.
        """
        if alert_time is None:
            alert_time = ts_now()

        # Compute top count keys
        if rule.get('top_count_keys'):
            for match in matches:
                if 'query_key' in rule and rule['query_key'] in match:
                    qk = match[rule['query_key']]
                else:
                    qk = None
                start = ts_to_dt(match[rule['timestamp_field']]) - rule.get('timeframe', datetime.timedelta(minutes=10))
                end = ts_to_dt(match[rule['timestamp_field']]) + datetime.timedelta(minutes=10)
                keys = rule.get('top_count_keys')
                counts = self.get_top_counts(rule, start, end, keys, qk=qk)
                match.update(counts)

        # Generate a kibana3 dashboard for the first match
        if rule.get('generate_kibana_link') or rule.get('use_kibana_dashboard'):
            try:
                if rule.get('generate_kibana_link'):
                    kb_link = self.generate_kibana_db(rule, matches[0])
                else:
                    kb_link = self.use_kibana_link(rule, matches[0])
            except EAException as e:
                self.handle_error("Could not generate kibana dash for %s match: %s" % (rule['name'], e))
            else:
                if kb_link:
                    matches[0]['kibana_link'] = kb_link

        if rule.get('use_kibana4_dashboard'):
            kb_link = self.generate_kibana4_db(rule, matches[0])
            if kb_link:
                matches[0]['kibana_link'] = kb_link

        for enhancement in rule['match_enhancements']:
            valid_matches = []
            for match in matches:
                try:
                    enhancement.process(match)
                    valid_matches.append(match)
                except DropMatchException as e:
                    pass
                except EAException as e:
                    self.handle_error("Error running match enhancement: %s" % (e), {'rule': rule['name']})
            matches = valid_matches
            if not matches:
                return None

        # Don't send real alerts in debug mode
        if self.debug:
            alerter = DebugAlerter(rule)
            alerter.alert(matches)
            return None

        # Run the alerts
        alert_sent = False
        alert_exception = None
        # Alert.pipeline is a single object shared between every alerter
        # This allows alerters to pass objects and data between themselves
        alert_pipeline = {"alert_time": alert_time}
        for alert in rule['alert']:
            alert.pipeline = alert_pipeline
            try:
                alert.alert(matches)
            except EAException as e:
                self.handle_error('Error while running alert %s: %s' % (alert.get_info()['type'], e), {'rule': rule['name']})
                alert_exception = str(e)
            else:
                self.alerts_sent += 1
                alert_sent = True

        # Write the alert(s) to ES
        agg_id = None
        for match in matches:
            alert_body = self.get_alert_body(match, rule, alert_sent, alert_time, alert_exception)
            # Set all matches to aggregate together
            if agg_id:
                alert_body['aggregate_id'] = agg_id
            res = self.writeback('elastalert', alert_body)
            if res and not agg_id:
                agg_id = res['_id']

    def get_alert_body(self, match, rule, alert_sent, alert_time, alert_exception=None):
        body = {'match_body': match}
        body['rule_name'] = rule['name']
        # TODO record info about multiple alerts
        body['alert_info'] = rule['alert'][0].get_info()
        body['alert_sent'] = alert_sent
        body['alert_time'] = alert_time

        # If the alert failed to send, record the exception
        if not alert_sent:
            body['alert_exception'] = alert_exception
        return body

    def writeback(self, doc_type, body):
        # Convert any datetime objects to timestamps
        for key in body.keys():
            if isinstance(body[key], datetime.datetime):
                body[key] = dt_to_ts(body[key])
        if self.debug:
            elastalert_logger.info("Skipping writing to ES: %s" % (body))
            return None

        if '@timestamp' not in body:
            body['@timestamp'] = dt_to_ts(ts_now())
        if self.writeback_es:
            try:
                res = self.writeback_es.create(index=self.writeback_index,
                                               doc_type=doc_type, body=body)
                return res
            except ElasticsearchException as e:
                logging.exception("Error writing alert info to elasticsearch: %s" % (e))
                self.writeback_es = None

    def find_recent_pending_alerts(self, time_limit):
        """ Queries writeback_es to find alerts that did not send
        and are newer than time_limit """

        # XXX only fetches 1000 results. If limit is reached, next loop will catch them
        # unless there is constantly more than 1000 alerts to send.

        # Fetch recent, unsent alerts that aren't part of an aggregate, earlier alerts first.
        query = {'query': {'query_string': {'query': '!_exists_:aggregate_id AND alert_sent:false'}},
                 'filter': {'range': {'alert_time': {'from': dt_to_ts(ts_now() - time_limit),
                                                     'to': dt_to_ts(ts_now())}}},
                 'sort': {'alert_time': {'order': 'asc'}}}
        if self.writeback_es:
            try:
                res = self.writeback_es.search(index=self.writeback_index,
                                               doc_type='elastalert',
                                               body=query,
                                               size=1000)
                if res['hits']['hits']:
                    return res['hits']['hits']
            except:  # TODO: Give this a more relevant exception, try:except: is evil.
                pass
        return []

    def send_pending_alerts(self):
        pending_alerts = self.find_recent_pending_alerts(self.alert_time_limit)
        for alert in pending_alerts:
            _id = alert['_id']
            alert = alert['_source']
            try:
                rule_name = alert.pop('rule_name')
                alert_time = alert.pop('alert_time')
                match_body = alert.pop('match_body')
            except KeyError:
                # Malformed alert, drop it
                continue

            # Find original rule
            for rule in self.rules:
                if rule['name'] == rule_name:
                    break
            else:
                # Original rule is missing, keep alert for later if rule reappears
                continue

            # Set current_es for top_count_keys query
            rule_es_conn_config = self.build_es_conn_config(rule)
            self.current_es = self.new_elasticsearch(rule_es_conn_config)
            self.current_es_addr = (rule['es_host'], rule['es_port'])

            # Send the alert unless it's a future alert
            if ts_now() > ts_to_dt(alert_time):
                aggregated_matches = self.get_aggregated_matches(_id)
                if aggregated_matches:
                    matches = [match_body] + [agg_match['match_body'] for agg_match in aggregated_matches]
                    self.alert(matches, rule, alert_time=alert_time)
                    if rule['current_aggregate_id'] == _id:
                        rule['current_aggregate_id'] = None
                else:
                    self.alert([match_body], rule, alert_time=alert_time)

                # Delete it from the index
                try:
                    self.writeback_es.delete(index=self.writeback_index,
                                             doc_type='elastalert',
                                             id=_id)
                except:  # TODO: Give this a more relevant exception, try:except: is evil.
                    self.handle_error("Failed to delete alert %s at %s" % (_id, alert_time))

        # Send in memory aggregated alerts
        for rule in self.rules:
            if rule['agg_matches']:
                if ts_now() > rule['aggregate_alert_time']:
                    self.alert(rule['agg_matches'], rule)
                    rule['agg_matches'] = []

    def get_aggregated_matches(self, _id):
        """ Removes and returns all matches from writeback_es that have aggregate_id == _id """

        # XXX if there are more than self.max_aggregation matches, you have big alerts and we will leave entries in ES.
        query = {'query': {'query_string': {'query': 'aggregate_id:%s' % (_id)}}}
        matches = []
        if self.writeback_es:
            try:
                res = self.writeback_es.search(index=self.writeback_index,
                                               doc_type='elastalert',
                                               body=query,
                                               size=self.max_aggregation)
                for match in res['hits']['hits']:
                    matches.append(match['_source'])
                    self.writeback_es.delete(index=self.writeback_index,
                                             doc_type='elastalert',
                                             id=match['_id'])
            except (KeyError, ElasticsearchException) as e:
                self.handle_error("Error fetching aggregated matches: %s" % (e), {'id': _id})
        return matches

    def find_pending_aggregate_alert(self, rule):
        query = {'filter': {'bool': {'must': [{'term': {'rule_name': rule['name']}},
                                              {'range': {'alert_time': {'gt': ts_now()}}},
                                              {'not': {'exists': {'field': 'aggregate_id'}}},
                                              {'term': {'alert_sent': 'false'}}]}},
                 'sort': {'alert_time': {'order': 'desc'}}}
        if not self.writeback_es:
            self.writeback_es = self.new_elasticsearch(self.es_conn_config)
        try:
            res = self.writeback_es.search(index=self.writeback_index,
                                           doc_type='elastalert',
                                           body=query,
                                           size=1)
            if len(res['hits']['hits']) == 0:
                return None
        except (KeyError, ElasticsearchException) as e:
            self.handle_error("Error searching for pending aggregated matches: %s" % (e), {'rule_name': rule['name']})
            return None

        return res['hits']['hits'][0]

    def add_aggregated_alert(self, match, rule):
        """ Save a match as a pending aggregate alert to elasticsearch. """
        if (not rule['current_aggregate_id'] or
                ('aggregate_alert_time' in rule and rule['aggregate_alert_time'] < ts_to_dt(match[rule['timestamp_field']]))):

            # Elastalert may have restarted while pending alerts exist
            pending_alert = self.find_pending_aggregate_alert(rule)
            if pending_alert:
                alert_time = rule['aggregate_alert_time'] = ts_to_dt(pending_alert['_source']['alert_time'])
                agg_id = rule['current_aggregate_id'] = pending_alert['_id']
                elastalert_logger.info('Adding alert for %s to aggregation(id: %s), next alert at %s' % (rule['name'], agg_id, alert_time))
            else:
                # First match, set alert_time
                match_time = ts_to_dt(match[rule['timestamp_field']])
                alert_time = ''
                if isinstance(rule['aggregation'], dict) and rule['aggregation'].get('schedule'):
                    croniter._datetime_to_timestamp = cronite_datetime_to_timestamp  # For Python 2.6 compatibility
                    try:
                        iter = croniter(rule['aggregation']['schedule'], ts_now())
                        alert_time = unix_to_dt(iter.get_next())
                    except Exception as e:
                        self.handle_error("Error parsing aggregate send time Cron format %s" % (e), rule['aggregation']['schedule'])
                else:
                    alert_time = match_time + rule['aggregation']

                rule['aggregate_alert_time'] = alert_time
                agg_id = None
                elastalert_logger.info('New aggregation for %s. next alert at %s.' % (rule['name'], alert_time))
        else:
            # Already pending aggregation, use existing alert_time
            alert_time = rule['aggregate_alert_time']
            agg_id = rule['current_aggregate_id']
            elastalert_logger.info('Adding alert for %s to aggregation(id: %s), next alert at %s' % (rule['name'], agg_id, alert_time))

        alert_body = self.get_alert_body(match, rule, False, alert_time)
        if agg_id:
            alert_body['aggregate_id'] = agg_id
        res = self.writeback('elastalert', alert_body)

        # If new aggregation, save _id
        if res and not agg_id:
            rule['current_aggregate_id'] = res['_id']

        # Couldn't write the match to ES, save it in memory for now
        if not res:
            rule['agg_matches'].append(match)

        return res

    def silence(self):
        """ Silence an alert for a period of time. --silence and --rule must be passed as args. """
        if self.debug:
            logging.error('--silence not compatible with --debug')
            exit(1)

        if not self.args.rule:
            logging.error('--silence must be used with --rule')
            exit(1)

        # With --rule, self.rules will only contain that specific rule
        rule_name = self.rules[0]['name']

        try:
            unit, num = self.args.silence.split('=')
            silence_time = datetime.timedelta(**{unit: int(num)})
            # Double conversion to add tzinfo
            silence_ts = ts_to_dt(dt_to_ts(silence_time + datetime.datetime.utcnow()))
        except (ValueError, TypeError):
            logging.error('%s is not a valid time period' % (self.args.silence))
            exit(1)

        if not self.set_realert(rule_name, silence_ts, 0):
            logging.error('Failed to save silence command to elasticsearch')
            exit(1)

        elastalert_logger.info('Success. %s will be silenced until %s' % (rule_name, silence_ts))

    def set_realert(self, rule_name, timestamp, exponent):
        """ Write a silence to elasticsearch for rule_name until timestamp. """
        body = {'exponent': exponent,
                'rule_name': rule_name,
                '@timestamp': ts_now(),
                'until': timestamp}

        self.silence_cache[rule_name] = (timestamp, exponent)
        return self.writeback('silence', body)

    def is_silenced(self, rule_name):
        """ Checks if rule_name is currently silenced. Returns false on exception. """
        if rule_name in self.silence_cache:
            if ts_now() < self.silence_cache[rule_name][0]:
                return True
            else:
                return False

        if self.debug:
            return False

        query = {'filter': {'term': {'rule_name': rule_name}},
                 'sort': {'until': {'order': 'desc'}}}

        if self.writeback_es:
            try:
                res = self.writeback_es.search(index=self.writeback_index, doc_type='silence',
                                               size=1, body=query, _source_include=['until', 'exponent'])
            except ElasticsearchException as e:
                self.handle_error("Error while querying for alert silence status: %s" % (e), {'rule': rule_name})

                return False

            if res['hits']['hits']:
                until_ts = res['hits']['hits'][0]['_source']['until']
                exponent = res['hits']['hits'][0]['_source'].get('exponent', 0)

                self.silence_cache[rule_name] = (ts_to_dt(until_ts), exponent)
                if ts_now() < ts_to_dt(until_ts):
                    return True
        return False

    def handle_error(self, message, data=None):
        ''' Logs message at error level and writes message, data and traceback to Elasticsearch. '''
        if not self.writeback_es:
            self.writeback_es = self.new_elasticsearch(self.es_conn_config)

        logging.error(message)
        body = {'message': message}
        tb = traceback.format_exc()
        body['traceback'] = tb.strip().split('\n')
        if data:
            body['data'] = data
        self.writeback('elastalert_error', body)

    def handle_uncaught_exception(self, exception, rule):
        """ Disables a rule and sends a notification. """
        logging.error(traceback.format_exc())
        self.handle_error('Uncaught exception running rule %s: %s' % (rule['name'], exception), {'rule': rule['name']})
        if self.disable_rules_on_error:
            self.rules = [running_rule for running_rule in self.rules if running_rule['name'] != rule['name']]
            self.disabled_rules.append(rule)
            elastalert_logger.info('Rule %s disabled', rule['name'])
        if self.notify_email:
            self.send_notification_email(exception=exception, rule=rule)

    def send_notification_email(self, text='', exception=None, rule=None, subject=None, rule_file=None):
        email_body = text
        rule_name = None
        if rule:
            rule_name = rule['name']
        elif rule_file:
            rule_name = rule_file
        if exception and rule_name:
            if not subject:
                subject = 'Uncaught exception in ElastAlert - %s' % (rule_name)
            email_body += '\n\n'
            email_body += 'The rule %s has raised an uncaught exception.\n\n' % (rule_name)
            if self.disable_rules_on_error:
                modified = ' or if the rule config file has been modified' if not self.args.pin_rules else ''
                email_body += 'It has been disabled and will be re-enabled when ElastAlert restarts%s.\n\n' % (modified)
            tb = traceback.format_exc()
            email_body += tb

        if isinstance(self.notify_email, basestring):
            self.notify_email = [self.notify_email]
        email = MIMEText(email_body)
        email['Subject'] = subject if subject else 'ElastAlert notification'
        recipients = self.notify_email
        if rule and rule.get('notify_email'):
            if isinstance(rule['notify_email'], basestring):
                rule['notify_email'] = [rule['notify_email']]
            recipients = recipients + rule['notify_email']
        recipients = list(set(recipients))
        email['To'] = ', '.join(recipients)
        email['From'] = self.from_addr
        email['Reply-To'] = self.conf.get('email_reply_to', email['To'])

        try:
            smtp = SMTP(self.smtp_host)
            smtp.sendmail(self.from_addr, recipients, email.as_string())
        except (SMTPException, error) as e:
            self.handle_error('Error connecting to SMTP host: %s' % (e), {'email_body': email_body})

    def get_top_counts(self, rule, starttime, endtime, keys, number=None, qk=None):
        """ Counts the number of events for each unique value for each key field.
        Returns a dictionary with top_events_<key> mapped to the top 5 counts for each key. """
        all_counts = {}
        if not number:
            number = rule.get('top_count_number', 5)
        for key in keys:
            index = self.get_index(rule, starttime, endtime)

            hits_terms = self.get_hits_terms(rule, starttime, endtime, index, key, qk, number)
            if hits_terms is None:
                top_events_count = {}
            else:
                buckets = hits_terms.values()[0]

                # get_hits_terms adds to num_hits, but we don't want to count these
                self.num_hits -= len(buckets)
                terms = {}
                for bucket in buckets:
                    terms[bucket['key']] = bucket['doc_count']
                counts = terms.items()
                counts.sort(key=lambda x: x[1], reverse=True)
                top_events_count = dict(counts[:number])

            # Save a dict with the top 5 events by key
            all_counts['top_events_%s' % (key)] = top_events_count

        return all_counts

    def next_alert_time(self, rule, name, timestamp):
        """ Calculate an 'until' time and exponent based on how much past the last 'until' we are. """
        if name in self.silence_cache:
            last_until, exponent = self.silence_cache[name]
        else:
            # If this isn't cached, this is the first alert or writeback_es is down, normal realert
            return timestamp + rule['realert'], 0

        if not rule.get('exponential_realert'):
            return timestamp + rule['realert'], 0
        diff = seconds(timestamp - last_until)
        # Increase exponent if we've alerted recently
        if diff < seconds(rule['realert']) * 2 ** exponent:
            exponent += 1
        else:
            # Continue decreasing exponent the longer it's been since the last alert
            while diff > seconds(rule['realert']) * 2 ** exponent and exponent > 0:
                diff -= seconds(rule['realert']) * 2 ** exponent
                exponent -= 1

        wait = datetime.timedelta(seconds=seconds(rule['realert']) * 2 ** exponent)
        if wait >= rule['exponential_realert']:
            return timestamp + rule['exponential_realert'], exponent - 1
        return timestamp + wait, exponent


def handle_signal(signal, frame):
    elastalert_logger.info('SIGINT received, stopping ElastAlert...')
    # use os._exit to exit immediately and avoid someone catching SystemExit
    os._exit(0)


def main(args=None):
    signal.signal(signal.SIGINT, handle_signal)
    if not args:
        args = sys.argv[1:]
    client = ElastAlerter(args)
    if not client.args.silence:
        client.start()

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
