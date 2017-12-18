# -*- coding: utf-8 -*-
import argparse
import copy
import datetime
import json
import logging
import os
import signal
import sys
import time
import timeit
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP
from smtplib import SMTPException
from socket import error

import dateutil.tz
import kibana
import yaml
from alerts import DebugAlerter
from config import get_rule_hashes
from config import load_configuration
from config import load_rules
from croniter import croniter
from elasticsearch.exceptions import ConnectionError
from elasticsearch.exceptions import ElasticsearchException
from elasticsearch.exceptions import TransportError
from enhancements import DropMatchException
from ruletypes import FlatlineRule
from util import add_raw_postfix
from util import cronite_datetime_to_timestamp
from util import dt_to_ts
from util import dt_to_unix
from util import EAException
from util import elastalert_logger
from util import elasticsearch_client
from util import format_index
from util import lookup_es_key
from util import parse_deadline
from util import parse_duration
from util import pretty_ts
from util import replace_dots_in_field_names
from util import seconds
from util import set_es_key
from util import total_seconds
from util import ts_add
from util import ts_now
from util import ts_to_dt
from util import unix_to_dt


class ElastAlerter():
    """ The main ElastAlert runner. This class holds all state about active rules,
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
        parser.add_argument(
            '--config',
            action='store',
            dest='config',
            default="config.yaml",
            help='Global config file (default: config.yaml)')
        parser.add_argument('--debug', action='store_true', dest='debug', help='Suppresses alerts and prints information instead. '
                                                                               'Not compatible with `--verbose`')
        parser.add_argument('--rule', dest='rule', help='Run only a specific rule (by filename, must still be in rules folder)')
        parser.add_argument('--silence', dest='silence', help='Silence rule for a time period. Must be used with --rule. Usage: '
                                                              '--silence <units>=<number>, eg. --silence hours=2')
        parser.add_argument('--start', dest='start', help='YYYY-MM-DDTHH:MM:SS Start querying from this timestamp.'
                                                          'Use "NOW" to start from current time. (Default: present)')
        parser.add_argument('--end', dest='end', help='YYYY-MM-DDTHH:MM:SS Query to this timestamp. (Default: present)')
        parser.add_argument('--verbose', action='store_true', dest='verbose', help='Increase verbosity without suppressing alerts. '
                                                                                   'Not compatible with `--debug`')
        parser.add_argument('--patience', action='store', dest='timeout',
                            type=parse_duration,
                            default=datetime.timedelta(),
                            help='Maximum time to wait for ElasticSearch to become responsive.  Usage: '
                            '--patience <units>=<number>. e.g. --patience minutes=5')
        parser.add_argument(
            '--pin_rules',
            action='store_true',
            dest='pin_rules',
            help='Stop ElastAlert from monitoring config file changes')
        parser.add_argument('--es_debug', action='store_true', dest='es_debug', help='Enable verbose logging from Elasticsearch queries')
        parser.add_argument(
            '--es_debug_trace',
            action='store',
            dest='es_debug_trace',
            help='Enable logging from Elasticsearch queries as curl command. Queries will be logged to file. Note that '
                 'this will incorrectly display localhost:9200 as the host/port')
        self.args = parser.parse_args(args)

    def __init__(self, args):
        self.parse_args(args)
        self.debug = self.args.debug
        self.verbose = self.args.verbose

        if self.verbose and self.debug:
            elastalert_logger.info(
                "Note: --debug and --verbose flags are set. --debug takes precedent."
            )

        if self.verbose or self.debug:
            elastalert_logger.setLevel(logging.INFO)

        if self.debug:
            elastalert_logger.info(
                """Note: In debug mode, alerts will be logged to console but NOT actually sent.
                To send them but remain verbose, use --verbose instead."""
            )

        if not self.args.es_debug:
            logging.getLogger('elasticsearch').setLevel(logging.WARNING)

        if self.args.es_debug_trace:
            tracer = logging.getLogger('elasticsearch.trace')
            tracer.setLevel(logging.INFO)
            tracer.addHandler(logging.FileHandler(self.args.es_debug_trace))

        self.conf = load_rules(self.args)
        self.max_query_size = self.conf['max_query_size']
        self.scroll_keepalive = self.conf['scroll_keepalive']
        self.rules = self.conf['rules']
        self.writeback_index = self.conf['writeback_index']
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
        self.num_dupes = 0
        self.current_es = None
        self.current_es_addr = None
        self.buffer_time = self.conf['buffer_time']
        self.silence_cache = {}
        self.rule_hashes = get_rule_hashes(self.conf, self.args.rule)
        self.starttime = self.args.start
        self.disabled_rules = []
        self.replace_dots_in_field_names = self.conf.get('replace_dots_in_field_names', False)
        self.string_multi_field_name = self.conf.get('string_multi_field_name', False)

        self.writeback_es = elasticsearch_client(self.conf)
        self._es_version = None

        remove = []
        for rule in self.rules:
            if not self.init_rule(rule):
                remove.append(rule)
        map(self.rules.remove, remove)

        if self.args.silence:
            self.silence()

    def get_version(self):
        info = self.writeback_es.info()
        return info['version']['number']

    @property
    def es_version(self):
        if self._es_version is None:
            self._es_version = self.get_version()
        return self._es_version

    def is_five(self):
        return self.es_version.startswith('5')

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
    def get_query(filters, starttime=None, endtime=None, sort=True, timestamp_field='@timestamp', to_ts_func=dt_to_ts, desc=False,
                  five=False):
        """ Returns a query dict that will apply a list of filters, filter by
        start and end time, and sort results by timestamp.

        :param filters: A list of Elasticsearch filters to use.
        :param starttime: A timestamp to use as the start time of the query.
        :param endtime: A timestamp to use as the end time of the query.
        :param sort: If true, sort results by timestamp. (Default True)
        :return: A query dictionary to pass to Elasticsearch.
        """
        starttime = to_ts_func(starttime)
        endtime = to_ts_func(endtime)
        filters = copy.copy(filters)
        must_filters = [x for x in filters if 'must_not' not in x]
        must_not_filters = [x['must_not'] for x in filters if 'must_not' in x]
        es_filters = {'filter': {'bool': {'must': must_filters, 'must_not': must_not_filters}}}
        if starttime and endtime:
            es_filters['filter']['bool']['must'].insert(0, {'range': {timestamp_field: {'gt': starttime,
                                                                                        'lte': endtime}}})
        if five:
            query = {'query': {'bool': es_filters}}
        else:
            query = {'query': {'filtered': es_filters}}
        if sort:
            query['sort'] = [{timestamp_field: {'order': 'desc' if desc else 'asc'}}]
        return query

    def get_terms_query(self, query, size, field, five=False):
        """ Takes a query generated by get_query and outputs a aggregation query """
        query_element = query['query']
        if 'sort' in query_element:
            query_element.pop('sort')
        if not five:
            query_element['filtered'].update({'aggs': {'counts': {'terms': {'field': field, 'size': size}}}})
            aggs_query = {'aggs': query_element}
        else:
            aggs_query = query
            aggs_query['aggs'] = {'counts': {'terms': {'field': field, 'size': size}}}
        return aggs_query

    def get_aggregation_query(self, query, rule, query_key, terms_size, timestamp_field='@timestamp'):
        """ Takes a query generated by get_query and outputs a aggregation query """
        query_element = query['query']
        if 'sort' in query_element:
            query_element.pop('sort')
        metric_agg_element = rule['aggregation_query_element']

        bucket_interval_period = rule.get('bucket_interval_period')
        if bucket_interval_period is not None:
            aggs_element = {
                'interval_aggs': {
                    'date_histogram': {
                        'field': timestamp_field,
                        'interval': bucket_interval_period},
                    'aggs': metric_agg_element
                }
            }
            if rule.get('bucket_offset_delta'):
                aggs_element['interval_aggs']['date_histogram']['offset'] = '+%ss' % (rule['bucket_offset_delta'])
        else:
            aggs_element = metric_agg_element

        if query_key is not None:
            for idx, key in reversed(list(enumerate(query_key.split(',')))):
                aggs_element = {'bucket_aggs': {'terms': {'field': key, 'size': terms_size}, 'aggs': aggs_element}}

        if not rule['five']:
            query_element['filtered'].update({'aggs': aggs_element})
            aggs_query = {'aggs': query_element}
        else:
            aggs_query = query
            aggs_query['aggs'] = aggs_element
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
            self.handle_error("Elasticsearch query error: %s" % (e), {'index': index, 'query': query})
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
            if not ts and not rule["_source_enabled"]:
                raise EAException(
                    "Error: No timestamp was found for hit. '_source_enabled' is set to false, check your mappings for stored fields"
                )

            set_es_key(hit['_source'], rule['timestamp_field'], rule['ts_to_dt'](ts))
            set_es_key(hit, rule['timestamp_field'], lookup_es_key(hit['_source'], rule['timestamp_field']))

            # Tack metadata fields into _source
            for field in ['_id', '_index', '_type']:
                if field in hit:
                    hit['_source'][field] = hit[field]

            if rule.get('compound_query_key'):
                values = [lookup_es_key(hit['_source'], key) for key in rule['compound_query_key']]
                hit['_source'][rule['query_key']] = ', '.join([unicode(value) for value in values])

            if rule.get('compound_aggregation_key'):
                values = [lookup_es_key(hit['_source'], key) for key in rule['compound_aggregation_key']]
                hit['_source'][rule['aggregation_key']] = ', '.join([unicode(value) for value in values])

            processed_hits.append(hit['_source'])

        return processed_hits

    def get_hits(self, rule, starttime, endtime, index, scroll=False):
        """ Query Elasticsearch for the given rule and return the results.

        :param rule: The rule configuration.
        :param starttime: The earliest time to query.
        :param endtime: The latest time to query.
        :return: A list of hits, bounded by rule['max_query_size'] (or self.max_query_size).
        """
        query = self.get_query(
            rule['filter'],
            starttime,
            endtime,
            timestamp_field=rule['timestamp_field'],
            to_ts_func=rule['dt_to_ts'],
            five=rule['five'],
        )
        extra_args = {'_source_include': rule['include']}
        scroll_keepalive = rule.get('scroll_keepalive', self.scroll_keepalive)
        if not rule.get('_source_enabled'):
            if rule['five']:
                query['stored_fields'] = rule['include']
            else:
                query['fields'] = rule['include']
            extra_args = {}

        try:
            if scroll:
                res = self.current_es.scroll(scroll_id=rule['scroll_id'], scroll=scroll_keepalive)
            else:
                res = self.current_es.search(
                    scroll=scroll_keepalive,
                    index=index,
                    size=rule.get('max_query_size', self.max_query_size),
                    body=query,
                    ignore_unavailable=True,
                    **extra_args
                )
                self.total_hits = int(res['hits']['total'])
            logging.debug(str(res))
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running query: %s' % (e), {'rule': rule['name'], 'query': query})
            return None

        hits = res['hits']['hits']
        self.num_hits += len(hits)
        lt = rule.get('use_local_time')
        status_log = "Queried rule %s from %s to %s: %s / %s hits" % (
            rule['name'],
            pretty_ts(starttime, lt),
            pretty_ts(endtime, lt),
            self.num_hits,
            len(hits)
        )
        if self.total_hits > rule.get('max_query_size', self.max_query_size):
            elastalert_logger.info("%s (scrolling..)" % status_log)
            rule['scroll_id'] = res['_scroll_id']
        else:
            elastalert_logger.info(status_log)

        hits = self.process_hits(rule, hits)

        # Record doc_type for use in get_top_counts
        if 'doc_type' not in rule and len(hits):
            rule['doc_type'] = hits[0]['_type']
        return hits

    def get_hits_count(self, rule, starttime, endtime, index):
        """ Query Elasticsearch for the count of results and returns a list of timestamps
        equal to the endtime. This allows the results to be passed to rules which expect
        an object for each hit.

        :param rule: The rule configuration dictionary.
        :param starttime: The earliest time to query.
        :param endtime: The latest time to query.
        :return: A dictionary mapping timestamps to number of hits for that time period.
        """
        query = self.get_query(
            rule['filter'],
            starttime,
            endtime,
            timestamp_field=rule['timestamp_field'],
            sort=False,
            to_ts_func=rule['dt_to_ts'],
            five=rule['five']
        )

        try:
            res = self.current_es.count(index=index, doc_type=rule['doc_type'], body=query, ignore_unavailable=True)
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running count query: %s' % (e), {'rule': rule['name'], 'query': query})
            return None

        self.num_hits += res['count']
        lt = rule.get('use_local_time')
        elastalert_logger.info(
            "Queried rule %s from %s to %s: %s hits" % (rule['name'], pretty_ts(starttime, lt), pretty_ts(endtime, lt), res['count'])
        )
        return {endtime: res['count']}

    def get_hits_terms(self, rule, starttime, endtime, index, key, qk=None, size=None):
        rule_filter = copy.copy(rule['filter'])
        if qk:
            filter_key = rule['query_key']
            if rule['five']:
                end = '.keyword'
            else:
                end = '.raw'
            if rule.get('raw_count_keys', True) and not rule['query_key'].endswith(end):
                filter_key = add_raw_postfix(filter_key, rule['five'])
            rule_filter.extend([{'term': {filter_key: qk}}])
        base_query = self.get_query(
            rule_filter,
            starttime,
            endtime,
            timestamp_field=rule['timestamp_field'],
            sort=False,
            to_ts_func=rule['dt_to_ts'],
            five=rule['five']
        )
        if size is None:
            size = rule.get('terms_size', 50)
        query = self.get_terms_query(base_query, size, key, rule['five'])

        try:
            if not rule['five']:
                res = self.current_es.search(
                    index=index,
                    doc_type=rule['doc_type'],
                    body=query,
                    search_type='count',
                    ignore_unavailable=True
                )
            else:
                res = self.current_es.search(index=index, doc_type=rule['doc_type'], body=query, size=0, ignore_unavailable=True)
        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running terms query: %s' % (e), {'rule': rule['name'], 'query': query})
            return None

        if 'aggregations' not in res:
            return {}
        if not rule['five']:
            buckets = res['aggregations']['filtered']['counts']['buckets']
        else:
            buckets = res['aggregations']['counts']['buckets']
        self.num_hits += len(buckets)
        lt = rule.get('use_local_time')
        elastalert_logger.info(
            'Queried rule %s from %s to %s: %s buckets' % (rule['name'], pretty_ts(starttime, lt), pretty_ts(endtime, lt), len(buckets))
        )
        return {endtime: buckets}

    def get_hits_aggregation(self, rule, starttime, endtime, index, query_key, term_size=None):
        rule_filter = copy.copy(rule['filter'])
        base_query = self.get_query(
            rule_filter,
            starttime,
            endtime,
            timestamp_field=rule['timestamp_field'],
            sort=False,
            to_ts_func=rule['dt_to_ts'],
            five=rule['five']
        )
        if term_size is None:
            term_size = rule.get('terms_size', 50)
        query = self.get_aggregation_query(base_query, rule, query_key, term_size, rule['timestamp_field'])
        try:
            if not rule['five']:
                res = self.current_es.search(
                    index=index,
                    doc_type=rule.get('doc_type'),
                    body=query,
                    search_type='count',
                    ignore_unavailable=True
                )
            else:
                res = self.current_es.search(index=index, doc_type=rule.get('doc_type'), body=query, size=0, ignore_unavailable=True)
        except ElasticsearchException as e:
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)
            self.handle_error('Error running query: %s' % (e), {'rule': rule['name']})
            return None
        if 'aggregations' not in res:
            return {}
        if not rule['five']:
            payload = res['aggregations']['filtered']
        else:
            payload = res['aggregations']
        self.num_hits += res['hits']['total']
        return {endtime: payload}

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
        if rule.get('query_delay'):
            buffer_time += rule['query_delay']
        for _id, timestamp in rule['processed_hits'].iteritems():
            if now - timestamp > buffer_time:
                remove.append(_id)
        map(rule['processed_hits'].pop, remove)

    def run_query(self, rule, start=None, end=None, scroll=False):
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
        index = self.get_index(rule, start, end)
        if rule.get('use_count_query'):
            data = self.get_hits_count(rule, start, end, index)
        elif rule.get('use_terms_query'):
            data = self.get_hits_terms(rule, start, end, index, rule['query_key'])
        elif rule.get('aggregation_query_element'):
            data = self.get_hits_aggregation(rule, start, end, index, rule.get('query_key', None))
        else:
            data = self.get_hits(rule, start, end, index, scroll)
            if data:
                old_len = len(data)
                data = self.remove_duplicate_events(data, rule)
                self.num_dupes += old_len - len(data)

        # There was an exception while querying
        if data is None:
            return False
        elif data:
            if rule.get('use_count_query'):
                rule_inst.add_count_data(data)
            elif rule.get('use_terms_query'):
                rule_inst.add_terms_data(data)
            elif rule.get('aggregation_query_element'):
                rule_inst.add_aggregation_data(data)
            else:
                rule_inst.add_data(data)

        try:
            if rule.get('scroll_id') and self.num_hits < self.total_hits:
                self.run_query(rule, start, end, scroll=True)
        except RuntimeError:
            # It's possible to scroll far enough to hit max recursive depth
            pass

        if 'scroll_id' in rule:
            rule.pop('scroll_id')

        return True

    def get_starttime(self, rule):
        """ Query ES for the last time we ran this rule.

        :param rule: The rule configuration.
        :return: A timestamp or None.
        """
        sort = {'sort': {'@timestamp': {'order': 'desc'}}}
        query = {'filter': {'term': {'rule_name': '%s' % (rule['name'])}}}
        if self.is_five():
            query = {'query': {'bool': query}}
        query.update(sort)

        try:
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

    def set_starttime(self, rule, endtime):
        """ Given a rule and an endtime, sets the appropriate starttime for it. """

        # This means we are starting fresh
        if 'starttime' not in rule:
            # Try to get the last run from Elasticsearch
            last_run_end = self.get_starttime(rule)
            if last_run_end:
                rule['starttime'] = last_run_end
                self.adjust_start_time_for_overlapping_agg_query(rule)
                self.adjust_start_time_for_interval_sync(rule, endtime)
                rule['minimum_starttime'] = rule['starttime']
                return None

        # Use buffer for normal queries, or run_every increments otherwise

        if not rule.get('use_count_query') and not rule.get('use_terms_query'):
            buffer_time = rule.get('buffer_time', self.buffer_time)
            buffer_delta = endtime - buffer_time
            # If we started using a previous run, don't go past that
            if 'minimum_starttime' in rule and rule['minimum_starttime'] > buffer_delta:
                rule['starttime'] = rule['minimum_starttime']
            # If buffer_time doesn't bring us past the previous endtime, use that instead
            elif 'previous_endtime' in rule:
                if rule['previous_endtime'] < buffer_delta:
                    rule['starttime'] = rule['previous_endtime']
                self.adjust_start_time_for_overlapping_agg_query(rule)
            else:
                rule['starttime'] = buffer_delta

            self.adjust_start_time_for_interval_sync(rule, endtime)

        else:
            # Query from the end of the last run, if it exists, otherwise a run_every sized window
            rule['starttime'] = rule.get('previous_endtime', endtime - self.run_every)

    def adjust_start_time_for_overlapping_agg_query(self, rule):
        if rule.get('aggregation_query_element'):
            if rule.get('allow_buffer_time_overlap') and not rule.get('use_run_every_query_size') and (
                    rule['buffer_time'] > rule['run_every']):
                rule['starttime'] = rule['starttime'] - (rule['buffer_time'] - rule['run_every'])
                rule['original_starttime'] = rule['starttime']

    def adjust_start_time_for_interval_sync(self, rule, endtime):
        # If aggregation query adjust bucket offset
        if rule.get('aggregation_query_element'):

            if rule.get('bucket_interval'):
                es_interval_delta = rule.get('bucket_interval_timedelta')
                unix_starttime = dt_to_unix(rule['starttime'])
                es_interval_delta_in_sec = total_seconds(es_interval_delta)
                offset = int(unix_starttime % es_interval_delta_in_sec)

                if rule.get('sync_bucket_interval'):
                    rule['starttime'] = unix_to_dt(unix_starttime - offset)
                    endtime = unix_to_dt(dt_to_unix(endtime) - offset)
                else:
                    rule['bucket_offset_delta'] = offset

    def get_segment_size(self, rule):
        """ The segment size is either buffer_size for queries which can overlap or run_every for queries
        which must be strictly separate. This mimicks the query size for when ElastAlert is running continuously. """
        if not rule.get('use_count_query') and not rule.get('use_terms_query') and not rule.get('aggregation_query_element'):
            return rule.get('buffer_time', self.buffer_time)
        elif rule.get('aggregation_query_element'):
            if rule.get('use_run_every_query_size'):
                return self.run_every
            else:
                return rule.get('buffer_time', self.buffer_time)
        else:
            return self.run_every

    def get_query_key_value(self, rule, match):
        # get the value for the match's query_key (or none) to form the key used for the silence_cache.
        # Flatline ruletype sets "key" instead of the actual query_key
        if isinstance(rule['type'], FlatlineRule) and 'key' in match:
            return unicode(match['key'])
        return self.get_named_key_value(rule, match, 'query_key')

    def get_aggregation_key_value(self, rule, match):
        # get the value for the match's aggregation_key (or none) to form the key used for grouped aggregates.
        return self.get_named_key_value(rule, match, 'aggregation_key')

    def get_named_key_value(self, rule, match, key_name):
        # search the match for the key specified in the rule to get the value
        if key_name in rule:
            try:
                key_value = lookup_es_key(match, rule[key_name])
                if key_value is not None:
                    # Only do the unicode conversion if we actually found something)
                    # otherwise we might transform None --> 'None'
                    key_value = unicode(key_value)
            except KeyError:
                # Some matches may not have the specified key
                # use a special token for these
                key_value = '_missing'
        else:
            key_value = None

        return key_value

    def run_rule(self, rule, endtime, starttime=None):
        """ Run a rule for a given time period, including querying and alerting on results.

        :param rule: The rule configuration.
        :param starttime: The earliest timestamp to query.
        :param endtime: The latest timestamp to query.
        :return: The number of matches that the rule produced.
        """
        run_start = time.time()

        self.current_es = elasticsearch_client(rule)
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
        self.num_dupes = 0
        segment_size = self.get_segment_size(rule)

        tmp_endtime = rule['starttime']

        while endtime - rule['starttime'] > segment_size:
            tmp_endtime = tmp_endtime + segment_size
            if not self.run_query(rule, rule['starttime'], tmp_endtime):
                return 0
            rule['starttime'] = tmp_endtime
            rule['type'].garbage_collect(tmp_endtime)

        if rule.get('aggregation_query_element'):
            if endtime - tmp_endtime == segment_size:
                self.run_query(rule, tmp_endtime, endtime)
            elif total_seconds(rule['original_starttime'] - tmp_endtime) == 0:
                rule['starttime'] = rule['original_starttime']
                return 0
            else:
                endtime = tmp_endtime
        else:
            if not self.run_query(rule, rule['starttime'], endtime):
                return 0
            rule['type'].garbage_collect(endtime)

        # Process any new matches
        num_matches = len(rule['type'].matches)
        while rule['type'].matches:
            match = rule['type'].matches.pop(0)
            match['num_hits'] = self.num_hits
            match['num_matches'] = num_matches

            # If realert is set, silence the rule for that duration
            # Silence is cached by query_key, if it exists
            # Default realert time is 0 seconds
            silence_cache_key = rule['name']
            query_key_value = self.get_query_key_value(rule, match)
            if query_key_value is not None:
                silence_cache_key += '.' + query_key_value

            if self.is_silenced(rule['name'] + "._silence") or self.is_silenced(silence_cache_key):
                elastalert_logger.info('Ignoring match for silenced rule %s' % (silence_cache_key,))
                continue

            if rule['realert']:
                next_alert, exponent = self.next_alert_time(rule, silence_cache_key, ts_now())
                self.set_realert(silence_cache_key, next_alert, exponent)

            if rule.get('run_enhancements_first'):
                try:
                    for enhancement in rule['match_enhancements']:
                        try:
                            enhancement.process(match)
                        except EAException as e:
                            self.handle_error("Error running match enhancement: %s" % (e), {'rule': rule['name']})
                except DropMatchException:
                    continue

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

    def init_rule(self, new_rule, new=True):
        ''' Copies some necessary non-config state from an exiting rule to a new rule. '''
        try:
            self.modify_rule_for_ES5(new_rule)
        except TransportError as e:
            elastalert_logger.warning('Error connecting to Elasticsearch for rule {}. '
                                      'The rule has been disabled.'.format(new_rule['name']))
            self.send_notification_email(exception=e, rule=new_rule)
            return False

        # Change top_count_keys to .raw
        if 'top_count_keys' in new_rule and new_rule.get('raw_count_keys', True):
            if self.string_multi_field_name:
                string_multi_field_name = self.string_multi_field_name
            elif self.is_five():
                string_multi_field_name = '.keyword'
            else:
                string_multi_field_name = '.raw'

            for i, key in enumerate(new_rule['top_count_keys']):
                if not key.endswith(string_multi_field_name):
                    new_rule['top_count_keys'][i] += string_multi_field_name

        if 'download_dashboard' in new_rule['filter']:
            # Download filters from Kibana and set the rules filters to them
            db_filters = self.filters_from_kibana(new_rule, new_rule['filter']['download_dashboard'])
            if db_filters is not None:
                new_rule['filter'] = db_filters
            else:
                raise EAException("Could not download filters from %s" % (new_rule['filter']['download_dashboard']))

        blank_rule = {'agg_matches': [],
                      'aggregate_alert_time': {},
                      'current_aggregate_id': {},
                      'processed_hits': {}}
        rule = blank_rule

        # Set rule to either a blank template or existing rule with same name
        if not new:
            for rule in self.rules:
                if rule['name'] == new_rule['name']:
                    break
            else:
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

    @staticmethod
    def modify_rule_for_ES5(new_rule):
        # Get ES version per rule
        rule_es = elasticsearch_client(new_rule)
        if rule_es.info()['version']['number'].startswith('5'):
            new_rule['five'] = True
        else:
            new_rule['five'] = False
            return

        # In ES5, filters starting with 'query' should have the top wrapper removed
        new_filters = []
        for es_filter in new_rule.get('filter', []):
            if es_filter.get('query'):
                new_filters.append(es_filter['query'])
            else:
                new_filters.append(es_filter)
        new_rule['filter'] = new_filters

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
                    if 'is_enabled' in new_rule and not new_rule['is_enabled']:
                        continue
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
                new_rule = self.init_rule(new_rule, False)
                self.rules = [rule for rule in self.rules if rule['rule_file'] != rule_file]
                if new_rule:
                    self.rules.append(new_rule)

        # Load new rules
        if not self.args.rule:
            for rule_file in set(new_rule_hashes.keys()) - set(self.rule_hashes.keys()):
                try:
                    new_rule = load_configuration(rule_file, self.conf)
                    if 'is_enabled' in new_rule and not new_rule['is_enabled']:
                        continue
                    if new_rule['name'] in [rule['name'] for rule in self.rules]:
                        raise EAException("A rule with the name %s already exists" % (new_rule['name']))
                except EAException as e:
                    self.handle_error('Could not load rule %s: %s' % (rule_file, e))
                    self.send_notification_email(exception=e, rule_file=rule_file)
                    continue
                if self.init_rule(new_rule):
                    elastalert_logger.info('Loaded new rule %s' % (rule_file))
                    self.rules.append(new_rule)

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
        self.wait_until_responsive(timeout=self.args.timeout)
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
            sleep_duration = total_seconds(next_run - datetime.datetime.utcnow())
            self.sleep_for(sleep_duration)

    def wait_until_responsive(self, timeout, clock=timeit.default_timer):
        """Wait until ElasticSearch becomes responsive (or too much time passes)."""

        # Elapsed time is a floating point number of seconds.
        timeout = timeout.total_seconds()

        # Don't poll unless we're asked to.
        if timeout <= 0.0:
            return

        # Periodically poll ElasticSearch.  Keep going until ElasticSearch is
        # responsive *and* the writeback index exists.
        ref = clock()
        while (clock() - ref) < timeout:
            try:
                if self.writeback_es.indices.exists(self.writeback_index):
                    return
            except ConnectionError:
                pass
            time.sleep(1.0)

        if self.writeback_es.ping():
            logging.error(
                'Writeback index "%s" does not exist, did you run `elastalert-create-index`?',
                self.writeback_index,
            )
        else:
            logging.error(
                'Could not reach ElasticSearch at "%s:%d".',
                self.conf['es_host'],
                self.conf['es_port'],
            )
        exit(1)

    def run_all_rules(self):
        """ Run each rule one time """
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
                elastalert_logger.info("Ran %s from %s to %s: %s query hits (%s already seen), %s matches,"
                                       " %s alerts sent" % (rule['name'], old_starttime, pretty_ts(endtime, rule.get('use_local_time')),
                                                            self.num_hits, self.num_dupes, num_matches, self.alerts_sent))
                self.alerts_sent = 0

                if next_run < datetime.datetime.utcnow():
                    # We were processing for longer than our refresh interval
                    # This can happen if --start was specified with a large time period
                    # or if we are running too slow to process events in real time.
                    logging.warning(
                        "Querying from %s to %s took longer than %s!" % (
                            old_starttime,
                            pretty_ts(endtime, rule.get('use_local_time')),
                            self.run_every
                        )
                    )

            self.remove_old_events(rule)

        # Only force starttime once
        self.starttime = None

        if not self.args.pin_rules:
            self.load_rule_changes()

    def stop(self):
        """ Stop an ElastAlert runner that's been started """
        self.running = False

    def sleep_for(self, duration):
        """ Sleep for a set duration """
        elastalert_logger.info("Sleeping for %s seconds" % (duration))
        time.sleep(duration)

    def generate_kibana4_db(self, rule, match):
        ''' Creates a link for a kibana4 dashboard which has time set to the match. '''
        db_name = rule.get('use_kibana4_dashboard')
        start = ts_add(
            lookup_es_key(match, rule['timestamp_field']),
            -rule.get('kibana4_start_timedelta', rule.get('timeframe', datetime.timedelta(minutes=10)))
        )
        end = ts_add(
            lookup_es_key(match, rule['timestamp_field']),
            rule.get('kibana4_end_timedelta', rule.get('timeframe', datetime.timedelta(minutes=10)))
        )
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
        ''' Uploads a dashboard schema to the kibana-int Elasticsearch index associated with rule.
        Returns the url to the dashboard. '''
        # Set time range
        start = ts_add(lookup_es_key(match, rule['timestamp_field']), -rule.get('timeframe', datetime.timedelta(minutes=10)))
        end = ts_add(lookup_es_key(match, rule['timestamp_field']), datetime.timedelta(minutes=10))
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

        # Add filter for aggregation_key value
        if 'aggregation_key' in rule:
            for qk in rule.get('compound_aggregation_key', [rule['aggregation_key']]):
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
        es = elasticsearch_client(rule)

        res = es.index(index='kibana-int',
                       doc_type='temp',
                       body=db_body)

        # Return dashboard URL
        kibana_url = rule.get('kibana_url')
        if not kibana_url:
            kibana_url = 'http://%s:%s/_plugin/kibana/' % (rule['es_host'],
                                                           rule['es_port'])
        return kibana_url + '#/dashboard/temp/%s' % (res['_id'])

    def get_dashboard(self, rule, db_name):
        """ Download dashboard which matches use_kibana_dashboard from Elasticsearch. """
        es = elasticsearch_client(rule)
        if not db_name:
            raise EAException("use_kibana_dashboard undefined")
        query = {'query': {'term': {'_id': db_name}}}
        try:
            res = es.search(index='kibana-int', doc_type='dashboard', body=query, _source_include=['dashboard'])
        except ElasticsearchException as e:
            raise EAException("Error querying for dashboard: %s" % (e)), None, sys.exc_info()[2]

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
        """ Downloads a dashboard from Kibana and returns corresponding filters, None on error. """
        try:
            db = rule.get('dashboard_schema')
            if not db:
                db = self.get_dashboard(rule, db_name)
            filters = kibana.filters_from_dashboard(db)
        except EAException:
            return None
        return filters

    def alert(self, matches, rule, alert_time=None, retried=False):
        """ Wraps alerting, Kibana linking and enhancements in an exception handler """
        try:
            return self.send_alert(matches, rule, alert_time=alert_time, retried=retried)
        except Exception as e:
            self.handle_uncaught_exception(e, rule)

    def send_alert(self, matches, rule, alert_time=None, retried=False):
        """ Send out an alert.

        :param matches: A list of matches.
        :param rule: A rule configuration.
        """
        if not matches:
            return

        if alert_time is None:
            alert_time = ts_now()

        # Compute top count keys
        if rule.get('top_count_keys'):
            for match in matches:
                if 'query_key' in rule and rule['query_key'] in match:
                    qk = match[rule['query_key']]
                else:
                    qk = None

                if isinstance(rule['type'], FlatlineRule):
                    # flatline rule triggers when there have been no events from now()-timeframe to now(),
                    # so using now()-timeframe will return no results. for now we can just mutliple the timeframe
                    # by 2, but this could probably be timeframe+run_every to prevent too large of a lookup?
                    timeframe = datetime.timedelta(seconds=2 * rule.get('timeframe').total_seconds())
                else:
                    timeframe = rule.get('timeframe', datetime.timedelta(minutes=10))

                start = ts_to_dt(lookup_es_key(match, rule['timestamp_field'])) - timeframe
                end = ts_to_dt(lookup_es_key(match, rule['timestamp_field'])) + datetime.timedelta(minutes=10)
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
                self.handle_error("Could not generate Kibana dash for %s match: %s" % (rule['name'], e))
            else:
                if kb_link:
                    matches[0]['kibana_link'] = kb_link

        if rule.get('use_kibana4_dashboard'):
            kb_link = self.generate_kibana4_db(rule, matches[0])
            if kb_link:
                matches[0]['kibana_link'] = kb_link

        # Enhancements were already run at match time if
        # run_enhancements_first is set or
        # retried==True, which means this is a retry of a failed alert
        if not rule.get('run_enhancements_first') and not retried:
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
        body = {
            'match_body': match,
            'rule_name': rule['name'],
            'alert_info': rule['alert'][0].get_info(),
            'alert_sent': alert_sent,
            'alert_time': alert_time
        }

        match_time = lookup_es_key(match, rule['timestamp_field'])
        if match_time is not None:
            body['match_time'] = match_time

        # TODO record info about multiple alerts

        # If the alert failed to send, record the exception
        if not alert_sent:
            body['alert_exception'] = alert_exception
        return body

    def writeback(self, doc_type, body):
        # ES 2.0 - 2.3 does not support dots in field names.
        if self.replace_dots_in_field_names:
            writeback_body = replace_dots_in_field_names(body)
        else:
            writeback_body = body

        for key in writeback_body.keys():
            # Convert any datetime objects to timestamps
            if isinstance(writeback_body[key], datetime.datetime):
                writeback_body[key] = dt_to_ts(writeback_body[key])

        if self.debug:
            elastalert_logger.info("Skipping writing to ES: %s" % (writeback_body))
            return None

        if '@timestamp' not in writeback_body:
            writeback_body['@timestamp'] = dt_to_ts(ts_now())

        try:
            res = self.writeback_es.index(index=self.writeback_index,
                                          doc_type=doc_type, body=body)
            return res
        except ElasticsearchException as e:
            logging.exception("Error writing alert info to Elasticsearch: %s" % (e))

    def find_recent_pending_alerts(self, time_limit):
        """ Queries writeback_es to find alerts that did not send
        and are newer than time_limit """

        # XXX only fetches 1000 results. If limit is reached, next loop will catch them
        # unless there is constantly more than 1000 alerts to send.

        # Fetch recent, unsent alerts that aren't part of an aggregate, earlier alerts first.
        inner_query = {'query_string': {'query': '!_exists_:aggregate_id AND alert_sent:false'}}
        time_filter = {'range': {'alert_time': {'from': dt_to_ts(ts_now() - time_limit),
                                                'to': dt_to_ts(ts_now())}}}
        sort = {'sort': {'alert_time': {'order': 'asc'}}}
        if self.is_five():
            query = {'query': {'bool': {'must': inner_query, 'filter': time_filter}}}
        else:
            query = {'query': inner_query, 'filter': time_filter}
        query.update(sort)
        try:
            res = self.writeback_es.search(index=self.writeback_index,
                                           doc_type='elastalert',
                                           body=query,
                                           size=1000)
            if res['hits']['hits']:
                return res['hits']['hits']
        except ElasticsearchException as e:
            logging.exception("Error finding recent pending alerts: %s %s" % (e, query))
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
            self.current_es = elasticsearch_client(rule)
            self.current_es_addr = (rule['es_host'], rule['es_port'])

            # Send the alert unless it's a future alert
            if ts_now() > ts_to_dt(alert_time):
                aggregated_matches = self.get_aggregated_matches(_id)
                if aggregated_matches:
                    matches = [match_body] + [agg_match['match_body'] for agg_match in aggregated_matches]
                    self.alert(matches, rule, alert_time=alert_time)
                else:
                    # If this rule isn't using aggregation, this must be a retry of a failed alert
                    retried = False
                    if not rule.get('aggregation'):
                        retried = True
                    self.alert([match_body], rule, alert_time=alert_time, retried=retried)

                if rule['current_aggregate_id']:
                    for qk, agg_id in rule['current_aggregate_id'].iteritems():
                        if agg_id == _id:
                            rule['current_aggregate_id'].pop(qk)
                            break

                # Delete it from the index
                try:
                    self.writeback_es.delete(index=self.writeback_index,
                                             doc_type='elastalert',
                                             id=_id)
                except ElasticsearchException:  # TODO: Give this a more relevant exception, try:except: is evil.
                    self.handle_error("Failed to delete alert %s at %s" % (_id, alert_time))

        # Send in memory aggregated alerts
        for rule in self.rules:
            if rule['agg_matches']:
                for aggregation_key_value, aggregate_alert_time in rule['aggregate_alert_time'].iteritems():
                    if ts_now() > aggregate_alert_time:
                        alertable_matches = [
                            agg_match
