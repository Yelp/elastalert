#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import copy
import datetime
import json
import logging
import random
import re
import string
import sys

from unittest import mock

from elastalert.config import load_conf
from elastalert.elastalert import ElastAlerter
from elastalert.util import EAException
from elastalert.util import elasticsearch_client
from elastalert.util import lookup_es_key
from elastalert.util import ts_now
from elastalert.util import ts_to_dt

logging.getLogger().setLevel(logging.INFO)
logging.getLogger('elasticsearch').setLevel(logging.WARNING)

"""
Error Codes:
    1: Error connecting to ElasticSearch
    2: Error querying ElasticSearch
    3: Invalid Rule
    4: Missing/invalid timestamp
"""


def print_terms(terms, parent):
    """ Prints a list of flattened dictionary keys """
    for term in terms:
        if type(terms[term]) != dict:
            print('\t' + parent + term)
        else:
            print_terms(terms[term], parent + term + '.')


class MockElastAlerter(object):
    def _parse_args(self, args: list) -> argparse.Namespace:
        """Uses args to run the various components of MockElastAlerter such as loading the file, saving data, loading data"""
        parser = argparse.ArgumentParser(description="Validate a rule configuration")
        parser.add_argument(
            "file", metavar="rule", type=str, help="rule configuration filename"
        )
        parser.add_argument(
            "--schema-only",
            action="store_true",
            help="Show only schema errors; do not run query",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=0,
            action="store",
            help="Query the previous N days with this rule",
        )
        parser.add_argument(
            "--start",
            dest="start",
            help="YYYY-MM-DDTHH:MM:SS Start querying from this timestamp.",
        )
        parser.add_argument(
            "--end",
            dest="end",
            help="YYYY-MM-DDTHH:MM:SS Query to this timestamp. (Default: present) "
            'Use "NOW" to start from current time. (Default: present)',
        )
        parser.add_argument(
            "--stop-error",
            action="store_true",
            help="Stop the entire test right after the first error",
        )
        parser.add_argument(
            "--formatted-output",
            action="store_true",
            help="Output results in formatted JSON",
        )
        parser.add_argument(
            "--data",
            type=str,
            metavar="FILENAME",
            action="store",
            dest="json",
            help="A JSON file containing data to run the rule against",
        )
        parser.add_argument(
            "--alert",
            action="store_true",
            help="Use actual alerts instead of debug output",
        )
        parser.add_argument(
            "--save-json",
            type=str,
            metavar="FILENAME",
            action="store",
            dest="save",
            help="A file to which documents from the last day or --days will be saved",
        )
        parser.add_argument(
            "--use-downloaded",
            action="store_true",
            dest="use_downloaded",
            help="Use the downloaded",
        )
        parser.add_argument(
            "--max-query-size",
            type=int,
            default=10000,
            action="store",
            dest="max_query_size",
            help="Maximum size of any query",
        )
        parser.add_argument(
            "--count-only",
            action="store_true",
            dest="count",
            help="Only display the number of documents matching the filter",
        )
        parser.add_argument(
            "--config",
            action="store",
            dest="config",
            help="Global config file.",
        )
        parsed_args = parser.parse_args(args)

        # Set arguments that ElastAlerter needs
        parsed_args.verbose = parsed_args.alert
        parsed_args.debug = not parsed_args.alert
        parsed_args.es_debug = False
        parsed_args.es_debug_trace = False

        return parsed_args

    def str_to_ts(self, input: str) -> datetime:
        if input == "NOW":
            return self.ts_now

        try:
            return ts_to_dt(input)
        except (TypeError, ValueError):
            raise Exception(
                f"Input is not a valid ISO8601 timestamp (YYYY-MM-DDTHH:MM:SS+XX:00): {input}"
            )

    def parse_starttime(self, timeframe=None) -> datetime:
        if self.args.start:
            try:
                return self.str_to_ts(self.args.start)
            except Exception:
                raise

        if self.args.days > 0:
            return self.endtime - datetime.timedelta(days=self.args.days)

        # Special case executed later after initialisation
        if timeframe is not None:
            return self.endtime - datetime.timedelta(
                seconds=timeframe.total_seconds() * 1.01
            )

        # Default is 1 days / 24 hours
        return self.endtime - datetime.timedelta(days=1)

    def __init__(self, args):
        self.args = self._parse_args(args)
        self.data = []
        self.formatted_output = {}
        self.ts_now = ts_now()
        # We need to store endtime before starttime, please see method `parse_starttime`
        self.endtime = self.str_to_ts(self.args.end) if self.args.end else self.ts_now
        self.starttime = self.parse_starttime()

    def test_file(self, conf):
        """Loads a rule config file, performs a query over the last day (self.args.days), lists available keys
        and prints the number of results."""
        if self.args.schema_only:
            return []

        # Set up Elasticsearch client and query
        es_client = elasticsearch_client(conf)

        try:
            ElastAlerter.modify_rule_for_ES5(conf)
        except EAException as ea:
            print('Invalid filter provided:', str(ea), file=sys.stderr)
            if self.args.stop_error:
                exit(3)
            return None
        except Exception as e:
            print("Error connecting to ElasticSearch:", file=sys.stderr)
            print(repr(e)[:2048], file=sys.stderr)
            if self.args.stop_error:
                exit(1)
            return None
        ts = conf.get('timestamp_field', '@timestamp')
        query = ElastAlerter.get_query(
            conf['filter'],
            starttime=self.starttime,
            endtime=self.endtime,
            timestamp_field=ts,
            to_ts_func=conf['dt_to_ts'],
            five=conf['five']
        )
        index = ElastAlerter.get_index(conf, self.starttime, self.endtime)

        # Get one document for schema
        try:
            res = es_client.search(index=index, size=1, body=query, ignore_unavailable=True)
        except Exception as e:
            print("Error running your filter:", file=sys.stderr)
            print(repr(e)[:2048], file=sys.stderr)
            if self.args.stop_error:
                exit(3)
            return None
        num_hits = len(res['hits']['hits'])
        if not num_hits:
            print("Didn't get any results.")
            return []

        terms = res['hits']['hits'][0]['_source']
        doc_type = res['hits']['hits'][0]['_type']

        # Get a count of all docs
        count_query = ElastAlerter.get_query(
            conf['filter'],
            starttime=self.starttime,
            endtime=self.endtime,
            timestamp_field=ts,
            to_ts_func=conf['dt_to_ts'],
            sort=False,
            five=conf['five']
        )
        try:
            res = es_client.count(index=index, doc_type=doc_type, body=count_query, ignore_unavailable=True)
        except Exception as e:
            print("Error querying Elasticsearch:", file=sys.stderr)
            print(repr(e)[:2048], file=sys.stderr)
            if self.args.stop_error:
                exit(2)
            return None

        num_hits = res['count']

        if self.args.formatted_output:
            self.formatted_output['hits'] = num_hits
            self.formatted_output['days'] = self.args.days
            self.formatted_output['terms'] = list(terms.keys())
            self.formatted_output['result'] = terms
        else:
            print(
                "Got %s hits from the last %s day%s"
                % (num_hits, self.args.days, "s" if self.args.days > 1 else "")
            )
            print("\nAvailable terms in first hit:")
            print_terms(terms, '')

        # Check for missing keys
        pk = conf.get('primary_key')
        ck = conf.get('compare_key')
        if pk and not lookup_es_key(terms, pk):
            print("Warning: primary key %s is either missing or null!", file=sys.stderr)
        if ck and not lookup_es_key(terms, ck):
            print("Warning: compare key %s is either missing or null!", file=sys.stderr)

        include = conf.get('include')
        if include:
            for term in include:
                if not lookup_es_key(terms, term) and '*' not in term:
                    print("Included term %s may be missing or null" % (term), file=sys.stderr)

        for term in conf.get('top_count_keys', []):
            # If the index starts with 'logstash', fields with .raw will be available but won't in _source
            if term not in terms and not (term.endswith('.raw') and term[:-4] in terms and index.startswith('logstash')):
                print("top_count_key %s may be missing" % (term), file=sys.stderr)
        if not self.args.formatted_output:
            print('')  # Newline

        # Download up to max_query_size (defaults to 10,000) documents to save
        if (self.args.save or self.args.formatted_output) and not self.args.count:
            try:
                res = es_client.search(index=index, size=self.args.max_query_size, body=query, ignore_unavailable=True)
            except Exception as e:
                print("Error running your filter:", file=sys.stderr)
                print(repr(e)[:2048], file=sys.stderr)
                if self.args.stop_error:
                    exit(2)
                return None
            num_hits = len(res['hits']['hits'])

            if self.args.save:
                print("Downloaded %s documents to save" % (num_hits))
            return res['hits']['hits']

    def mock_count(self, rule, start, end, index):
        """ Mocks the effects of get_hits_count using global data instead of Elasticsearch """
        count = 0
        for doc in self.data:
            if start <= ts_to_dt(doc[rule['timestamp_field']]) < end:
                count += 1
        return {end: count}

    def mock_hits(self, rule, start, end, index, scroll=False):
        """ Mocks the effects of get_hits using global data instead of Elasticsearch. """
        docs = []
        for doc in self.data:
            if start <= ts_to_dt(doc[rule['timestamp_field']]) < end:
                docs.append(doc)

        # Remove all fields which don't match 'include'
        for doc in docs:
            fields_to_remove = []
            for field in doc:
                if field != '_id':
                    if not any([re.match(incl.replace('*', '.*'), field) for incl in rule['include']]):
                        fields_to_remove.append(field)
            list(map(doc.pop, fields_to_remove))

        # Separate _source and _id, convert timestamps
        resp = [{'_source': doc, '_id': doc['_id']} for doc in docs]
        for doc in resp:
            doc['_source'].pop('_id')
        return ElastAlerter.process_hits(rule, resp)

    def mock_terms(self, rule, start, end, index, key, qk=None, size=None):
        """ Mocks the effects of get_hits_terms using global data instead of Elasticsearch. """
        if key.endswith('.raw'):
            key = key[:-4]
        buckets = {}
        for doc in self.data:
            if key not in doc:
                continue
            if start <= ts_to_dt(doc[rule['timestamp_field']]) < end:
                if qk is None or doc[rule['query_key']] == qk:
                    buckets.setdefault(doc[key], 0)
                    buckets[doc[key]] += 1
        counts = list(buckets.items())
        counts.sort(key=lambda x: x[1], reverse=True)
        if size:
            counts = counts[:size]
        buckets = [{'key': value, 'doc_count': count} for value, count in counts]
        return {end: buckets}

    def mock_elastalert(self, elastalert):
        """ Replaces elastalert's get_hits functions with mocks. """
        elastalert.get_hits_count = self.mock_count
        elastalert.get_hits_terms = self.mock_terms
        elastalert.get_hits = self.mock_hits
        elastalert.elasticsearch_client = mock.Mock()

    def run_elastalert(self, rule, conf):
        """ Creates an ElastAlert instance and run's over for a specific rule using either real or mock data. """

        # Load and instantiate rule
        # Pass an args containing the context of whether we're alerting or not
        # It is needed to prevent unnecessary initialization of unused alerters
        load_modules_args = argparse.Namespace()
        load_modules_args.debug = not self.args.alert
        conf['rules_loader'].load_modules(rule, load_modules_args)

        # If using mock data, make sure it's sorted and find appropriate time range
        timestamp_field = rule.get('timestamp_field', '@timestamp')
        if self.args.json:
            if not self.data:
                return None
            try:
                self.data.sort(key=lambda x: x[timestamp_field])
                self.starttime = self.str_to_ts(self.data[0][timestamp_field])
                self.endtime = self.str_to_ts(self.data[-1][timestamp_field]) + datetime.timedelta(seconds=1)
            except KeyError as e:
                print("All documents must have a timestamp and _id: %s" % (e), file=sys.stderr)
                if self.args.stop_error:
                    exit(4)
                return None

            # Create mock _id for documents if it's missing
            used_ids = []

            def get_id():
                _id = ''.join([random.choice(string.ascii_letters) for i in range(16)])
                if _id in used_ids:
                    return get_id()
                used_ids.append(_id)
                return _id

            for doc in self.data:
                doc.update({'_id': doc.get('_id', get_id())})
        else:
            # Updating starttime based on timeframe rule
            if "timeframe" in rule:
                self.starttime = self.parse_starttime(timeframe=rule["timeframe"])

        # Set run_every to cover the entire time range unless count query, terms query or agg query used
        # This is to prevent query segmenting which unnecessarily slows down tests
        if not rule.get('use_terms_query') and not rule.get('use_count_query') and not rule.get('aggregation_query_element'):
            conf['run_every'] = self.endtime - self.starttime

        # Instantiate ElastAlert to use mock config and special rule
        with mock.patch.object(conf['rules_loader'], 'get_hashes'):
            with mock.patch.object(conf['rules_loader'], 'load') as load_rules:
                load_rules.return_value = [rule]
                with mock.patch('elastalert.elastalert.load_conf') as load_conf:
                    load_conf.return_value = conf
                    if self.args.alert:
                        client = ElastAlerter(['--verbose'])
                    else:
                        client = ElastAlerter(['--debug'])

        # Replace get_hits_* functions to use mock data
        if self.args.json:
            self.mock_elastalert(client)

        # Mock writeback to return empty results
        client.writeback_es = mock.MagicMock()
        client.writeback_es.search.return_value = {"hits": {"hits": []}}

        with mock.patch.object(client, 'writeback') as mock_writeback:
            client.run_rule(rule, self.endtime, self.starttime)

            if mock_writeback.call_count:

                if self.args.formatted_output:
                    self.formatted_output['writeback'] = {}
                else:
                    print("\nWould have written the following documents to writeback index (default is elastalert_status):\n")

                errors = False
                for call in mock_writeback.call_args_list:
                    if self.args.formatted_output:
                        self.formatted_output['writeback'][call[0][0]] = json.loads(json.dumps(call[0][1], default=str))
                    else:
                        print("%s - %s\n" % (call[0][0], call[0][1]))

                    if call[0][0] == 'elastalert_error':
                        errors = True
                if errors and self.args.stop_error:
                    exit(2)

    def run_rule_test(self):
        defaults = {
            'rules_folder': 'rules',
            'es_host': 'localhost',
            'es_port': 14900,
            'writeback_index': 'wb',
            'max_query_size': 10000,
            'alert_time_limit': {'hours': 24},
            'old_query_limit': {'weeks': 1},
            'run_every': {'minutes': 5},
            'disable_rules_on_error': False,
            'buffer_time': {'minutes': 45},
            'scroll_keepalive': '30s'
        }
        overwrites = {
            'rules_loader': 'file',
        }

        conf = load_conf(self.args, defaults, overwrites)
        rule_yaml = conf['rules_loader'].load_yaml(self.args.file)
        conf['rules_loader'].load_options(rule_yaml, conf, self.args.file)

        if self.args.json:
            try:
                with open(self.args.json, "r") as data_file:
                    self.data = json.loads(data_file.read())
            except OSError:
                raise
        else:
            # Temporarily remove the jinja_template, if it exists, to avoid deepcopy issues
            template = rule_yaml.get("jinja_template")
            rule_yaml["jinja_template"] = None

            # Copy the rule object without the template in it
            copied_rule = copy.deepcopy(rule_yaml)

            # Set the template back onto the original rule object and the newly copied object
            rule_yaml["jinja_template"] = template
            copied_rule["jinja_template"] = template

            hits = self.test_file(copied_rule)
            if hits and self.args.formatted_output:
                self.formatted_output['results'] = json.loads(json.dumps(hits))
            if hits and self.args.save:
                try:
                    with open(self.args.save, "wb") as data_file:
                        # Add _id to _source for dump
                        [doc['_source'].update({'_id': doc['_id']}) for doc in hits]
                        data_file.write(str.encode(json.dumps([doc['_source'] for doc in hits], indent=4)))
                except OSError:
                    raise
            if self.args.use_downloaded:
                if hits:
                    self.args.json = self.args.save
                    try:
                        with open(self.args.json, "r") as data_file:
                            self.data = json.loads(data_file.read())
                    except OSError:
                        raise
                else:
                    self.data = []

        if not self.args.schema_only and not self.args.count:
            self.run_elastalert(rule_yaml, conf)

        if self.args.formatted_output:
            print(json.dumps(self.formatted_output))


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    test_instance = MockElastAlerter(args)
    test_instance.run_rule_test()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
