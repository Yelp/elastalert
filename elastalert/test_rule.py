#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import datetime

import argparse
import yaml

from elastalert.config import load_options
from elastalert.elastalert import ElastAlerter
from elastalert.elastalert import Elasticsearch
from elastalert.util import lookup_es_key
from elastalert.util import ts_now


def print_terms(terms, parent):
    for term in terms:
        if type(terms[term]) != dict:
            print('\t', parent + term)
        else:
            print_terms(terms[term], parent + term + '.')


def check_files():
    print("Note: This tool is for testing filters and config syntax. It will not process data or alert.\n")
    parser = argparse.ArgumentParser(description='Validate a rule configuration')
    parser.add_argument('files', metavar='file', type=str, nargs='+', help='rule configuration filename')
    parser.add_argument('--schema-only', action='store_true', help='Show only schema errors; do not run query')
    parser.add_argument('--days', type=int, default=[1, 7], nargs='+', help='Query the previous N days with this rule')
    args = parser.parse_args()

    for filename in args.files:
        with open(filename) as fh:
            conf = yaml.load(fh)
        load_options(conf)
        print("Successfully loaded %s\n" % (conf['name']))

        if args.schema_only:
            continue

        es_client = Elasticsearch(host=conf['es_host'], port=conf['es_port'])
        for days in args.days:
            start_time = ts_now() - datetime.timedelta(days=days)
            end_time = ts_now()
            ts = conf.get('timestamp_field', '@timestamp')
            query = ElastAlerter.get_query(conf['filter'], starttime=start_time, endtime=end_time, timestamp_field=ts)
            index = ElastAlerter.get_index(conf, start_time, end_time)
            try:
                res = es_client.search(index, size=1000, body=query)
            except Exception as e:
                print("Error running your filter:")
                print(repr(e)[:2048])
                exit(1)

            num_hits = len(res['hits']['hits'])
            print("Got %s hits from the last %s day%s" % (num_hits if num_hits != 1000 else '1000+', days,
                                                          's' if days > 1 else ''))

        if num_hits:
            print("\nAvailable terms in first hit:")
            terms = res['hits']['hits'][0]['_source']
            print_terms(terms, '')

            pk = conf.get('primary_key')
            ck = conf.get('compare_key')
            if pk and not lookup_es_key(terms, pk):
                print("Warning: primary key %s is either missing or null!")
            if ck and not lookup_es_key(terms, ck):
                print("Warning: compare key %s is either missing or null!")

            include = conf.get('include')
            if include:
                for term in include:
                    if not lookup_es_key(terms, term) and '*' not in term:
                        print("Included term %s may be missing or null" % (term))

            for term in conf.get('top_count_keys', []):
                if term not in terms and (term.endswith('.raw') and term[:-4] not in terms or 'logstash' not in index):
                    print("top_count_key %s may be missing" % (term))
        print('')

if __name__ == '__main__':
    check_files()
