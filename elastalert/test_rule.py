#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import datetime

import argparse

from elastalert.config import load_configuration
from elastalert.elastalert import ElastAlerter
from elastalert.elastalert import Elasticsearch
from elastalert.util import dt_to_ts
from elastalert.util import lookup_es_key
from elastalert.util import ts_now


def print_terms(terms, parent):
    for term in terms:
        if type(terms[term]) != dict:
            print('\t', parent + term)
        else:
            print_terms(terms[term], parent + term + '.')


def check_files():
    parser = argparse.ArgumentParser(description='Validate a rule configuration')
    parser.add_argument('files', metavar='file', type=str, nargs='+', help='rule configuration filename')
    parser.add_argument('--days', type=int, default=1, help='Query the previous N days with this rule')
    args = parser.parse_args()

    for filename in args.files:
        conf = load_configuration(filename)
        print("Loaded %s" % (conf['name']))

        es_client = Elasticsearch(host=conf['es_host'], port=conf['es_port'])
        start_time = datetime.datetime.utcnow() - datetime.timedelta(days=args.days)
        start_ts = dt_to_ts(start_time)
        end_ts = ts_now()
        ts = conf.get('timestamp_field', '@timestamp')
        query = ElastAlerter.get_query(conf['filter'], starttime=start_ts, endtime=end_ts, timestamp_field=ts)
        try:
            res = es_client.search(index=conf['index'], size=100, body=query)
        except Exception as e:
            print("Error running your filter:")
            print(repr(e)[:2048])
            exit(1)

        num_hits = len(res['hits']['hits'])
        print("Got %s hits from the last %s days" % (num_hits if num_hits != 100 else '100+', args.days))

        if num_hits:
            print("Available terms in first hit:")
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
        print('')

if __name__ == '__main__':
    check_files()
