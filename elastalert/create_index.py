#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import getpass
import json
import os
import time

import argparse
import yaml
from elasticsearch.client import Elasticsearch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help='Elasticsearch host')
    parser.add_argument('--port', type=int, help='Elasticsearch port')
    parser.add_argument('--url-prefix', help='Elasticsearch URL prefix')
    parser.add_argument('--no-auth', action='store_const', const=True, help='Suppress prompt for basic auth')
    parser.add_argument('--ssl', action='store_true', default=None, help='Use SSL')
    parser.add_argument('--no-ssl', dest='ssl', action='store_false', help='Do not use SSL')
    parser.add_argument('--index', help='Index name to create')
    parser.add_argument('--old-index', help='Old index name to copy')
    args = parser.parse_args()

    if os.path.isfile('../config.yaml'):
        filename = '../config.yaml'
    elif os.path.isfile('config.yaml'):
        filename = 'config.yaml'
    else:
        filename = ''

    username = None
    password = None
    use_ssl = None
    url_prefix = None
    http_auth = None

    if filename:
        with open(filename) as config_file:
            data = yaml.load(config_file)
        host = data.get('es_host')
        port = data.get('es_port')
        username = data.get('es_username')
        password = data.get('es_password')
        url_prefix = data.get('es_url_prefix', '')
        use_ssl = data.get('use_ssl')
    else:
        host = args.host if args.host else raw_input('Enter elasticsearch host: ')
        port = args.port if args.port else int(raw_input('Enter elasticsearch port: '))
        use_ssl = (args.ssl if args.ssl is not None
                   else raw_input('Use SSL? t/f: ').lower() in ('t', 'true'))
        if args.no_auth is None:
            username = raw_input('Enter optional basic-auth username: ')
            password = getpass.getpass('Enter optional basic-auth password: ')
        url_prefix = (args.url_prefix if args.url_prefix is not None
                      else raw_input('Enter optional Elasticsearch URL prefix: '))

    if username and password:
        http_auth = username + ':' + password

    es = Elasticsearch(host=host, port=port, use_ssl=use_ssl, http_auth=http_auth, url_prefix=url_prefix)

    silence_mapping = {'silence': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                  'until': {'type': 'date', 'format': 'dateOptionalTime'},
                                                  '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}
    ess_mapping = {'elastalert_status': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                        '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}
    es_mapping = {'elastalert': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'},
                                                'alert_time': {'format': 'dateOptionalTime', 'type': 'date'},
                                                'match_body': {'enabled': False, 'type': 'object'},
                                                'aggregate_id': {'index': 'not_analyzed', 'type': 'string'}}}}
    past_mapping = {'past_elastalert': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                       'match_body': {'enabled': False, 'type': 'object'},
                                                       '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'},
                                                       'aggregate_id': {'index': 'not_analyzed', 'type': 'string'}}}}
    error_mapping = {'elastalert_error': {'properties': {'data': {'type': 'object', 'enabled': False},
                                                         '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}

    index = args.index if args.index is not None else raw_input('New index name? (Default elastalert_status) ')
    if not index:
        index = 'elastalert_status'

    old_index = (args.old_index if args.old_index is not None
                 else raw_input('Name of existing index to copy? (Default None) '))

    res = None
    if old_index:
        print('Downloading existing data...')
        res = es.search(index=old_index, body={}, size=500000)
        print('Got %s documents' % (len(res['hits']['hits'])))

    es.indices.create(index)
    # To avoid a race condition. TODO: replace this with a real check
    time.sleep(2)
    es.indices.put_mapping(index=index, doc_type='elastalert', body=es_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_status', body=ess_mapping)
    es.indices.put_mapping(index=index, doc_type='silence', body=silence_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_error', body=error_mapping)
    es.indices.put_mapping(index=index, doc_type='past_elastalert', body=past_mapping)
    print('New index %s created' % (index))

    if res:
        bulk = ''.join(['%s\n%s\n' % (json.dumps({'create': {'_type': doc['_type'], '_index': index}}),
                                      json.dumps(doc['_source'])) for doc in res['hits']['hits']])
        print('Uploading data...')
        es.bulk(body=bulk, index=index)

    print('Done!')

if __name__ == '__main__':
    main()
