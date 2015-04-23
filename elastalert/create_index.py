#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import json
import os

import yaml
from elasticsearch.client import Elasticsearch


def main():
    if os.path.isfile('../config.yaml'):
        filename = '../config.yaml'
    elif os.path.isfile('config.yaml'):
        filename = 'config.yaml'
    else:
        filename = ''

    username = None
    password = None
    use_ssl = None
    http_auth = None

    if filename:
        with open(filename) as config_file:
            data = yaml.load(config_file)
        host = data.get('es_host')
        port = data.get('es_port')
        username = data.get('es_username')
        password = data.get('es_password')
        use_ssl = data.get('use_ssl')
    else:
        host = raw_input("Enter elasticsearch host: ")
        port = int(raw_input("Enter elasticsearch port: "))
        while use_ssl is None:
            resp = raw_input("Use SSL? t/f: ").lower()
            use_ssl = True if resp in ('t', 'true') else (False if resp in ('f', 'false') else None)
        username = raw_input("Enter optional basic-auth username: ")
        password = raw_input("Enter optional basic-auth password: ")

    if username and password:
        http_auth = username + ':' + password

    es = Elasticsearch(host=host, port=port, use_ssl=use_ssl, http_auth=http_auth)

    silence_mapping = {'silence': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                  'until': {'type': 'date', 'format': 'dateOptionalTime'}}}}
    ess_mapping = {'elastalert_status': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                        '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}
    es_mapping = {'elastalert': {'properties': {'rule_name': {'index': 'not_analyzed', 'type': 'string'},
                                                'match_body': {'enabled': False, 'type': 'object'}}}}
    error_mapping = {'elastalert_error': {'properties': {'data': {'type': 'object', 'enabled': False}}}}

    index = raw_input('New index name? (Default elastalert_status) ')
    index = index if index else 'elastalert_status'
    old_index = raw_input('Name of existing index to copy? (Default None) ')

    res = None
    if old_index:
        print("Downloading existing data...")
        res = es.search(index=old_index, body={}, size=500000)
        print("Got %s documents" % (len(res['hits']['hits'])))

    es.indices.create(index)
    es.indices.put_mapping(index=index, doc_type='elastalert', body=es_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_status', body=ess_mapping)
    es.indices.put_mapping(index=index, doc_type='silence', body=silence_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_error', body=error_mapping)
    print("New index %s created" % (index))

    if res:
        bulk = ''.join(['%s\n%s\n' % (json.dumps({'create': {'_type': doc['_type'], '_index': index}}),
                                      json.dumps(doc['_source'])) for doc in res['hits']['hits']])
        print("Uploading data...")
        es.bulk(body=bulk, index=index)

    print("Done!")

if __name__ == '__main__':
    main()
