#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import getpass
import os
import time

import argparse
import elasticsearch.helpers
import yaml
from auth import Auth
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch
from elasticsearch.client import IndicesClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help='Elasticsearch host')
    parser.add_argument('--port', type=int, help='Elasticsearch port')
    parser.add_argument('--url-prefix', help='Elasticsearch URL prefix')
    parser.add_argument('--no-auth', action='store_const', const=True, help='Suppress prompt for basic auth')
    parser.add_argument('--ssl', action='store_true', default=None, help='Use TLS')
    parser.add_argument('--no-ssl', dest='ssl', action='store_false', help='Do not use TLS')
    parser.add_argument('--verify-certs', action='store_true', default=None, help='Verify TLS certificates')
    parser.add_argument('--no-verify-certs', dest='verify_certs', action='store_false', help='Do not verify TLS certificates')
    parser.add_argument('--index', help='Index name to create')
    parser.add_argument('--old-index', help='Old index name to copy')
    parser.add_argument('--send_get_body_as', default='GET', help='Method for querying Elasticsearch - POST, GET or source')
    parser.add_argument('--boto-profile', default=None, help='Boto profile to use for signing requests')
    parser.add_argument('--aws-region', default=None, help='AWS Region to use for signing requests')
    args = parser.parse_args()

    if os.path.isfile('../config.yaml'):
        filename = '../config.yaml'
    elif os.path.isfile('config.yaml'):
        filename = 'config.yaml'
    else:
        filename = ''

    if filename:
        with open(filename) as config_file:
            data = yaml.load(config_file)
        host = args.host if args.host else data.get('es_host')
        port = args.port if args.port else data.get('es_port')
        username = data.get('es_username')
        password = data.get('es_password')
        url_prefix = args.url_prefix if args.url_prefix is not None else data.get('es_url_prefix', '')
        use_ssl = args.ssl if args.ssl is not None else data.get('use_ssl')
        verify_certs = args.verify_certs if args.verify_certs is not None else data.get('verify_certs') is not False
        aws_region = data.get('aws_region', None)
        send_get_body_as = data.get('send_get_body_as', 'GET')
    else:
        username = None
        password = None
        aws_region = args.aws_region
        host = args.host if args.host else raw_input('Enter Elasticsearch host: ')
        port = args.port if args.port else int(raw_input('Enter Elasticsearch port: '))
        use_ssl = (args.ssl if args.ssl is not None
                   else raw_input('Use SSL? t/f: ').lower() in ('t', 'true'))
        if use_ssl:
            verify_certs = (args.verify_certs if args.verify_certs is not None
                            else raw_input('Verify TLS certificates? t/f: ').lower() not in ('f', 'false'))
        else:
            verify_certs = True
        if args.no_auth is None:
            username = raw_input('Enter optional basic-auth username (or leave blank): ')
            password = getpass.getpass('Enter optional basic-auth password (or leave blank): ')
        url_prefix = (args.url_prefix if args.url_prefix is not None
                      else raw_input('Enter optional Elasticsearch URL prefix (prepends a string to the URL of every request): '))
        send_get_body_as = args.send_get_body_as

    auth = Auth()
    http_auth = auth(host=host,
                     username=username,
                     password=password,
                     aws_region=aws_region,
                     boto_profile=args.boto_profile)

    es = Elasticsearch(
        host=host,
        port=port,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        connection_class=RequestsHttpConnection,
        http_auth=http_auth,
        url_prefix=url_prefix,
        send_get_body_as=send_get_body_as)

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

    es_index = IndicesClient(es)
    if es_index.exists(index):
        print('Index ' + index + ' already exists. Skipping index creation.')
        return None

    es.indices.create(index)
    # To avoid a race condition. TODO: replace this with a real check
    time.sleep(2)
    es.indices.put_mapping(index=index, doc_type='elastalert', body=es_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_status', body=ess_mapping)
    es.indices.put_mapping(index=index, doc_type='silence', body=silence_mapping)
    es.indices.put_mapping(index=index, doc_type='elastalert_error', body=error_mapping)
    es.indices.put_mapping(index=index, doc_type='past_elastalert', body=past_mapping)
    print('New index %s created' % index)

    if old_index:
        print("Copying all data from old index '{0}' to new index '{1}'".format(old_index, index))
        # Use the defaults for chunk_size, scroll, scan_kwargs, and bulk_kwargs
        elasticsearch.helpers.reindex(es, old_index, index)

    print('Done!')

if __name__ == '__main__':
    main()
