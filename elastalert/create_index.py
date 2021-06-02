#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import getpass
import json
import os
import time

import elasticsearch.helpers
import yaml
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch
from elasticsearch.client import IndicesClient
from elasticsearch.exceptions import NotFoundError
from envparse import Env

from elastalert.auth import Auth

env = Env(ES_USE_SSL=bool)


def create_index_mappings(es_client, ea_index, recreate=False, old_ea_index=None):
    esversion = es_client.info()["version"]["number"]
    print("Elastic Version: " + esversion)

    es_index_mappings = read_es_index_mappings() if is_atleastsix(esversion) else read_es_index_mappings(5)

    es_index = IndicesClient(es_client)
    if not recreate:
        if es_index.exists(ea_index):
            print('Index ' + ea_index + ' already exists. Skipping index creation.')
            return None

    # (Re-)Create indices.
    if is_atleastsix(esversion):
        index_names = (
            ea_index,
            ea_index + '_status',
            ea_index + '_silence',
            ea_index + '_error',
            ea_index + '_past',
        )
    else:
        index_names = (
            ea_index,
        )
    for index_name in index_names:
        if es_index.exists(index_name):
            print('Deleting index ' + index_name + '.')
            try:
                es_index.delete(index_name)
            except NotFoundError:
                # Why does this ever occur?? It shouldn't. But it does.
                pass
        es_index.create(index_name)

    # To avoid a race condition. TODO: replace this with a real check
    time.sleep(2)

    if is_atleastseven(esversion):
        # TODO remove doc_type completely when elasicsearch client allows doc_type=None
        # doc_type is a deprecated feature and will be completely removed in Elasicsearch 8
        es_client.indices.put_mapping(index=ea_index, doc_type='_doc',
                                      body=es_index_mappings['elastalert'], include_type_name=True)
        es_client.indices.put_mapping(index=ea_index + '_status', doc_type='_doc',
                                      body=es_index_mappings['elastalert_status'], include_type_name=True)
        es_client.indices.put_mapping(index=ea_index + '_silence', doc_type='_doc',
                                      body=es_index_mappings['silence'], include_type_name=True)
        es_client.indices.put_mapping(index=ea_index + '_error', doc_type='_doc',
                                      body=es_index_mappings['elastalert_error'], include_type_name=True)
        es_client.indices.put_mapping(index=ea_index + '_past', doc_type='_doc',
                                      body=es_index_mappings['past_elastalert'], include_type_name=True)
    elif is_atleastsixtwo(esversion):
        es_client.indices.put_mapping(index=ea_index, doc_type='_doc',
                                      body=es_index_mappings['elastalert'])
        es_client.indices.put_mapping(index=ea_index + '_status', doc_type='_doc',
                                      body=es_index_mappings['elastalert_status'])
        es_client.indices.put_mapping(index=ea_index + '_silence', doc_type='_doc',
                                      body=es_index_mappings['silence'])
        es_client.indices.put_mapping(index=ea_index + '_error', doc_type='_doc',
                                      body=es_index_mappings['elastalert_error'])
        es_client.indices.put_mapping(index=ea_index + '_past', doc_type='_doc',
                                      body=es_index_mappings['past_elastalert'])
    elif is_atleastsix(esversion):
        es_client.indices.put_mapping(index=ea_index, doc_type='elastalert',
                                      body=es_index_mappings['elastalert'])
        es_client.indices.put_mapping(index=ea_index + '_status', doc_type='elastalert_status',
                                      body=es_index_mappings['elastalert_status'])
        es_client.indices.put_mapping(index=ea_index + '_silence', doc_type='silence',
                                      body=es_index_mappings['silence'])
        es_client.indices.put_mapping(index=ea_index + '_error', doc_type='elastalert_error',
                                      body=es_index_mappings['elastalert_error'])
        es_client.indices.put_mapping(index=ea_index + '_past', doc_type='past_elastalert',
                                      body=es_index_mappings['past_elastalert'])
    else:
        es_client.indices.put_mapping(index=ea_index, doc_type='elastalert',
                                      body=es_index_mappings['elastalert'])
        es_client.indices.put_mapping(index=ea_index, doc_type='elastalert_status',
                                      body=es_index_mappings['elastalert_status'])
        es_client.indices.put_mapping(index=ea_index, doc_type='silence',
                                      body=es_index_mappings['silence'])
        es_client.indices.put_mapping(index=ea_index, doc_type='elastalert_error',
                                      body=es_index_mappings['elastalert_error'])
        es_client.indices.put_mapping(index=ea_index, doc_type='past_elastalert',
                                      body=es_index_mappings['past_elastalert'])

    print('New index %s created' % ea_index)
    if old_ea_index:
        print("Copying all data from old index '{0}' to new index '{1}'".format(old_ea_index, ea_index))
        # Use the defaults for chunk_size, scroll, scan_kwargs, and bulk_kwargs
        elasticsearch.helpers.reindex(es_client, old_ea_index, ea_index)

    print('Done!')


def read_es_index_mappings(es_version=6):
    print('Reading Elastic {0} index mappings:'.format(es_version))
    return {
        'silence': read_es_index_mapping('silence', es_version),
        'elastalert_status': read_es_index_mapping('elastalert_status', es_version),
        'elastalert': read_es_index_mapping('elastalert', es_version),
        'past_elastalert': read_es_index_mapping('past_elastalert', es_version),
        'elastalert_error': read_es_index_mapping('elastalert_error', es_version)
    }


def read_es_index_mapping(mapping, es_version=6):
    base_path = os.path.abspath(os.path.dirname(__file__))
    mapping_path = 'es_mappings/{0}/{1}.json'.format(es_version, mapping)
    path = os.path.join(base_path, mapping_path)
    with open(path, 'r') as f:
        print("Reading index mapping '{0}'".format(mapping_path))
        return json.load(f)


def is_atleastsix(es_version):
    return int(es_version.split(".")[0]) >= 6


def is_atleastsixtwo(es_version):
    major, minor = list(map(int, es_version.split(".")[:2]))
    return major > 6 or (major == 6 and minor >= 2)


def is_atleastseven(es_version):
    return int(es_version.split(".")[0]) >= 7


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=os.environ.get('ES_HOST', None), help='Elasticsearch host')
    parser.add_argument('--port', default=os.environ.get('ES_PORT', None), type=int, help='Elasticsearch port')
    parser.add_argument('--username', default=os.environ.get('ES_USERNAME', None), help='Elasticsearch username')
    parser.add_argument('--password', default=os.environ.get('ES_PASSWORD', None), help='Elasticsearch password')
    parser.add_argument('--bearer', default=os.environ.get('ES_BEARER', None), help='Elasticsearch bearer token')
    parser.add_argument('--api-key', default=os.environ.get('ES_API_KEY', None), help='Elasticsearch api-key token')
    parser.add_argument('--url-prefix', help='Elasticsearch URL prefix')
    parser.add_argument('--no-auth', action='store_const', const=True, help='Suppress prompt for basic auth')
    parser.add_argument('--ssl', action='store_true', default=env('ES_USE_SSL', None), help='Use TLS')
    parser.add_argument('--no-ssl', dest='ssl', action='store_false', help='Do not use TLS')
    parser.add_argument('--verify-certs', action='store_true', default=None, help='Verify TLS certificates')
    parser.add_argument('--no-verify-certs', dest='verify_certs', action='store_false',
                        help='Do not verify TLS certificates')
    parser.add_argument('--index', help='Index name to create')
    parser.add_argument('--old-index', help='Old index name to copy')
    parser.add_argument('--send_get_body_as', default='GET',
                        help='Method for querying Elasticsearch - POST, GET or source')
    parser.add_argument(
        '--boto-profile',
        default=None,
        dest='profile',
        help='DEPRECATED: (use --profile) Boto profile to use for signing requests')
    parser.add_argument(
        '--profile',
        default=None,
        help='AWS profile to use for signing requests. Optionally use the AWS_DEFAULT_PROFILE environment variable')
    parser.add_argument(
        '--aws-region',
        default=None,
        help='AWS Region to use for signing requests. Optionally use the AWS_DEFAULT_REGION environment variable')
    parser.add_argument('--timeout', default=60, type=int, help='Elasticsearch request timeout')
    parser.add_argument('--config', default='config.yaml', help='Global config file (default: config.yaml)')
    parser.add_argument('--recreate', type=bool, default=False,
                        help='Force re-creation of the index (this will cause data loss).')
    args = parser.parse_args()

    if os.path.isfile(args.config):
        filename = args.config
    elif os.path.isfile('../config.yaml'):
        filename = '../config.yaml'
    else:
        filename = ''

    if filename:
        with open(filename) as config_file:
            data = yaml.load(config_file, Loader=yaml.FullLoader)
        host = args.host if args.host else data.get('es_host')
        port = args.port if args.port else data.get('es_port')
        username = args.username if args.username else data.get('es_username')
        password = args.password if args.password else data.get('es_password')
        bearer = args.bearer if args.bearer else data.get('es_bearer')
        api_key = args.api_key if args.api_key else data.get('es_api_key')
        url_prefix = args.url_prefix if args.url_prefix is not None else data.get('es_url_prefix', '')
        use_ssl = args.ssl if args.ssl is not None else data.get('use_ssl')
        verify_certs = args.verify_certs if args.verify_certs is not None else data.get('verify_certs') is not False
        aws_region = data.get('aws_region', None)
        send_get_body_as = data.get('send_get_body_as', 'GET')
        ca_certs = data.get('ca_certs')
        client_cert = data.get('client_cert')
        client_key = data.get('client_key')
        index = args.index if args.index is not None else data.get('writeback_index')
        old_index = args.old_index if args.old_index is not None else None
    else:
        username = args.username if args.username else None
        password = args.password if args.password else None
        bearer = args.bearer if args.bearer else None
        api_key = args.api_key if args.api_key else None
        aws_region = args.aws_region
        host = args.host if args.host else input('Enter Elasticsearch host: ')
        port = args.port if args.port else int(input('Enter Elasticsearch port: '))
        use_ssl = (args.ssl if args.ssl is not None
                   else input('Use SSL? t/f: ').lower() in ('t', 'true'))
        if use_ssl:
            verify_certs = (args.verify_certs if args.verify_certs is not None
                            else input('Verify TLS certificates? t/f: ').lower() not in ('f', 'false'))
        else:
            verify_certs = True
        if args.no_auth is None and username is None:
            username = input('Enter optional basic-auth username (or leave blank): ')
            password = getpass.getpass('Enter optional basic-auth password (or leave blank): ')
        url_prefix = (args.url_prefix if args.url_prefix is not None
                      else input('Enter optional Elasticsearch URL prefix (prepends a string to the URL of every request): '))
        send_get_body_as = args.send_get_body_as
        ca_certs = None
        client_cert = None
        client_key = None
        index = args.index if args.index is not None else input('New index name? (Default elastalert_status) ')
        if not index:
            index = 'elastalert_status'
        old_index = (args.old_index if args.old_index is not None
                     else input('Name of existing index to copy? (Default None) '))

    timeout = args.timeout

    auth = Auth()
    http_auth = auth(host=host,
                     username=username,
                     password=password,
                     aws_region=aws_region,
                     profile_name=args.profile)

    headers = {}
    if bearer is not None:
        headers.update({'Authorization': f'Bearer {bearer}'})
    if api_key is not None:
        headers.update({'Authorization': f'ApiKey {api_key}'})

    es = Elasticsearch(
        host=host,
        port=port,
        timeout=timeout,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        connection_class=RequestsHttpConnection,
        http_auth=http_auth,
        headers=headers,
        url_prefix=url_prefix,
        send_get_body_as=send_get_body_as,
        client_cert=client_cert,
        ca_certs=ca_certs,
        client_key=client_key)

    create_index_mappings(es_client=es, ea_index=index, recreate=args.recreate, old_ea_index=old_index)


if __name__ == '__main__':
    main()
