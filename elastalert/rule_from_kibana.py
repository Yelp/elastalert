#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import json

import yaml
from elasticsearch.client import Elasticsearch

from elastalert.kibana import filters_from_dashboard


def main():
    es_host = raw_input("Elasticsearch host: ")
    es_port = raw_input("Elasticsearch port: ")
    db_name = raw_input("Dashboard name: ")
    send_get_body_as = raw_input("Method for querying Elasticsearch[GET]: ") or 'GET'
    es = Elasticsearch(host=es_host, port=es_port, send_get_body_as=send_get_body_as)

    es_version = es.info()["version"]["number"]
    print("Elastic Version:" + es_version)

    query = {'query': {'term': {'_id': db_name}}}

    if is_atleastsixsix(es_version):
        # TODO check support for kibana 7
        # TODO use doc_type='_doc' instead
        # TODO use _source_includes=[...] instead when elasticsearch client supports this
        res = es.search(index='kibana-int', doc_type='dashboard', body=query, params={'_source_includes': 'dashboard'})
    else:
        res = es.search(index='kibana-int', doc_type='dashboard', body=query, _source_include=['dashboard'])

    if not res['hits']['hits']:
        print("No dashboard %s found" % (db_name))
        exit()

    db = json.loads(res['hits']['hits'][0]['_source']['dashboard'])
    config_filters = filters_from_dashboard(db)

    print("\nPartial Config file")
    print("-----------\n")
    print("name: %s" % (db_name))
    print("es_host: %s" % (es_host))
    print("es_port: %s" % (es_port))
    print("filter:")
    print(yaml.safe_dump(config_filters))


def is_atleastsixsix(es_version):
    return float('.'.join(es_version.split('.')[:2])) >= 6.6


if __name__ == '__main__':
    main()
