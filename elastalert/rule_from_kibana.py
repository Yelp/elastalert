#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json

import yaml

from elastalert.kibana import filters_from_dashboard
from elastalert.util import elasticsearch_client


def main():
    es_host = input("Elasticsearch host: ")
    es_port = input("Elasticsearch port: ")
    db_name = input("Dashboard name: ")
    send_get_body_as = input("Method for querying Elasticsearch[GET]: ") or 'GET'

    es = elasticsearch_client({'es_host': es_host, 'es_port': es_port, 'send_get_body_as': send_get_body_as})

    print("Elastic Version:" + es.es_version)

    query = {'query': {'term': {'_id': db_name}}}

    if es.is_atleastsixsix():
        # TODO check support for kibana 7
        # TODO use doc_type='_doc' instead
        res = es.deprecated_search(index='kibana-int', doc_type='dashboard', body=query, _source_includes=['dashboard'])
    else:
        res = es.deprecated_search(index='kibana-int', doc_type='dashboard', body=query, _source_include=['dashboard'])

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


if __name__ == '__main__':
    main()
