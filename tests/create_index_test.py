# -*- coding: utf-8 -*-
import json

import pytest
from elasticsearch import Elasticsearch, RequestsHttpConnection

import elastalert.create_index

es_mappings = [
    'elastalert',
    'elastalert_error',
    'elastalert_status',
    'past_elastalert',
    'silence'
]


@pytest.mark.parametrize('es_mapping', es_mappings)
def test_read_default_index_mapping(es_mapping):
    mapping = elastalert.create_index.read_es_index_mapping(es_mapping)
    assert es_mapping not in mapping
    print(json.dumps(mapping, indent=2))


@pytest.mark.parametrize('es_mapping', es_mappings)
def test_read_es_5_index_mapping(es_mapping):
    mapping = elastalert.create_index.read_es_index_mapping(es_mapping, 5)
    assert es_mapping in mapping
    print(json.dumps(mapping, indent=2))


@pytest.mark.parametrize('es_mapping', es_mappings)
def test_read_es_6_index_mapping(es_mapping):
    mapping = elastalert.create_index.read_es_index_mapping(es_mapping, 6)
    assert es_mapping not in mapping
    print(json.dumps(mapping, indent=2))


def test_read_default_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings()
    assert len(mappings) == len(es_mappings)
    print(json.dumps(mappings, indent=2))


def test_read_es_5_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings(5)
    assert len(mappings) == len(es_mappings)
    print(json.dumps(mappings, indent=2))


def test_read_es_6_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings(6)
    assert len(mappings) == len(es_mappings)
    print(json.dumps(mappings, indent=2))


@pytest.mark.elasticsearch
def test_create_indices():
    es = Elasticsearch(host='127.0.0.1', port=9200, connection_class=RequestsHttpConnection, timeout=10)
    print(json.dumps(es.info()['version']['number'], indent=2))
    index = 'create_index'
    elastalert.create_index.main(es_client=es, ea_index=index)
    indices_mappings = es.indices.get_mapping(index + '*')
    print(json.dumps(indices_mappings, indent=2))
    if es_major_version(es) > 5:
        assert index in indices_mappings
        assert index + '_error' in indices_mappings
        assert index + '_status' in indices_mappings
        assert index + '_silence' in indices_mappings
        assert index + '_past' in indices_mappings
    else:
        assert 'elastalert' in indices_mappings[index]['mappings']
        assert 'elastalert_error' in indices_mappings[index]['mappings']
        assert 'elastalert_status' in indices_mappings[index]['mappings']
        assert 'silence' in indices_mappings[index]['mappings']
        assert 'past_elastalert' in indices_mappings[index]['mappings']


def es_major_version(es):
    return int(es.info()['version']['number'].split(".")[0])
