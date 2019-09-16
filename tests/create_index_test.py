# -*- coding: utf-8 -*-
import json

import pytest

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
    print((json.dumps(mapping, indent=2)))


@pytest.mark.parametrize('es_mapping', es_mappings)
def test_read_es_5_index_mapping(es_mapping):
    mapping = elastalert.create_index.read_es_index_mapping(es_mapping, 5)
    assert es_mapping in mapping
    print((json.dumps(mapping, indent=2)))


@pytest.mark.parametrize('es_mapping', es_mappings)
def test_read_es_6_index_mapping(es_mapping):
    mapping = elastalert.create_index.read_es_index_mapping(es_mapping, 6)
    assert es_mapping not in mapping
    print((json.dumps(mapping, indent=2)))


def test_read_default_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings()
    assert len(mappings) == len(es_mappings)
    print((json.dumps(mappings, indent=2)))


def test_read_es_5_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings(5)
    assert len(mappings) == len(es_mappings)
    print((json.dumps(mappings, indent=2)))


def test_read_es_6_index_mappings():
    mappings = elastalert.create_index.read_es_index_mappings(6)
    assert len(mappings) == len(es_mappings)
    print((json.dumps(mappings, indent=2)))
