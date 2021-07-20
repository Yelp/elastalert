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


@pytest.mark.parametrize('es_version, expected', [
    ('5.6.0', False),
    ('6.0.0', True),
    ('6.1.0', True),
    ('6.2.0', True),
    ('6.3.0', True),
    ('6.4.0', True),
    ('6.5.0', True),
    ('6.6.0', True),
    ('6.7.0', True),
    ('6.8.0', True),
    ('7.0.0', True),
    ('7.1.0', True),
    ('7.2.0', True),
    ('7.3.0', True),
    ('7.4.0', True),
    ('7.5.0', True),
    ('7.6.0', True),
    ('7.7.0', True),
    ('7.8.0', True),
    ('7.9.0', True),
    ('7.10.0', True),
    ('7.11.0', True),
    ('7.12.0', True),
    ('7.13.0', True)
])
def test_is_atleastsix(es_version, expected):
    result = elastalert.create_index.is_atleastsix(es_version)
    assert result == expected


@pytest.mark.parametrize('es_version, expected', [
    ('5.6.0', False),
    ('6.0.0', False),
    ('6.1.0', False),
    ('6.2.0', True),
    ('6.3.0', True),
    ('6.4.0', True),
    ('6.5.0', True),
    ('6.6.0', True),
    ('6.7.0', True),
    ('6.8.0', True),
    ('7.0.0', True),
    ('7.1.0', True),
    ('7.2.0', True),
    ('7.3.0', True),
    ('7.4.0', True),
    ('7.5.0', True),
    ('7.6.0', True),
    ('7.7.0', True),
    ('7.8.0', True),
    ('7.9.0', True),
    ('7.10.0', True),
    ('7.11.0', True),
    ('7.12.0', True),
    ('7.13.0', True)
])
def test_is_atleastsixtwo(es_version, expected):
    result = elastalert.create_index.is_atleastsixtwo(es_version)
    assert result == expected


@pytest.mark.parametrize('es_version, expected', [
    ('5.6.0', False),
    ('6.0.0', False),
    ('6.1.0', False),
    ('6.2.0', False),
    ('6.3.0', False),
    ('6.4.0', False),
    ('6.5.0', False),
    ('6.6.0', False),
    ('6.7.0', False),
    ('6.8.0', False),
    ('7.0.0', True),
    ('7.1.0', True),
    ('7.2.0', True),
    ('7.3.0', True),
    ('7.4.0', True),
    ('7.5.0', True),
    ('7.6.0', True),
    ('7.7.0', True),
    ('7.8.0', True),
    ('7.9.0', True),
    ('7.10.0', True),
    ('7.11.0', True),
    ('7.12.0', True),
    ('7.13.0', True)
])
def test_is_atleastseven(es_version, expected):
    result = elastalert.create_index.is_atleastseven(es_version)
    assert result == expected
