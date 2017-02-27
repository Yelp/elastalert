# -*- coding: utf-8 -*-
from elastalert.util import lookup_es_key, set_es_key, add_raw_postfix, replace_dots_in_field_names


def test_setting_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts': 'fail',
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    # Set the value
    assert set_es_key(record, 'Fields.ts', expected)

    # Get the value again
    assert lookup_es_key(record, 'Fields.ts') == expected


def test_looking_up_missing_keys(ea):
    record = {
        'Message': '12345',
        'Fields': {
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts') is None


def test_looking_up_nested_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts': expected,
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts') == expected


def test_looking_up_nested_composite_keys(ea):
    expected = 12467267
    record = {
        'Message': '12345',
        'Fields': {
            'ts.value': expected,
            'severity': 'large',
            'user': 'jimmay'
        }
    }

    assert lookup_es_key(record, 'Fields.ts.value') == expected


def test_add_raw_postfix(ea):
    expected = 'foo.raw'
    assert add_raw_postfix('foo', False) == expected
    assert add_raw_postfix('foo.raw', False) == expected
    expected = 'foo.keyword'
    assert add_raw_postfix('foo', True) == expected
    assert add_raw_postfix('foo.keyword', True) == expected


def test_replace_dots_in_field_names(ea):
    actual = {
        'a': {
            'b.c': 'd',
            'e': {
                'f': {
                    'g.h': 0
                }
            }
        },
        'i.j.k': 1,
        'l': {
            'm': 2
        }
    }
    expected = {
        'a': {
            'b_c': 'd',
            'e': {
                'f': {
                    'g_h': 0
                }
            }
        },
        'i_j_k': 1,
        'l': {
            'm': 2
        }
    }
    assert replace_dots_in_field_names(actual) == expected
    assert replace_dots_in_field_names({'a': 0, 1: 2}) == {'a': 0, 1: 2}
